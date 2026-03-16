"""
Celery tasks for security scanning
"""
import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select
import cuid2

from app.core.config import settings
from app.core.celery_app import celery_app
from app.models.models import Scan, Target, ScanFinding, ScanStatus, Severity
from app.services.scanner.scanner import SecurityScanner
from app.services.ai.report_generator import AIReportGenerator

logger = logging.getLogger(__name__)


def get_severity(s: str) -> Severity:
    mapping = {
        "INFO": Severity.INFO,
        "LOW": Severity.LOW,
        "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH,
        "CRITICAL": Severity.CRITICAL,
    }
    return mapping.get(s, Severity.INFO)


async def _run_scan_async(scan_id: str):
    """Async implementation of scan runner."""
    engine = create_async_engine(settings.DATABASE_URL)
    AsyncSession_ = async_sessionmaker(engine, expire_on_commit=False)

    async with AsyncSession_() as db:
        try:
            # Get scan
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return

            # Get target
            target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
            target = target_result.scalar_one_or_none()
            if not target:
                logger.error(f"Target for scan {scan_id} not found")
                return

            # Update status
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

            # Run scanner
            scanner = SecurityScanner(
                target_domain=target.domain,
                target_ip=target.ip_address,
            )
            scan_results = await scanner.run_full_scan()

            # Store findings
            for finding_data in scan_results["findings"]:
                finding = ScanFinding(
                    id=cuid2.cuid(),
                    scan_id=scan_id,
                    category=finding_data["category"],
                    title=finding_data["title"],
                    description=finding_data["description"],
                    severity=get_severity(finding_data["severity"]),
                    details=finding_data.get("details"),
                    remediation=finding_data.get("remediation"),
                )
                db.add(finding)

            # Update scan
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.risk_score = scan_results["risk_score"]
            await db.commit()

            # Generate AI report
            await _generate_report(db, scan_id, scan.user_id, scan_results, target)

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            async with AsyncSession_() as error_db:
                error_result = await error_db.execute(select(Scan).where(Scan.id == scan_id))
                error_scan = error_result.scalar_one_or_none()
                if error_scan:
                    error_scan.status = ScanStatus.FAILED
                    error_scan.error = str(e)
                    await error_db.commit()
        finally:
            await engine.dispose()


async def _generate_report(db: AsyncSession, scan_id: str, user_id: str, scan_results: dict, target):
    """Generate AI report after scan completion."""
    try:
        generator = AIReportGenerator()
        findings = scan_results["findings"]

        from app.models.models import ScanFinding
        db_findings_result = await db.execute(
            select(ScanFinding).where(ScanFinding.scan_id == scan_id)
        )
        db_findings = db_findings_result.scalars().all()

        report_data = await generator.generate_report(
            target_info={
                "name": target.name,
                "domain": target.domain,
                "ip": target.ip_address,
            },
            findings=findings,
            risk_score=scan_results["risk_score"],
        )

        from app.models.models import Report
        report = Report(
            id=cuid2.cuid(),
            scan_id=scan_id,
            user_id=user_id,
            title=report_data["title"],
            executive_summary=report_data["executive_summary"],
            technical_findings=report_data["technical_findings"],
            recommendations=report_data["recommendations"],
            risk_score=scan_results["risk_score"],
            critical_count=sum(1 for f in findings if f["severity"] == "CRITICAL"),
            high_count=sum(1 for f in findings if f["severity"] == "HIGH"),
            medium_count=sum(1 for f in findings if f["severity"] == "MEDIUM"),
            low_count=sum(1 for f in findings if f["severity"] == "LOW"),
            info_count=sum(1 for f in findings if f["severity"] == "INFO"),
            generated_by_ai=True,
        )
        db.add(report)
        await db.commit()

        # Generate PDF in background
        await _generate_pdf(report.id)

    except Exception as e:
        logger.error(f"Report generation failed for scan {scan_id}: {e}", exc_info=True)


async def _generate_pdf(report_id: str):
    """Generate PDF report."""
    try:
        from app.services.reports.pdf_generator import PDFGenerator
        generator = PDFGenerator()
        await generator.generate(report_id)
    except Exception as e:
        logger.error(f"PDF generation failed for report {report_id}: {e}")


def run_security_scan(scan_id: str):
    """Synchronous wrapper for async scan task (used with BackgroundTasks)."""
    asyncio.run(_run_scan_async(scan_id))


@celery_app.task(name="app.services.scanner.tasks.celery_run_scan", bind=True, max_retries=2)
def celery_run_scan(self, scan_id: str):
    """Celery task for security scan."""
    try:
        asyncio.run(_run_scan_async(scan_id))
    except Exception as exc:
        logger.error(f"Celery scan task failed: {exc}")
        raise self.retry(exc=exc, countdown=60)
