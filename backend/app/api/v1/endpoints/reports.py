"""Reports endpoints"""
import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.models import Report, Scan, User
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/")
async def list_reports(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Report)
        .where(Report.user_id == current_user.id)
        .order_by(desc(Report.created_at))
        .offset(skip).limit(limit)
    )
    reports = result.scalars().all()

    return [
        {
            "id": r.id,
            "scanId": r.scan_id,
            "title": r.title,
            "riskScore": r.risk_score,
            "criticalCount": r.critical_count,
            "highCount": r.high_count,
            "mediumCount": r.medium_count,
            "lowCount": r.low_count,
            "infoCount": r.info_count,
            "hasPdf": r.pdf_path is not None and os.path.exists(r.pdf_path),
            "generatedByAI": r.generated_by_ai,
            "createdAt": r.created_at.isoformat(),
        }
        for r in reports
    ]


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": report.id,
        "scanId": report.scan_id,
        "title": report.title,
        "executiveSummary": report.executive_summary,
        "technicalFindings": report.technical_findings,
        "recommendations": report.recommendations,
        "riskScore": report.risk_score,
        "criticalCount": report.critical_count,
        "highCount": report.high_count,
        "mediumCount": report.medium_count,
        "lowCount": report.low_count,
        "infoCount": report.info_count,
        "hasPdf": report.pdf_path is not None and os.path.exists(report.pdf_path),
        "generatedByAI": report.generated_by_ai,
        "createdAt": report.created_at.isoformat(),
    }


@router.get("/{report_id}/download")
async def download_report_pdf(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.user_id == current_user.id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if not report.pdf_path or not os.path.exists(report.pdf_path):
        # Generate PDF on demand
        try:
            from app.services.reports.pdf_generator import PDFGenerator
            generator = PDFGenerator()
            import asyncio
            pdf_path = await generator.generate(report_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
    else:
        pdf_path = report.pdf_path

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"cyberguard-report-{report_id[:8]}.pdf",
    )
