from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel
import cuid2

from app.core.database import get_db
from app.models.models import Scan, Target, User, Subscription, ScanStatus, ScanType
from app.api.deps import get_current_user
from app.services.scanner.tasks import run_security_scan

router = APIRouter()


class CreateScanRequest(BaseModel):
    target_id: str
    scan_type: ScanType = ScanType.QUICK


class ScanResponse(BaseModel):
    id: str
    target_id: str
    type: str
    status: str
    risk_score: Optional[float]
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str
    finding_counts: Optional[dict] = None
    target_name: Optional[str] = None


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_scan(
    data: CreateScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify target belongs to user
    result = await db.execute(
        select(Target).where(Target.id == data.target_id, Target.user_id == current_user.id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Check subscription limits
    sub_result = await db.execute(
        select(Subscription).where(Subscription.user_id == current_user.id)
    )
    subscription = sub_result.scalar_one_or_none()

    if subscription and subscription.scans_used >= subscription.scans_limit:
        raise HTTPException(
            status_code=403,
            detail=f"Scan limit reached. Upgrade your subscription to run more scans."
        )

    scan_id = cuid2.cuid()
    scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        target_id=data.target_id,
        type=data.scan_type,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)

    if subscription:
        subscription.scans_used += 1

    await db.commit()

    # Queue the scan
    background_tasks.add_task(run_security_scan, scan_id)

    return {
        "id": scan_id,
        "status": ScanStatus.QUEUED,
        "message": "Scan queued successfully",
    }


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    status_filter: Optional[ScanStatus] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Scan).where(Scan.user_id == current_user.id)
    if status_filter:
        query = query.where(Scan.status == status_filter)
    query = query.order_by(desc(Scan.created_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    scans = result.scalars().all()

    responses = []
    for scan in scans:
        target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_result.scalar_one_or_none()

        responses.append(ScanResponse(
            id=scan.id,
            target_id=scan.target_id,
            type=scan.type.value,
            status=scan.status.value,
            risk_score=scan.risk_score,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            created_at=scan.created_at.isoformat(),
            target_name=target.name if target else None,
        ))

    return responses


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get findings
    from app.models.models import ScanFinding
    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()

    return {
        "id": scan.id,
        "target": {
            "id": target.id if target else None,
            "name": target.name if target else None,
            "domain": target.domain if target else None,
            "ipAddress": target.ip_address if target else None,
        },
        "type": scan.type.value,
        "status": scan.status.value,
        "riskScore": scan.risk_score,
        "startedAt": scan.started_at.isoformat() if scan.started_at else None,
        "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
        "createdAt": scan.created_at.isoformat(),
        "error": scan.error,
        "findings": [
            {
                "id": f.id,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "details": f.details,
                "remediation": f.remediation,
                "isFixed": f.is_fixed,
            }
            for f in findings
        ],
        "findingCounts": {
            "critical": sum(1 for f in findings if f.severity.value == "CRITICAL"),
            "high": sum(1 for f in findings if f.severity.value == "HIGH"),
            "medium": sum(1 for f in findings if f.severity.value == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity.value == "LOW"),
            "info": sum(1 for f in findings if f.severity.value == "INFO"),
        },
    }


@router.delete("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in [ScanStatus.PENDING, ScanStatus.QUEUED]:
        raise HTTPException(status_code=400, detail="Cannot cancel scan in current status")

    scan.status = ScanStatus.CANCELLED
    await db.commit()
    return {"message": "Scan cancelled"}
