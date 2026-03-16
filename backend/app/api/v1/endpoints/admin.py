"""Admin endpoints"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, update
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import User, Scan, Report, Subscription, Target, ScanStatus, UserRole
from app.api.deps import get_current_admin
from app.services.scanner.tasks import run_security_scan

router = APIRouter()


@router.get("/stats")
async def get_admin_stats(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    total_users = await db.scalar(func.count(User.id))
    total_scans = await db.scalar(func.count(Scan.id))
    active_scans = await db.scalar(
        func.count(Scan.id).filter(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]))
    )
    total_reports = await db.scalar(func.count(Report.id))

    premium_subs = await db.scalar(
        func.count(Subscription.id).filter(Subscription.plan != "FREE")
    )

    return {
        "totalUsers": total_users or 0,
        "totalScans": total_scans or 0,
        "activeScans": active_scans or 0,
        "totalReports": total_reports or 0,
        "premiumSubscriptions": premium_subs or 0,
    }


@router.get("/users")
async def list_all_users(
    skip: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    query = select(User).order_by(desc(User.created_at)).offset(skip).limit(limit)
    if search:
        query = query.where(User.email.ilike(f"%{search}%") | User.name.ilike(f"%{search}%"))

    result = await db.execute(query)
    users = result.scalars().all()

    users_data = []
    for user in users:
        sub_result = await db.execute(select(Subscription).where(Subscription.user_id == user.id))
        sub = sub_result.scalar_one_or_none()

        scan_count = await db.scalar(func.count(Scan.id).filter(Scan.user_id == user.id))

        users_data.append({
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "company": user.company,
            "role": user.role.value,
            "isActive": user.is_active,
            "createdAt": user.created_at.isoformat(),
            "lastLoginAt": user.last_login_at.isoformat() if user.last_login_at else None,
            "subscription": {
                "plan": sub.plan.value if sub else "FREE",
                "status": sub.status.value if sub else "INACTIVE",
            } if sub else None,
            "scanCount": scan_count or 0,
        })

    return users_data


@router.get("/scans")
async def list_all_scans(
    skip: int = 0,
    limit: int = 50,
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    query = select(Scan).order_by(desc(Scan.created_at)).offset(skip).limit(limit)
    if status_filter:
        query = query.where(Scan.status == status_filter)

    result = await db.execute(query)
    scans = result.scalars().all()

    scans_data = []
    for scan in scans:
        target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_result.scalar_one_or_none()
        user_result = await db.execute(select(User).where(User.id == scan.user_id))
        user = user_result.scalar_one_or_none()

        scans_data.append({
            "id": scan.id,
            "status": scan.status.value,
            "type": scan.type.value,
            "riskScore": scan.risk_score,
            "createdAt": scan.created_at.isoformat(),
            "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
            "target": {"name": target.name if target else "N/A", "domain": target.domain if target else None},
            "user": {"email": user.email if user else "N/A", "name": user.name if user else None},
        })

    return scans_data


@router.post("/scans/{scan_id}/trigger")
async def trigger_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.status = ScanStatus.QUEUED
    scan.queued_by = admin.id
    await db.commit()

    background_tasks.add_task(run_security_scan, scan_id)
    return {"message": "Scan triggered"}


@router.patch("/users/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    user.is_active = not user.is_active
    await db.commit()
    return {"message": f"User {'activated' if user.is_active else 'deactivated'}", "isActive": user.is_active}
