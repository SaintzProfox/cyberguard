"""Monitoring endpoint"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional
import cuid2
import datetime as dt

from app.core.database import get_db
from app.models.models import Monitor, Target, MonitorLog, User
from app.api.deps import get_current_user

router = APIRouter()


class CreateMonitorRequest(BaseModel):
    target_id: str
    check_interval: int = 86400


@router.post("/")
async def create_monitor(
    data: CreateMonitorRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target_result = await db.execute(
        select(Target).where(Target.id == data.target_id, Target.user_id == current_user.id)
    )
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    monitor = Monitor(
        id=cuid2.cuid(),
        target_id=data.target_id,
        check_interval=data.check_interval,
        next_check_at=dt.datetime.utcnow(),
    )
    db.add(monitor)
    await db.commit()
    return {"id": monitor.id, "message": "Monitor created"}


@router.get("/")
async def list_monitors(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Monitor, Target)
        .join(Target, Monitor.target_id == Target.id)
        .where(Target.user_id == current_user.id)
    )
    rows = result.all()

    return [
        {
            "id": m.id,
            "isActive": m.is_active,
            "checkInterval": m.check_interval,
            "lastCheckedAt": m.last_checked_at.isoformat() if m.last_checked_at else None,
            "nextCheckAt": m.next_check_at.isoformat() if m.next_check_at else None,
            "sslExpiryDays": m.ssl_expiry_days,
            "uptimeStatus": m.uptime_status,
            "target": {"id": t.id, "name": t.name, "domain": t.domain},
        }
        for m, t in rows
    ]


@router.get("/{monitor_id}/logs")
async def get_monitor_logs(
    monitor_id: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify ownership via target
    result = await db.execute(
        select(Monitor, Target)
        .join(Target, Monitor.target_id == Target.id)
        .where(Monitor.id == monitor_id, Target.user_id == current_user.id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Monitor not found")

    logs_result = await db.execute(
        select(MonitorLog)
        .where(MonitorLog.monitor_id == monitor_id)
        .order_by(desc(MonitorLog.checked_at))
        .limit(limit)
    )
    logs = logs_result.scalars().all()

    return [
        {
            "id": l.id,
            "checkType": l.check_type,
            "status": l.status,
            "message": l.message,
            "checkedAt": l.checked_at.isoformat(),
        }
        for l in logs
    ]
