"""Alerts endpoint"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, update

from app.core.database import get_db
from app.models.models import Alert, User
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/")
async def list_alerts(
    skip: int = 0,
    limit: int = 20,
    unread_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Alert).where(Alert.user_id == current_user.id).order_by(desc(Alert.created_at)).offset(skip).limit(limit)
    if unread_only:
        query = query.where(Alert.is_read == False)

    result = await db.execute(query)
    alerts = result.scalars().all()

    return [
        {
            "id": a.id,
            "type": a.type.value,
            "title": a.title,
            "message": a.message,
            "severity": a.severity.value,
            "isRead": a.is_read,
            "createdAt": a.created_at.isoformat(),
        }
        for a in alerts
    ]


@router.post("/{alert_id}/read")
async def mark_alert_read(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await db.execute(
        update(Alert).where(Alert.id == alert_id, Alert.user_id == current_user.id).values(is_read=True)
    )
    await db.commit()
    return {"message": "Alert marked as read"}


@router.post("/read-all")
async def mark_all_alerts_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await db.execute(
        update(Alert).where(Alert.user_id == current_user.id).values(is_read=True)
    )
    await db.commit()
    return {"message": "All alerts marked as read"}
