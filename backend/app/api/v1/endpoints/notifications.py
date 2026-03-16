"""Notifications endpoint"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, update

from app.core.database import get_db
from app.models.models import Notification, User
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/")
async def list_notifications(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Notification)
        .where(Notification.user_id == current_user.id)
        .order_by(desc(Notification.created_at))
        .offset(skip).limit(limit)
    )
    notifications = result.scalars().all()

    unread_count_result = await db.execute(
        select(Notification).where(Notification.user_id == current_user.id, Notification.is_read == False)
    )
    unread_count = len(unread_count_result.scalars().all())

    return {
        "items": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "isRead": n.is_read,
                "link": n.link,
                "createdAt": n.created_at.isoformat(),
            }
            for n in notifications
        ],
        "unreadCount": unread_count,
    }


@router.post("/read-all")
async def mark_all_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await db.execute(
        update(Notification).where(Notification.user_id == current_user.id).values(is_read=True)
    )
    await db.commit()
    return {"message": "All notifications marked as read"}
