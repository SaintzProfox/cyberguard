"""
Celery tasks for sending notifications
"""
import asyncio
import logging
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from app.core.config import settings
from app.core.celery_app import celery_app
from app.services.notifications.service import email_service, telegram_service

logger = logging.getLogger(__name__)


@celery_app.task(name="app.services.notifications.tasks.send_alert_notifications")
def send_alert_notifications(alert_id: str):
    asyncio.run(_send_alert(alert_id))


async def _send_alert(alert_id: str):
    engine = create_async_engine(settings.DATABASE_URL)
    AsyncSession = async_sessionmaker(engine, expire_on_commit=False)

    async with AsyncSession() as db:
        from app.models.models import Alert, User

        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return

        user_result = await db.execute(select(User).where(User.id == alert.user_id))
        user = user_result.scalar_one_or_none()
        if not user:
            return

        # Send email
        if not alert.sent_email:
            sent = email_service.send_alert_email(
                user.email, alert.title, alert.message,
                alert.severity.value if hasattr(alert.severity, 'value') else alert.severity
            )
            if sent:
                alert.sent_email = True

        await db.commit()

    await engine.dispose()
