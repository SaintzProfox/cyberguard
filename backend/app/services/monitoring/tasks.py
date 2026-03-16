"""
Monitoring Celery Tasks
"""
import asyncio
import logging
import ssl
import socket
import datetime as dt
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
import cuid2

from app.core.config import settings
from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)


async def _run_monitor_check(monitor_id: str):
    engine = create_async_engine(settings.DATABASE_URL)
    AsyncSession = async_sessionmaker(engine, expire_on_commit=False)

    async with AsyncSession() as db:
        from app.models.models import Monitor, MonitorLog, Target, Alert, AlertType, Severity

        result = await db.execute(select(Monitor).where(Monitor.id == monitor_id))
        monitor = result.scalar_one_or_none()
        if not monitor or not monitor.is_active:
            return

        target_result = await db.execute(select(Target).where(Target.id == monitor.target_id))
        target = target_result.scalar_one_or_none()
        if not target:
            return

        now = dt.datetime.utcnow()
        checks = []

        # SSL check
        if target.domain:
            ssl_result = await _check_ssl(target.domain)
            checks.append(ssl_result)

            log = MonitorLog(
                id=cuid2.cuid(),
                monitor_id=monitor_id,
                check_type="ssl",
                status=ssl_result["status"],
                message=ssl_result["message"],
                details=ssl_result.get("details"),
                checked_at=now,
            )
            db.add(log)

            if ssl_result.get("days_remaining") is not None:
                monitor.ssl_expiry_days = ssl_result["days_remaining"]

            if ssl_result["status"] == "critical":
                alert = Alert(
                    id=cuid2.cuid(),
                    user_id=target.user_id,
                    type=AlertType.SSL_EXPIRY,
                    title=f"SSL Certificate Alert: {target.domain}",
                    message=ssl_result["message"],
                    severity=Severity.CRITICAL if ssl_result["days_remaining"] and ssl_result["days_remaining"] < 7 else Severity.HIGH,
                )
                db.add(alert)

        # Uptime check
        if target.domain or target.ip_address:
            uptime_result = await _check_uptime(target.domain or target.ip_address)
            checks.append(uptime_result)

            log = MonitorLog(
                id=cuid2.cuid(),
                monitor_id=monitor_id,
                check_type="uptime",
                status=uptime_result["status"],
                message=uptime_result["message"],
                checked_at=now,
            )
            db.add(log)
            monitor.uptime_status = uptime_result["status"] == "ok"

        monitor.last_checked_at = now
        monitor.next_check_at = now + dt.timedelta(seconds=monitor.check_interval)
        await db.commit()

    await engine.dispose()


async def _check_ssl(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        sock = socket.create_connection((domain, 443), timeout=10)
        ssock = context.wrap_socket(sock, server_hostname=domain)
        cert = ssock.getpeercert()
        ssock.close()

        expire_str = cert.get("notAfter", "")
        expire_date = dt.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days = (expire_date - dt.datetime.utcnow()).days

        if days < 0:
            return {"status": "critical", "message": f"SSL certificate expired {abs(days)} days ago", "days_remaining": days}
        elif days < 14:
            return {"status": "critical", "message": f"SSL certificate expires in {days} days", "days_remaining": days}
        elif days < 30:
            return {"status": "warning", "message": f"SSL certificate expires in {days} days", "days_remaining": days}
        else:
            return {"status": "ok", "message": f"SSL certificate valid for {days} days", "days_remaining": days}
    except Exception as e:
        return {"status": "critical", "message": f"SSL check failed: {str(e)}", "days_remaining": None}


async def _check_uptime(host: str) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.get(f"https://{host}")
            if resp.status_code < 500:
                return {"status": "ok", "message": f"Site responding with status {resp.status_code}"}
            else:
                return {"status": "warning", "message": f"Site returning error {resp.status_code}"}
    except Exception as e:
        return {"status": "critical", "message": f"Site unreachable: {str(e)}"}


@celery_app.task(name="app.services.monitoring.tasks.run_all_monitors")
def run_all_monitors():
    async def _run():
        engine = create_async_engine(settings.DATABASE_URL)
        AsyncSession = async_sessionmaker(engine, expire_on_commit=False)
        async with AsyncSession() as db:
            from app.models.models import Monitor
            import datetime as dt
            now = dt.datetime.utcnow()
            result = await db.execute(
                select(Monitor).where(Monitor.is_active == True)
            )
            monitors = result.scalars().all()
            for monitor in monitors:
                if not monitor.next_check_at or monitor.next_check_at <= now:
                    await _run_monitor_check(monitor.id)
        await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.services.monitoring.tasks.check_ssl_expiry_alerts")
def check_ssl_expiry_alerts():
    asyncio.run(_run_ssl_alerts())


@celery_app.task(name="app.services.monitoring.tasks.check_domain_expiry_alerts")
def check_domain_expiry_alerts():
    asyncio.run(_run_domain_alerts())


@celery_app.task(name="app.services.monitoring.tasks.cleanup_old_logs")
def cleanup_old_logs():
    asyncio.run(_cleanup())


async def _run_ssl_alerts():
    engine = create_async_engine(settings.DATABASE_URL)
    AsyncSession = async_sessionmaker(engine, expire_on_commit=False)
    async with AsyncSession() as db:
        from app.models.models import Monitor
        result = await db.execute(
            select(Monitor).where(Monitor.is_active == True, Monitor.ssl_expiry_days != None)
        )
        monitors = result.scalars().all()
        for monitor in monitors:
            if monitor.ssl_expiry_days and monitor.ssl_expiry_days < 30:
                await _run_monitor_check(monitor.id)
    await engine.dispose()


async def _run_domain_alerts():
    pass


async def _cleanup():
    engine = create_async_engine(settings.DATABASE_URL)
    AsyncSession = async_sessionmaker(engine, expire_on_commit=False)
    async with AsyncSession() as db:
        from app.models.models import MonitorLog
        import datetime as dt
        cutoff = dt.datetime.utcnow() - dt.timedelta(days=90)
        from sqlalchemy import delete
        await db.execute(delete(MonitorLog).where(MonitorLog.checked_at < cutoff))
        await db.commit()
    await engine.dispose()
