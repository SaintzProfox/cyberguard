from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth, users, targets, scans, reports, monitoring, alerts, 
    subscriptions, admin, notifications
)

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(users.router, prefix="/users", tags=["Users"])
router.include_router(targets.router, prefix="/targets", tags=["Targets"])
router.include_router(scans.router, prefix="/scans", tags=["Scans"])
router.include_router(reports.router, prefix="/reports", tags=["Reports"])
router.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring"])
router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
router.include_router(subscriptions.router, prefix="/subscriptions", tags=["Subscriptions"])
router.include_router(admin.router, prefix="/admin", tags=["Admin"])
router.include_router(notifications.router, prefix="/notifications", tags=["Notifications"])
