"""Subscriptions endpoint"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Subscription, SubscriptionPlan, User
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/me")
async def get_my_subscription(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Subscription).where(Subscription.user_id == current_user.id))
    sub = result.scalar_one_or_none()
    if not sub:
        return {"plan": "FREE", "status": "ACTIVE", "scansUsed": 0, "scansLimit": 3}

    return {
        "id": sub.id,
        "plan": sub.plan.value,
        "status": sub.status.value,
        "scansUsed": sub.scans_used,
        "scansLimit": sub.scans_limit,
        "currentPeriodStart": sub.current_period_start.isoformat() if sub.current_period_start else None,
        "currentPeriodEnd": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "cancelAtPeriodEnd": sub.cancel_at_period_end,
    }


PLAN_DETAILS = {
    "FREE": {"scans_limit": 3, "price": 0, "name": "Free", "features": ["3 scans/month", "Basic reports", "Email alerts"]},
    "MONTHLY": {"scans_limit": 30, "price": 49, "name": "Monthly Monitoring", "features": ["30 scans/month", "AI reports", "Daily monitoring", "PDF export", "Telegram alerts"]},
    "PREMIUM": {"scans_limit": 999, "price": 149, "name": "Premium Audit", "features": ["Unlimited scans", "AI reports", "24/7 monitoring", "PDF export", "Priority support", "Custom alerts"]},
}


@router.get("/plans")
async def list_plans():
    return [
        {
            "id": plan_id,
            "name": details["name"],
            "price": details["price"],
            "scansLimit": details["scans_limit"],
            "features": details["features"],
        }
        for plan_id, details in PLAN_DETAILS.items()
    ]
