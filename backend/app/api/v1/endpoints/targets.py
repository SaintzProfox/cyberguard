"""Targets endpoints"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
import cuid2

from app.core.database import get_db
from app.models.models import Target, User
from app.api.deps import get_current_user

router = APIRouter()


class CreateTargetRequest(BaseModel):
    name: str
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_target(
    data: CreateTargetRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not data.domain and not data.ip_address:
        raise HTTPException(status_code=400, detail="At least domain or IP address is required")

    target = Target(
        id=cuid2.cuid(),
        user_id=current_user.id,
        name=data.name,
        domain=data.domain,
        ip_address=data.ip_address,
        url=data.url,
        description=data.description,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    return {"id": target.id, "name": target.name, "domain": target.domain, "message": "Target created"}


@router.get("/")
async def list_targets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target)
        .where(Target.user_id == current_user.id, Target.is_active == True)
        .order_by(desc(Target.created_at))
    )
    targets = result.scalars().all()

    return [
        {
            "id": t.id,
            "name": t.name,
            "domain": t.domain,
            "ipAddress": t.ip_address,
            "url": t.url,
            "description": t.description,
            "createdAt": t.created_at.isoformat(),
        }
        for t in targets
    ]


@router.get("/{target_id}")
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.user_id == current_user.id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    return {
        "id": target.id,
        "name": target.name,
        "domain": target.domain,
        "ipAddress": target.ip_address,
        "url": target.url,
        "description": target.description,
        "createdAt": target.created_at.isoformat(),
        "updatedAt": target.updated_at.isoformat(),
    }


@router.delete("/{target_id}")
async def delete_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.user_id == current_user.id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.is_active = False
    await db.commit()
    return {"message": "Target deleted"}
