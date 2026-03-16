"""Users endpoint"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.core.security import get_password_hash, verify_password
from app.models.models import User
from app.api.deps import get_current_user

router = APIRouter()


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    company: Optional[str] = None
    phone: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.put("/me")
async def update_profile(
    data: UpdateProfileRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.name is not None:
        current_user.name = data.name
    if data.company is not None:
        current_user.company = data.company
    if data.phone is not None:
        current_user.phone = data.phone
    await db.commit()
    return {"message": "Profile updated"}


@router.post("/me/change-password")
async def change_password(
    data: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(data.current_password, current_user.password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.password = get_password_hash(data.new_password)
    await db.commit()
    return {"message": "Password changed successfully"}
