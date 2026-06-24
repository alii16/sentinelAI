"""
Sentinel AI - Auth API
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token, get_current_user
from app.models.models import User, Role
from app.repositories.user_repository import UserRepository
from app.utils.response import ok, fail
from app.utils.activity import log_activity
from datetime import datetime, timezone

router = APIRouter()


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class RegisterSchema(BaseModel):
    name: str
    email: EmailStr
    password: str


class UpdateProfileSchema(BaseModel):
    name: str | None = None
    avatar: str | None = None


class ChangePasswordSchema(BaseModel):
    current_password: str
    new_password: str


@router.post("/login")
async def login(body: LoginSchema, request: Request, db: AsyncSession = Depends(get_db)):
    repo = UserRepository(db)
    user = await repo.get_by_email(body.email)
    if not user or not verify_password(body.password, user.password):
        await log_activity(db, None, "login_failed", metadata={"email": body.email})
        raise HTTPException(status_code=401, detail="Email atau password salah")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Akun nonaktif")
    token = create_access_token({"sub": str(user.id), "role": user.role.name})
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    await log_activity(db, user.id, "login")
    return ok({
        "token": token,
        "user": {
            "id": user.id, "name": user.name,
            "email": user.email, "role": user.role.name,
            "avatar": user.avatar
        }
    })


@router.post("/register")
async def register(body: RegisterSchema, db: AsyncSession = Depends(get_db)):
    repo = UserRepository(db)
    if await repo.get_by_email(body.email):
        raise HTTPException(status_code=409, detail="Email sudah terdaftar")
    # Get user role
    from sqlalchemy import select
    role = (await db.execute(select(Role).where(Role.name == "user"))).scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=500, detail="Role tidak ditemukan")
    user = User(
        role_id=role.id,
        name=body.name,
        email=body.email,
        password=hash_password(body.password)
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_activity(db, user.id, "register")
    return ok({"message": "Registrasi berhasil"}, 201)


@router.post("/logout")
async def logout(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await log_activity(db, current_user.id, "logout")
    return ok({"message": "Logout berhasil"})


@router.get("/me")
async def me(current_user=Depends(get_current_user)):
    return ok({
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role.name,
        "avatar": current_user.avatar,
        "is_active": current_user.is_active,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "created_at": current_user.created_at.isoformat()
    })


@router.put("/profile")
async def update_profile(body: UpdateProfileSchema, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if body.name:
        current_user.name = body.name
    if body.avatar is not None:
        current_user.avatar = body.avatar
    await db.commit()
    await log_activity(db, current_user.id, "update_profile")
    return ok({"message": "Profil diperbarui"})


@router.put("/password")
async def change_password(body: ChangePasswordSchema, current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not verify_password(body.current_password, current_user.password):
        raise HTTPException(status_code=400, detail="Password lama salah")
    current_user.password = hash_password(body.new_password)
    await db.commit()
    await log_activity(db, current_user.id, "change_password")
    return ok({"message": "Password berhasil diubah"})
