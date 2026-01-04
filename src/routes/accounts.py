from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

import crud
import exceptions
import schemas
from config import get_jwt_auth_manager
from database import (
    get_db,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=schemas.UserRegistrationResponseSchema, status_code=201)
async def register_user(
        user_data: schemas.UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)):
    exists = await crud.get_user_by_email(db, str(user_data.email))

    if exists:
        raise HTTPException(detail=f"A user with this email {user_data.email} already exists.", status_code=409)
    try:
        user = await crud.create_user_model(db, user_data)
        return user
    except Exception:
        raise HTTPException(detail="An error occurred during user creation.", status_code=500)


@router.post("/activate/", response_model=schemas.MessageResponseSchema)
async def activate_user(data: schemas.UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        await crud.activate_user_by_activation_token(db, data)
    except exceptions.ActivationException as e:
        raise HTTPException(detail=str(e), status_code=400)
    except Exception:
        raise HTTPException(detail="An error occurred during user activation.", status_code=500)
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=schemas.MessageResponseSchema)
async def password_reset(data: schemas.PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        await crud.create_password_reset_token(db, data)
    except exceptions.PasswordResetException:
        pass
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=schemas.MessageResponseSchema)
async def reset_password_complete(
        data: schemas.PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)):
    try:
        await crud.reset_password_completion(db, data)
    except exceptions.PasswordResetException:
        raise HTTPException(detail="Invalid email or token.", status_code=400)
    except Exception:
        raise HTTPException(detail="An error occurred while resetting the password.", status_code=500)
    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=schemas.UserLoginResponseSchema, status_code=201)
async def login(
        data: schemas.UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    try:
        data = await crud.authenticate_user(db, data, jwt_manager)
    except exceptions.LoginException as e:
        raise HTTPException(detail=str(e), status_code=401)
    except exceptions.NotActivatedException as e:
        raise HTTPException(detail=str(e), status_code=403)
    except Exception:
        raise HTTPException(detail="An error occurred while processing the request.", status_code=500)
    return data


@router.post("/refresh/", response_model=schemas.TokenRefreshResponseSchema)
async def refresh(
        data: schemas.TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    try:
        data = await crud.refresh_token(db, data, jwt_manager)
    except (exceptions.TokenExpiredError, exceptions.InvalidTokenError) as e:
        raise HTTPException(detail=str(e), status_code=400)
    except exceptions.RefreshTokenNotFound as e:
        raise HTTPException(detail=str(e), status_code=401)
    except exceptions.UserNotFound as e:
        raise HTTPException(detail=str(e), status_code=404)
    return data
