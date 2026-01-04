from datetime import datetime, timezone

from jose import JWTError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio.session import AsyncSession
from sqlalchemy.orm.strategy_options import joinedload
from sqlalchemy.sql.expression import select

import database
import exceptions
import schemas
from exceptions import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface


async def get_user_by_email(db: AsyncSession, email: str) -> database.UserModel | None:
    query = select(database.UserModel).where(database.UserModel.email == email)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_user_group_by_name_enum(db: AsyncSession, name: database.UserGroupEnum) -> database.UserGroupModel:
    query = select(database.UserGroupModel).where(database.UserGroupModel.name == name)
    result = await db.execute(query)
    return result.scalar_one()


async def create_user_model(db: AsyncSession, user_data: schemas.UserRegistrationRequestSchema) -> database.UserModel:
    try:
        group_model = await get_user_group_by_name_enum(db, database.UserGroupEnum.USER)
        user = database.UserModel(
            email=str(user_data.email),
            group=group_model,
        )
        user.password = user_data.password

        db.add(user)
        await db.flush()
        await db.refresh(user)

        token = database.ActivationTokenModel(
            user=user,
        )

        db.add(token)
        await db.commit()

        return user

    except SQLAlchemyError as e:
        await db.rollback()
        raise e


async def get_activation_token_by_token(db: AsyncSession, activation_token: str) -> database.ActivationTokenModel:
    query = select(
        database.ActivationTokenModel
    ).where(database.ActivationTokenModel.token == activation_token)
    query = query.options(
        joinedload(database.ActivationTokenModel.user),
    )
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def activate_user_by_activation_token(db: AsyncSession, data: schemas.UserActivationRequestSchema) -> None:
    email = str(data.email).lower()
    now = datetime.now(timezone.utc)

    token = await get_activation_token_by_token(db, data.token)
    if not token:
        raise exceptions.ActivationException("Invalid or expired activation token.")

    expected_email = str(token.user.email).lower()

    if not expected_email or expected_email != email or token.expires_at.replace(tzinfo=timezone.utc) < now:
        raise exceptions.ActivationException("Invalid or expired activation token.")

    user = await get_user_by_email(db, email)

    if user.is_active:
        raise exceptions.ActivationException("User account is already active.")

    try:
        user.is_active = True
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise
    return


async def get_password_reset_token_by_user(db: AsyncSession,
                                           user: database.UserModel) -> database.PasswordResetTokenModel:
    query = select(database.PasswordResetTokenModel).where(database.PasswordResetTokenModel.user == user)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_password_rest_token_by_user(
        db: AsyncSession,
        user: database.UserModel) -> database.PasswordResetTokenModel:
    query = select(database.PasswordResetTokenModel).where(database.PasswordResetTokenModel.user == user)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def create_password_reset_token(db: AsyncSession, data: schemas.PasswordResetRequestSchema) -> None:
    email = str(data.email).lower()
    user = await get_user_by_email(db, email)
    if not user or not user.is_active:
        raise exceptions.PasswordResetException

    try:
        exists = await get_password_reset_token_by_user(db, user)
        if exists:
            await db.delete(exists)
        token = database.PasswordResetTokenModel(user=user)
        db.add(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise exceptions.PasswordResetException
    return


async def reset_password_completion(db: AsyncSession, data: schemas.PasswordResetCompleteRequestSchema) -> None:
    email = str(data.email).lower()
    user = await get_user_by_email(db, email)

    if not user:
        raise exceptions.PasswordResetException

    token = await get_password_rest_token_by_user(db, user)

    if not token:
        raise exceptions.PasswordResetException
    if (
            token.token != data.token
            or token.user != user
            or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        await db.delete(token)
        await db.commit()
        raise exceptions.PasswordResetException

    try:
        user.password = data.password
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise
    return


async def create_token(db: AsyncSession, user: database.UserModel, jwt_manager: JWTAuthManagerInterface):
    data = {
        "user_id": user.id,
        "email": user.email,
    }
    refresh_token = jwt_manager.create_refresh_token(
        data=data,
    )
    access_token = jwt_manager.create_access_token(
        data=data,
    )
    try:
        token = database.RefreshTokenModel(
            user=user,
            token=refresh_token,
        )
        db.add(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


async def get_user_by_id(db: AsyncSession, user_id: int) -> database.UserModel | None:
    user = await db.get(database.UserModel, user_id)
    return user


async def get_refresh_token_by_token(db: AsyncSession, token: str) -> database.RefreshTokenModel | None:
    query = select(database.RefreshTokenModel).where(database.RefreshTokenModel.token == token)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def authenticate_user(
        db: AsyncSession,
        data: schemas.UserLoginRequestSchema, jwt_manager: JWTAuthManagerInterface) -> dict:
    user = await get_user_by_email(db, str(data.email).lower())
    if not user or not user.verify_password(data.password):
        raise exceptions.LoginException("Invalid email or password.")
    if not user.is_active:
        raise exceptions.NotActivatedException("User account is not activated.")
    return await create_token(db, user, jwt_manager)


async def refresh_token(
        db: AsyncSession,
        data: schemas.TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface) -> dict:
    token = await get_refresh_token_by_token(db, data.refresh_token)

    if not token:
        raise exceptions.RefreshTokenNotFound("Refresh token not found.")

    try:
        decoded = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise TokenExpiredError("Token has expired.")
    except JWTError:
        raise InvalidTokenError("Invalid token.")

    user_id = decoded["user_id"]
    user = await get_user_by_id(db, user_id)

    if not user:
        raise exceptions.UserNotFound("User not found.")

    data = {
        "user_id": user.id,
        "email": user.email,
    }
    access = jwt_manager.create_access_token(
        data=data,
    )
    return {
        "access_token": access,
    }
