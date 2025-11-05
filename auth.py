from fastapi import Request, HTTPException, status
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

from settings import Settings

settings = Settings()
STATE_COOKIE_NAME = "oauth_state"
SECRET_KEY = settings.app_jwt_secret
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(request: Request) -> dict[str, str]:
    token = request.cookies.get("app_session_token")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token is None:
        raise credentials_exception

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token: str | None = payload.get("sub")
        username: str | None = payload.get("username")
        if token is None or username is None:
            raise credentials_exception
        return {"token": token, "username": username}
    except JWTError:
        raise credentials_exception
