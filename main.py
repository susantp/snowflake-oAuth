import secrets
from base64 import b64encode
from http.client import HTTPException

from urllib.parse import quote

import httpx
import urllib3.util
from fastapi import FastAPI, Request, HTTPException
from fastapi.params import Depends
from starlette import status
from starlette.responses import RedirectResponse, JSONResponse

from auth import create_access_token, get_current_user
from settings import Settings

settings = Settings()
STATE_COOKIE_NAME = "oauth_state"
app = FastAPI()
SECRET_KEY = settings.app_jwt_secret
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes


@app.get("/")
async def root():
    return {"message": ""}


@app.get('/login')
async def login(payload: dict | None = Depends(get_current_user)):
    if payload is not None:
        return RedirectResponse(url="/profile", status_code=status.HTTP_308_PERMANENT_REDIRECT)

    state = secrets.token_urlsafe(32)
    auth_url = (
        f"https://{settings.snowflake_account_url}/oauth/authorize"
        f"?client_id={quote(settings.snowflake_client_id)}"
        f"&redirect_uri={settings.redirect_uri}"
        f"&response_type=code"
        f"&scope={settings.snowflake_role_scope}"
        f"&state={state}"
    )
    response = RedirectResponse(url=urllib3.util.parse_url(auth_url))
    response.set_cookie(
        key=STATE_COOKIE_NAME,
        value=state,
        max_age=600,  # 10 minutes
        httponly=True,
        samesite="lax"
    )
    return response


@app.get('/snowflake/callback')
async def snowflake_callback(request: Request, code: str, state: str):
    stored_state = request.cookies.get(STATE_COOKIE_NAME)
    if not stored_state or stored_state != state:
        raise HTTPException(status_code=400, detail="Invalid state token (CSRF attempt block)")

    token_url = f"https://{settings.snowflake_account_url}/oauth/token-request"
    auth_header = b64encode(
        f"{settings.snowflake_client_id}:{settings.snowflake_client_secret}".encode("utf-8")
    ).decode("utf-8")
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri,
    }
    async with httpx.AsyncClient(verify=False) as client:
        try:
            token_response = await client.post(token_url, headers=headers, data=data)
            token_response.raise_for_status()  # Raise exception for 4xx/5xx responses
            token_data = token_response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=500, detail=f"Failed to get token from Snowflake: {e.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Token exchange error: {str(e)}")

    snowflake_access_token = token_data.get("access_token")
    verified_username = token_data.get("username")
    app_access_token = create_access_token(
        data={"sub": snowflake_access_token, "username": verified_username})

    response = RedirectResponse(url="/profile", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.set_cookie(
        key="app_session_token",
        value=app_access_token,
        httponly=True,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60
    )
    response.delete_cookie(STATE_COOKIE_NAME)

    return response


@app.get("/profile")
async def get_user_profile(payload: dict | None = Depends(get_current_user)):
    if payload is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_308_PERMANENT_REDIRECT)

    return JSONResponse(content={"message": "Login successful!", "username": payload.get('username')})
