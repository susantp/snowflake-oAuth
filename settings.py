from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class Settings(BaseSettings):
    snowflake_client_id: str
    snowflake_client_secret: str
    snowflake_account_url: str
    redirect_uri: str
    snowflake_role_scope: str
    app_jwt_secret: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    model_config = SettingsConfigDict(env_file=Path(__file__).resolve().parent.joinpath('.env'))
