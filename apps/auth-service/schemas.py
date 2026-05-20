from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime
from uuid import UUID

class SessionInfo(BaseModel):
    id: UUID
    user_id: str
    roles: List[str]
    created_at: datetime
    expires_at: datetime
    revoked: bool

    model_config = ConfigDict(from_attributes=True)

class JWKSKey(BaseModel):
    kty: str
    kid: str
    use: str
    alg: str
    n: str
    e: str

class JWKSResponse(BaseModel):
    keys: List[JWKSKey]

class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    id_token: str
    not_before_policy: int
    session_state: str
    scope: str
