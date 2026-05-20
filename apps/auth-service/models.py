import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ARRAY
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
from database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = {"schema": "auth"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(255), nullable=False, index=True)
    username = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True)
    roles = Column(ARRAY(String), nullable=False)
    groups = Column(ARRAY(String), nullable=True)
    department = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow)
    revoked = Column(Boolean, default=False)

class OAuthState(Base):
    __tablename__ = "oauth_states"
    __table_args__ = {"schema": "auth"}

    state_hash = Column(String(255), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
