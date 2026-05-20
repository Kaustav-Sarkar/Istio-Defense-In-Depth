import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session as DbSession
from models import Session, OAuthState

def create_oauth_state(db: DbSession, expires_in_minutes: int = 15) -> str:
    state = secrets.token_urlsafe(32)
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    
    oauth_state = OAuthState(
        state_hash=state_hash,
        expires_at=expires_at
    )
    db.add(oauth_state)
    db.commit()
    
    return state

def verify_oauth_state(db: DbSession, state: str) -> bool:
    if not state:
        return False
        
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    oauth_state = db.query(OAuthState).filter(OAuthState.state_hash == state_hash).with_for_update().first()
    
    if not oauth_state:
        return False
        
    if oauth_state.consumed_at or oauth_state.expires_at < datetime.now(timezone.utc):
        return False
        
    oauth_state.consumed_at = datetime.now(timezone.utc)
    db.commit()
    return True

def create_session(db: DbSession, user_id: str, roles: list[str], username: str = None, email: str = None, groups: list[str] = None, department: str = None, expires_in_seconds: int = 3600) -> Session:
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
    db_session = Session(
        user_id=user_id,
        username=username,
        email=email,
        roles=roles,
        groups=groups,
        department=department,
        expires_at=expires_at
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session

def get_session(db: DbSession, session_id: str) -> Session | None:
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        return None
    
    session = db.query(Session).filter(Session.id == session_uuid).first()
    if not session:
        return None
        
    if session.revoked or session.expires_at < datetime.now(timezone.utc):
        return None
        
    now = datetime.now(timezone.utc)
    if not session.last_seen_at or now - session.last_seen_at > timedelta(minutes=5):
        session.last_seen_at = now
        try:
            db.commit()
        except Exception:
            db.rollback()
            # Session is still valid, we just failed to update the last_seen_at timestamp
        
    return session

def revoke_session(db: DbSession, session_id: str) -> bool:
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        return False
        
    session = db.query(Session).filter(Session.id == session_uuid).first()
    if session:
        session.revoked = True
        db.commit()
        return True
    return False
