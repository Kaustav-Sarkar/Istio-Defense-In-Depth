from fastapi import FastAPI, Depends, Request, Response, HTTPException, Cookie
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import Optional

from contextlib import asynccontextmanager

from database import get_db
from config import settings
import oidc, sessions, ext_authz, mesh_tokens, jwks, vault_client
import urllib.parse

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    oidc._client.close()
    vault_client._client.close()

app = FastAPI(title="Auth Service", lifespan=lifespan)

def _public_app_root() -> str:
    return settings.APP_PUBLIC_URL.rstrip("/")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/auth/login")
def login(request: Request, db: Session = Depends(get_db)):
    # Set the redirect URI to callback
    redirect_uri = f"{_public_app_root()}/auth/callback"
    state = sessions.create_oauth_state(db)
    return RedirectResponse(oidc.get_login_url(redirect_uri, state))

@app.get("/auth/callback")
def callback(code: str, state: Optional[str] = None, db: Session = Depends(get_db)):
    if not sessions.verify_oauth_state(db, state):
        raise HTTPException(status_code=401, detail="Invalid or missing state")
        
    redirect_uri = f"{_public_app_root()}/auth/callback"
    try:
        token_data = oidc.exchange_code(code, redirect_uri)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Failed to exchange code")
        
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="No access token")
        
    decoded = oidc.validate_bearer(access_token)
    if not decoded:
        raise HTTPException(status_code=401, detail="Invalid token signature")
        
    import uuid
    
    username = decoded.get("preferred_username")
    if username:
        user_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"istio-security://users/{username}"))
    else:
        user_id = decoded.get("sub")
        
    email = decoded.get("email")
    
    roles = []
    realm_access = decoded.get("realm_access", {})
    if "roles" in realm_access:
        roles = realm_access["roles"]
        
    groups = decoded.get("groups", [])
    department = decoded.get("department")
        
    # Create DB session
    session = sessions.create_session(
        db, 
        user_id=user_id, 
        roles=roles, 
        username=username, 
        email=email, 
        groups=groups, 
        department=department
    )
    
    response = RedirectResponse(url="/")
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=str(session.id),
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=3600
    )
    return response

@app.get("/auth/logout")
def logout(zt_session: Optional[str] = Cookie(None), db: Session = Depends(get_db)):
    if zt_session:
        sessions.revoke_session(db, zt_session)
        
    post_logout_redirect_uri = f"{_public_app_root()}/"
    params = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "post_logout_redirect_uri": post_logout_redirect_uri
    }
    query = urllib.parse.urlencode(params)
    logout_url = f"{settings.KEYCLOAK_PUBLIC_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout?{query}"
    
    response = RedirectResponse(url=logout_url)
    response.delete_cookie(
        settings.COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/"
    )
    return response

@app.get("/auth/session")
def get_session(zt_session: Optional[str] = Cookie(None), db: Session = Depends(get_db)):
    if not zt_session:
        raise HTTPException(status_code=401, detail="No session")
        
    session = sessions.get_session(db, zt_session)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
        
    return {
        "id": session.id,
        "user_id": session.user_id,
        "username": session.username,
        "email": session.email,
        "roles": session.roles,
        "groups": session.groups,
        "department": session.department,
        "created_at": session.created_at,
        "expires_at": session.expires_at,
        "revoked": session.revoked
    }

@app.get("/auth/jwks")
def jwks_endpoint():
    try:
        return jwks.get_jwks()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to fetch JWKS")

# Catch all route for ExtAuthz
@app.api_route("/verify/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.api_route("/verify", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def verify(request: Request, db: Session = Depends(get_db), path: str = ""):
    decision = ext_authz.evaluate_request(request, db)
    
    if not decision.get("allowed"):
        return Response(status_code=401, content="Unauthorized")
        
    # Generate Mesh Token
    try:
        mesh_token = mesh_tokens.create_mesh_token(decision)
    except Exception as e:
        return Response(status_code=500, content="Internal Server Error")
        
    # ExtAuthz requires returning the header we want injected
    response = Response(status_code=200, content="Authorized")
    response.headers["x-mesh-identity"] = mesh_token
    return response
