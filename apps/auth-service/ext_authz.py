import uuid

from fastapi import Request
from sqlalchemy.orm import Session
from config import settings
import sessions
import oidc

def _normalize_check_path(path: str) -> str:
    if path == "/verify":
        return "/"
    if path.startswith("/verify/"):
        return path[len("/verify"):]
    return path

def evaluate_request(request: Request, db: Session) -> dict:
    decision = {
        "allowed": False,
        "subject": None,
        "username": None,
        "email": None,
        "roles": [],
        "groups": [],
        "department": None,
        "audience": [],
        "request_id": request.headers.get("x-request-id", "unknown")
    }

    # Extract method and path from envoy headers or fallback to fastapi url
    path = _normalize_check_path(request.headers.get("x-envoy-original-path") or request.url.path)
    method = request.headers.get("x-envoy-original-method") or request.method

    user_info = None

    # 1. Check Bearer Token
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        decoded = oidc.validate_bearer(token)
        if decoded:
            roles = []
            realm_access = decoded.get("realm_access", {})
            if "roles" in realm_access:
                roles = realm_access["roles"]

            username = decoded.get("preferred_username")
            if username:
                subject = str(uuid.uuid5(uuid.NAMESPACE_URL, f"istio-security://users/{username}"))
            else:
                subject = decoded.get("sub")

            user_info = {
                "subject": subject,
                "username": username,
                "email": decoded.get("email"),
                "roles": roles,
                "groups": decoded.get("groups", []),
                "department": decoded.get("department")
            }

    # 2. Check Cookie Session if no bearer
    if not user_info:
        cookie = request.cookies.get(settings.COOKIE_NAME)
        if cookie:
            session = sessions.get_session(db, cookie)
            if session:
                user_info = {
                    "subject": session.user_id,
                    "username": session.username,
                    "email": session.email,
                    "roles": session.roles,
                    "groups": session.groups or [],
                    "department": session.department
                }

    if not user_info:
        decision["reason"] = "No valid authentication found"
        return decision

    decision.update(user_info)

    allowed_roles = set()

    # 3. Coarse Route/Role Policy Map
    if path.startswith("/api/profile/"):
        allowed_roles = {"employee", "manager", "hr_admin", "it_admin"}
        decision["audience"] = ["ms1-profile-aggregator", "ms2-employee-details", "ms3-hardware-assets"]
    elif path.startswith("/api/holidays") and method == "GET":
        allowed_roles = {"employee", "manager", "hr_admin", "it_admin", "public_data_admin", "security_auditor"}
        decision["audience"] = ["ms4-holiday-calendar"]
    elif path.startswith("/api/holidays") and method in ("POST", "PUT", "DELETE", "PATCH"):
        allowed_roles = {"public_data_admin", "hr_admin"}
        decision["audience"] = ["ms4-holiday-calendar"]
    else:
        decision["reason"] = "Route not defined in coarse policy map"
        return decision

    user_roles = set(decision["roles"])
    if not allowed_roles.intersection(user_roles):
        decision["reason"] = "Unauthorized role for route"
        return decision

    decision["allowed"] = True
    return decision
