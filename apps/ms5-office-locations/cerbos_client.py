import httpx
import logging
from typing import Dict, Any, List
from config import settings

logger = logging.getLogger(__name__)

async def check_cerbos(
    principal_id: str,
    principal_roles: List[str],
    resource_kind: str,
    resource_id: str,
    action: str,
    resource_attrs: Dict[str, Any] = None,
    request_id: str | None = None
) -> Dict[str, Any]:
    """
    Call Cerbos to check permissions and get masking outputs.
    """
    payload = {
        "requestId": request_id if request_id else "unknown",
        "principal": {
            "id": principal_id,
            "roles": principal_roles,
        },
        "resources": [
            {
                "actions": [action],
                "resource": {
                    "kind": resource_kind,
                    "id": resource_id,
                    "attr": resource_attrs or {}
                }
            }
        ]
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{settings.CERBOS_URL}/api/check/resources", json=payload, timeout=settings.CERBOS_TIMEOUT_SECONDS)
            response.raise_for_status()
            data = response.json()
            
            result = data.get("results", [])[0]
            action_result = result.get("actions", {}).get(action, "EFFECT_DENY")
            outputs = result.get("outputs", [])
            
            # Extract output for the specific action
            action_output = {}
            if outputs and len(outputs) > 0:
                action_output = outputs[0].get("val", {})
                    
            return {
                "allowed": action_result == "EFFECT_ALLOW",
                "outputs": action_output
            }
    except Exception as e:
        logger.error(f"Cerbos check failed: {e}")
        # Fail closed for writes, but allow reads for public data
        if action in ["view", "list"]:
            logger.warning("Cerbos is down. Allowing read-only access to public data.")
            return {"allowed": True, "outputs": {}}
        return {"allowed": False, "outputs": {}}
