import asyncio
import logging
import httpx
from fastapi import FastAPI, HTTPException, Header, Depends
from uuid import UUID

from schemas import ProfileResponse
from config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MS1 Profile Aggregator API")

async def get_ms1_headers(
    x_ms1_user: str | None = Header(None),
    x_ms1_role: str | None = Header(None),
    x_request_id: str | None = Header(None),
    x_mesh_identity: str | None = Header(None)
):
    """Extract and log custom headers injected by Envoy sidecar."""
    if not x_ms1_user or not x_ms1_role:
        raise HTTPException(status_code=401, detail="Missing required legacy headers")
    logger.info(f"Received Envoy headers - x-ms1-user: {x_ms1_user}, x-ms1-role: {x_ms1_role}, x-request-id: {x_request_id}")
    return {
        "user": x_ms1_user, 
        "role": x_ms1_role, 
        "request_id": x_request_id,
        "mesh_identity": x_mesh_identity
    }

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/api/profile/{id}", response_model=ProfileResponse)
async def get_profile(
    id: UUID,
    headers: dict = Depends(get_ms1_headers)
):
    ms2_url = f"{settings.MS2_BASE_URL}/api/employees/{id}"
    ms2_fin_url = f"{settings.MS2_BASE_URL}/api/employees/{id}/financials"
    ms2_pii_url = f"{settings.MS2_BASE_URL}/api/employees/{id}/pii"
    ms3_url = f"{settings.MS3_BASE_URL}/api/assets?employee_id={id}"
    
    downstream_headers = {}
    if headers.get("request_id"):
        downstream_headers["x-request-id"] = headers["request_id"]
    if headers.get("mesh_identity"):
        downstream_headers["x-mesh-identity"] = headers["mesh_identity"]
    
    # We don't need to forward x-ms2-user or x-ms3-user manually, because the inbound sidecars of MS2 and MS3 
    # will project them from x-mesh-identity. But for compatibility during migration, we can send them if needed.
    # The architecture doc says: "Rely on projected x-ms1-* headers as compatibility context, not as original proof."
    # And "Ensure downstream calls preserve mesh identity at platform boundary as designed in Phase 4."
    # So we just forward x-mesh-identity and x-request-id.
    
    async with httpx.AsyncClient(timeout=settings.DOWNSTREAM_TIMEOUT_SECONDS) as client:
        # Launch requests concurrently
        ms2_task = asyncio.create_task(client.get(ms2_url, headers=downstream_headers))
        ms2_fin_task = asyncio.create_task(client.get(ms2_fin_url, headers=downstream_headers))
        ms2_pii_task = asyncio.create_task(client.get(ms2_pii_url, headers=downstream_headers))
        ms3_task = asyncio.create_task(client.get(ms3_url, headers=downstream_headers))
        
        results = await asyncio.gather(ms2_task, ms2_fin_task, ms2_pii_task, ms3_task, return_exceptions=True)
        
        ms2_res, ms2_fin_res, ms2_pii_res, ms3_res = results
        
        # Handle exceptions and HTTP errors for MS2
        if isinstance(ms2_res, Exception):
            logger.error(f"MS2 connection error: {ms2_res}")
            raise HTTPException(status_code=502, detail="Error communicating with MS2")
        
        if ms2_res.status_code == 404:
            raise HTTPException(status_code=404, detail="Employee not found")
        elif ms2_res.status_code != 200:
            logger.error(f"MS2 error: status={ms2_res.status_code}, body={ms2_res.text}")
            raise HTTPException(status_code=502, detail="Invalid response from MS2")
            
        employee_data = ms2_res.json()
        
        # Merge financials if successful
        fin_error = None
        if isinstance(ms2_fin_res, Exception):
            logger.error(f"MS2 financials connection error: {ms2_fin_res}")
            fin_error = "Connection error"
        elif ms2_fin_res.status_code == 403:
            fin_error = "Forbidden"
        elif ms2_fin_res.status_code != 200:
            logger.error(f"MS2 financials error: status={ms2_fin_res.status_code}, body={ms2_fin_res.text}")
            fin_error = f"Error {ms2_fin_res.status_code}"
        else:
            fin_data = ms2_fin_res.json()
            if fin_data:
                # Update employee_data with financial info
                employee_data.update(fin_data)

        # Merge PII if successful
        pii_error = None
        if isinstance(ms2_pii_res, Exception):
            logger.error(f"MS2 PII connection error: {ms2_pii_res}")
            pii_error = "Connection error"
        elif ms2_pii_res.status_code == 403:
            pii_error = "Forbidden"
        elif ms2_pii_res.status_code != 200:
            logger.error(f"MS2 PII error: status={ms2_pii_res.status_code}, body={ms2_pii_res.text}")
            pii_error = f"Error {ms2_pii_res.status_code}"
        else:
            pii_data = ms2_pii_res.json()
            if pii_data:
                # Update employee_data with PII info
                employee_data.update(pii_data)
        
        # Handle exceptions and HTTP errors for MS3 (Graceful degradation)
        assets_data = []
        assets_error = None
        if isinstance(ms3_res, Exception):
            logger.error(f"MS3 connection error: {ms3_res}")
            assets_error = "Connection error"
        elif ms3_res.status_code == 403:
            assets_error = "Forbidden"
        elif ms3_res.status_code != 200:
            logger.error(f"MS3 error: status={ms3_res.status_code}, body={ms3_res.text}")
            assets_error = f"Error {ms3_res.status_code}"
        else:
            assets_data = ms3_res.json()
            
        return ProfileResponse(
            employee=employee_data, 
            assets=assets_data, 
            assets_error=assets_error,
            pii_error=pii_error,
            fin_error=fin_error
        )
