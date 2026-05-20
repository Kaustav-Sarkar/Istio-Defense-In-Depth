import logging
from typing import List, Optional
from fastapi import FastAPI, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import get_db
from models import OfficeLocation
from schemas import OfficeLocationCreate, OfficeLocationUpdate, OfficeLocationResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MS5 Office Locations API", description="Tier 1 microservice for office locations")

async def get_ms5_headers(
    x_ms5_user: str | None = Header(None),
    x_ms5_role: str | None = Header(None),
    x_request_id: str | None = Header(None)
):
    """Extract and log custom headers injected by Envoy sidecar."""
    if not x_ms5_user or not x_ms5_role:
        x_ms5_user = "anonymous"
        x_ms5_role = "public"
        
    logger.info(f"Received Envoy headers - x-ms5-user: {x_ms5_user}, x-ms5-role: {x_ms5_role}, x-request-id: {x_request_id}")
    return {"user": x_ms5_user, "role": x_ms5_role, "request_id": x_request_id}

def require_admin(headers: dict = Depends(get_ms5_headers)):
    roles = headers.get("role", "").split(",")
    if "public_data_admin" not in roles:
        raise HTTPException(status_code=403, detail="Forbidden: admin role required")
    return headers

@app.get("/health")
async def health_check():
    return {"status": "ok"}

from cerbos_client import check_cerbos
from rls import set_rls_context

@app.get("/api/offices", response_model=List[OfficeLocationResponse])
async def get_offices(
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms5_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="office_location",
        resource_id="*",
        action="list",
        request_id=request_id
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    result = await db.execute(select(OfficeLocation))
    return result.scalars().all()

@app.get("/api/offices/{id}", response_model=OfficeLocationResponse)
async def get_office(
    id: int,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms5_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="office_location",
        resource_id=str(id),
        action="view",
        request_id=request_id,
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    result = await db.execute(select(OfficeLocation).where(OfficeLocation.id == id))
    office = result.scalars().first()
    if not office:
        raise HTTPException(status_code=404, detail="Office location not found")
    return office

@app.post("/api/offices", response_model=OfficeLocationResponse, status_code=status.HTTP_201_CREATED)
async def create_office(
    office: OfficeLocationCreate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_admin)
):
    new_office = OfficeLocation(**office.model_dump())
    db.add(new_office)
    await db.commit()
    await db.refresh(new_office)
    return new_office

@app.put("/api/offices/{id}", response_model=OfficeLocationResponse)
async def update_office(
    id: int,
    office_update: OfficeLocationUpdate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_admin)
):
    result = await db.execute(select(OfficeLocation).where(OfficeLocation.id == id))
    existing_office = result.scalars().first()
    if not existing_office:
        raise HTTPException(status_code=404, detail="Office location not found")
    
    for key, value in office_update.model_dump(exclude_unset=True).items():
        setattr(existing_office, key, value)
        
    await db.commit()
    await db.refresh(existing_office)
    return existing_office

@app.delete("/api/offices/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_office(
    id: int,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_admin)
):
    result = await db.execute(select(OfficeLocation).where(OfficeLocation.id == id))
    existing_office = result.scalars().first()
    if not existing_office:
        raise HTTPException(status_code=404, detail="Office location not found")
        
    await db.delete(existing_office)
    await db.commit()
    return None
