import logging
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import FastAPI, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import get_db
from models import HardwareAsset
from schemas import HardwareAssetCreate, HardwareAssetUpdate, HardwareAssetResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MS3 Hardware Assets API", description="Tier 2 microservice for hardware assets")

async def get_ms3_headers(
    x_ms3_user: str | None = Header(None),
    x_ms3_role: str | None = Header(None),
    x_request_id: str | None = Header(None)
):
    """Extract and log custom headers expected by MS3."""
    if not x_ms3_user or not x_ms3_role:
        raise HTTPException(status_code=401, detail="Missing required legacy headers")
    logger.info(f"Received headers - x-ms3-user: {x_ms3_user}, x-ms3-role: {x_ms3_role}, x-request-id: {x_request_id}")
    return {"user": x_ms3_user, "role": x_ms3_role, "request_id": x_request_id}

def require_it_admin(headers: dict = Depends(get_ms3_headers)):
    if headers.get("role") != "it_admin":
        raise HTTPException(status_code=403, detail="Forbidden: it_admin role required")
    return headers

@app.get("/health")
async def health_check():
    return {"status": "ok"}

from cerbos_client import check_cerbos
from masking import apply_masking
from rls import set_rls_context

async def authorize_asset_write(
    db: AsyncSession,
    headers: dict,
    resource_id: str = "*",
    resource_attrs: Dict[str, Any] | None = None
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")

    await set_rls_context(db, user_id, headers["role"], request_id)

    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="hardware_asset",
        resource_id=resource_id,
        action="update",
        resource_attrs=resource_attrs or {},
        request_id=request_id
    )

    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")

    return cerbos_result

@app.get("/api/assets", response_model=List[Dict[str, Any]])
async def get_assets(
    employee_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms3_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    # Set RLS context
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    query = select(HardwareAsset)
    if employee_id:
        query = query.where(HardwareAsset.employee_id == employee_id)
        
    result = await db.execute(query)
    assets = result.scalars().all()
    
    # Check Cerbos for list action
    # We use a generic resource check for list
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="hardware_asset",
        resource_id="*",
        action="list",
        resource_attrs={"owner_id": str(employee_id) if employee_id else None},
        request_id=request_id,
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    serial_mode = cerbos_result["outputs"].get("asset_serial_mode", "truncated")
    
    masked_assets = []
    for asset in assets:
        masked_data = apply_masking(asset.__dict__, serial_mode)
        masked_assets.append(masked_data)
        
    return masked_assets

@app.get("/api/assets/{asset_tag}", response_model=Dict[str, Any])
async def get_asset(
    asset_tag: str,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms3_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    # Set RLS context
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    result = await db.execute(select(HardwareAsset).where(HardwareAsset.asset_tag == asset_tag))
    asset = result.scalars().first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    # Check Cerbos
    resource_attrs = {
        "owner_id": str(asset.employee_id) if asset.employee_id else None
    }
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="hardware_asset",
        resource_id=asset_tag,
        action="view",
        resource_attrs=resource_attrs,
        request_id=request_id,
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    serial_mode = cerbos_result["outputs"].get("asset_serial_mode", "truncated")
    masked_data = apply_masking(asset.__dict__, serial_mode)
    
    return masked_data

@app.post("/api/assets", response_model=HardwareAssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset: HardwareAssetCreate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_it_admin)
):
    await authorize_asset_write(db, headers, resource_id=asset.asset_tag)
    # Check if asset exists
    existing = await db.execute(select(HardwareAsset).where(HardwareAsset.asset_tag == asset.asset_tag))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="Asset with this tag already exists")
        
    new_asset = HardwareAsset(**asset.model_dump())
    db.add(new_asset)
    await db.commit()
    await db.refresh(new_asset)
    return new_asset

@app.put("/api/assets/{asset_tag}", response_model=HardwareAssetResponse)
async def update_asset(
    asset_tag: str,
    asset_update: HardwareAssetUpdate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_it_admin)
):
    result = await db.execute(select(HardwareAsset).where(HardwareAsset.asset_tag == asset_tag))
    existing_asset = result.scalars().first()
    if not existing_asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    await authorize_asset_write(
        db,
        headers,
        resource_id=asset_tag,
        resource_attrs={"owner_id": str(getattr(existing_asset, "employee_id", "")) if getattr(existing_asset, "employee_id", None) else None}
    )

    for key, value in asset_update.model_dump(exclude_unset=True).items():
        setattr(existing_asset, key, value)

    await db.commit()
    await db.refresh(existing_asset)
    return existing_asset

@app.delete("/api/assets/{asset_tag}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_tag: str,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_it_admin)
):
    result = await db.execute(select(HardwareAsset).where(HardwareAsset.asset_tag == asset_tag))
    existing_asset = result.scalars().first()
    if not existing_asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    await authorize_asset_write(
        db,
        headers,
        resource_id=asset_tag,
        resource_attrs={"owner_id": str(getattr(existing_asset, "employee_id", "")) if getattr(existing_asset, "employee_id", None) else None}
    )

    await db.delete(existing_asset)
    await db.commit()
    return None
