import logging
from typing import List
from fastapi import FastAPI, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import get_db
from models import CompanyHoliday
from schemas import HolidayCreate, HolidayUpdate, HolidayResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MS4 Holiday Calendar API", description="Tier 1 microservice for company holidays")

async def get_ms4_headers(
    x_ms4_user: str | None = Header(None),
    x_ms4_role: str | None = Header(None),
    x_request_id: str | None = Header(None)
):
    """Extract and log custom headers injected by Envoy sidecar."""
    if not x_ms4_user or not x_ms4_role:
        raise HTTPException(status_code=401, detail="Missing required legacy headers")
    logger.info(f"Received Envoy headers - x-ms4-user: {x_ms4_user}, x-ms4-role: {x_ms4_role}, x-request-id: {x_request_id}")
    return {"user": x_ms4_user, "role": x_ms4_role, "request_id": x_request_id}

def require_admin(headers: dict = Depends(get_ms4_headers)):
    roles = headers.get("role", "").split(",")
    if "public_data_admin" not in roles and "hr_admin" not in roles:
        raise HTTPException(status_code=403, detail="Forbidden: admin role required")
    return headers

@app.get("/health")
async def health_check():
    return {"status": "ok"}

from cerbos_client import check_cerbos
from rls import set_rls_context

@app.get("/api/holidays", response_model=List[HolidayResponse])
async def get_holidays(
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms4_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="holiday_calendar",
        resource_id="*",
        action="list",
        request_id=request_id
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    result = await db.execute(select(CompanyHoliday))
    return result.scalars().all()

@app.get("/api/holidays/{id}", response_model=HolidayResponse)
async def get_holiday(
    id: int,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms4_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="holiday_calendar",
        resource_id=str(id),
        action="view",
        request_id=request_id,
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    result = await db.execute(select(CompanyHoliday).where(CompanyHoliday.id == id))
    holiday = result.scalars().first()
    if not holiday:
        raise HTTPException(status_code=404, detail="Holiday not found")
    return holiday

@app.post("/api/holidays", response_model=HolidayResponse, status_code=status.HTTP_201_CREATED)
async def create_holiday(
    holiday: HolidayCreate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_admin)
):
    new_holiday = CompanyHoliday(**holiday.model_dump())
    db.add(new_holiday)
    await db.commit()
    await db.refresh(new_holiday)
    return new_holiday

@app.put("/api/holidays/{id}", response_model=HolidayResponse)
async def update_holiday(
    id: int,
    holiday_update: HolidayUpdate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_admin)
):
    result = await db.execute(select(CompanyHoliday).where(CompanyHoliday.id == id))
    existing_holiday = result.scalars().first()
    if not existing_holiday:
        raise HTTPException(status_code=404, detail="Holiday not found")
    
    for key, value in holiday_update.model_dump(exclude_unset=True).items():
        setattr(existing_holiday, key, value)
        
    await db.commit()
    await db.refresh(existing_holiday)
    return existing_holiday

@app.delete("/api/holidays/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_holiday(
    id: int,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_admin)
):
    result = await db.execute(select(CompanyHoliday).where(CompanyHoliday.id == id))
    existing_holiday = result.scalars().first()
    if not existing_holiday:
        raise HTTPException(status_code=404, detail="Holiday not found")
        
    await db.delete(existing_holiday)
    await db.commit()
    return None
