import logging
from typing import List, Dict, Any
from uuid import UUID
from fastapi import FastAPI, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import get_db
from models import Employee, EmployeePII, EmployeeFinancials
from schemas import (
    EmployeeCreate, EmployeeUpdate, EmployeeResponse,
    EmployeePIICreate, EmployeePIIUpdate, EmployeePIIResponse,
    EmployeeFinancialsCreate, EmployeeFinancialsUpdate, EmployeeFinancialsResponse
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MS2 Employee Details API", description="Tier 2 microservice for HR employee details")

async def get_ms2_headers(
    x_ms2_user: str | None = Header(None),
    x_ms2_role: str | None = Header(None),
    x_request_id: str | None = Header(None)
):
    """Extract and log custom headers expected by MS2."""
    if not x_ms2_user or not x_ms2_role:
        raise HTTPException(status_code=401, detail="Missing required legacy headers")
    logger.info(f"Received headers - x-ms2-user: {x_ms2_user}, x-ms2-role: {x_ms2_role}, x-request-id: {x_request_id}")
    return {"user": x_ms2_user, "role": x_ms2_role, "request_id": x_request_id}

def require_hr_admin(headers: dict = Depends(get_ms2_headers)):
    if headers.get("role") != "hr_admin":
        raise HTTPException(status_code=403, detail="Forbidden: hr_admin role required")
    return headers

@app.get("/health")
async def health_check():
    return {"status": "ok"}

# ==========================================
# Employees
# ==========================================

@app.get("/api/employees", response_model=List[Dict[str, Any]])
async def get_employees(
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms2_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    # Set RLS context
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    result = await db.execute(select(Employee))
    employees = result.scalars().all()
    
    # We should ideally do a batch Cerbos check here, but for simplicity we'll check each or assume list action is allowed
    # Let's do a single check for the "list" action on a generic resource
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="employee_profile",
        resource_id="*",
        action="list",
        request_id=request_id
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    visible_fields = cerbos_result["outputs"].get("visible_fields", [])
    
    masked_employees = []
    for emp in employees:
        masked_data = apply_masking(emp.__dict__, visible_fields)
        masked_employees.append(masked_data)
        
    return masked_employees

from cerbos_client import check_cerbos
from masking import apply_masking
from rls import set_rls_context

async def authorize_hr_write(
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
        resource_kind="employee_profile",
        resource_id=resource_id,
        action="update",
        resource_attrs=resource_attrs or {},
        request_id=request_id
    )

    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")

    return cerbos_result

@app.get("/api/employees/{id}", response_model=Dict[str, Any])
async def get_employee(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms2_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    # Set RLS context
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    result = await db.execute(select(Employee).where(Employee.id == id))
    employee = result.scalars().first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
        
    # Check Cerbos
    resource_attrs = {
        "id": str(employee.id),
        "manager_id": str(employee.manager_id) if employee.manager_id else None,
        "department": employee.department,
        "status": employee.status
    }
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="employee_profile",
        resource_id=str(employee.id),
        action="view",
        resource_attrs=resource_attrs,
        request_id=request_id
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    # Apply masking
    visible_fields = cerbos_result["outputs"].get("visible_fields", [])
    masked_data = apply_masking(employee.__dict__, visible_fields)
    
    return masked_data

@app.post("/api/employees", response_model=EmployeeResponse, status_code=status.HTTP_201_CREATED)
async def create_employee(
    employee: EmployeeCreate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    await authorize_hr_write(db, headers)
    new_employee = Employee(**employee.model_dump())
    db.add(new_employee)
    await db.commit()
    await db.refresh(new_employee)
    return new_employee

@app.put("/api/employees/{id}", response_model=EmployeeResponse)
async def update_employee(
    id: UUID,
    employee_update: EmployeeUpdate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    result = await db.execute(select(Employee).where(Employee.id == id))
    existing_employee = result.scalars().first()
    if not existing_employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    await authorize_hr_write(
        db,
        headers,
        resource_id=str(existing_employee.id),
        resource_attrs={
            "id": str(existing_employee.id),
            "manager_id": str(getattr(existing_employee, "manager_id", "")) if getattr(existing_employee, "manager_id", None) else None,
            "department": getattr(existing_employee, "department", None),
            "status": getattr(existing_employee, "status", None)
        }
    )

    for key, value in employee_update.model_dump(exclude_unset=True).items():
        setattr(existing_employee, key, value)

    await db.commit()
    await db.refresh(existing_employee)
    return existing_employee

@app.delete("/api/employees/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_employee(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    result = await db.execute(select(Employee).where(Employee.id == id))
    existing_employee = result.scalars().first()
    if not existing_employee:
        raise HTTPException(status_code=404, detail="Employee not found")

    await authorize_hr_write(
        db,
        headers,
        resource_id=str(existing_employee.id),
        resource_attrs={
            "id": str(existing_employee.id),
            "manager_id": str(getattr(existing_employee, "manager_id", "")) if getattr(existing_employee, "manager_id", None) else None,
            "department": getattr(existing_employee, "department", None),
            "status": getattr(existing_employee, "status", None)
        }
    )

    await db.delete(existing_employee)
    await db.commit()
    return None

# ==========================================
# Employee PII
# ==========================================

@app.get("/api/employees/{id}/pii", response_model=Dict[str, Any])
async def get_employee_pii(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms2_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    # Set RLS context
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    # We need to get the employee first to get manager_id for Cerbos
    emp_result = await db.execute(select(Employee).where(Employee.id == id))
    employee = emp_result.scalars().first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
        
    resource_attrs = {
        "id": str(employee.id),
        "manager_id": str(employee.manager_id) if employee.manager_id else None,
        "department": employee.department,
        "status": employee.status
    }
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="employee_profile",
        resource_id=str(employee.id),
        action="view_sensitive",
        resource_attrs=resource_attrs,
        request_id=request_id
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    result = await db.execute(select(EmployeePII).where(EmployeePII.employee_id == id))
    pii = result.scalars().first()
    if not pii:
        raise HTTPException(status_code=404, detail="Employee PII not found")
        
    visible_fields = cerbos_result["outputs"].get("visible_fields", [])
    masked_data = apply_masking(pii.__dict__, visible_fields)
    
    return masked_data

@app.post("/api/employees/{id}/pii", response_model=EmployeePIIResponse, status_code=status.HTTP_201_CREATED)
async def create_employee_pii(
    id: UUID,
    pii: EmployeePIICreate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    await authorize_hr_write(db, headers, resource_id=str(id))
    existing = await db.execute(select(EmployeePII).where(EmployeePII.employee_id == id))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="PII for this employee already exists")
    
    new_pii = EmployeePII(employee_id=id, **pii.model_dump())
    db.add(new_pii)
    await db.commit()
    await db.refresh(new_pii)
    return new_pii

@app.put("/api/employees/{id}/pii", response_model=EmployeePIIResponse)
async def update_employee_pii(
    id: UUID,
    pii_update: EmployeePIIUpdate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    result = await db.execute(select(EmployeePII).where(EmployeePII.employee_id == id))
    existing_pii = result.scalars().first()
    if not existing_pii:
        raise HTTPException(status_code=404, detail="Employee PII not found")

    await authorize_hr_write(db, headers, resource_id=str(id))

    for key, value in pii_update.model_dump(exclude_unset=True).items():
        setattr(existing_pii, key, value)

    await db.commit()
    await db.refresh(existing_pii)
    return existing_pii

@app.delete("/api/employees/{id}/pii", status_code=status.HTTP_204_NO_CONTENT)
async def delete_employee_pii(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    result = await db.execute(select(EmployeePII).where(EmployeePII.employee_id == id))
    existing_pii = result.scalars().first()
    if not existing_pii:
        raise HTTPException(status_code=404, detail="Employee PII not found")

    await authorize_hr_write(db, headers, resource_id=str(id))

    await db.delete(existing_pii)
    await db.commit()
    return None

# ==========================================
# Employee Financials
# ==========================================

@app.get("/api/employees/{id}/financials", response_model=Dict[str, Any])
async def get_employee_financials(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(get_ms2_headers)
):
    user_id = headers["user"]
    roles = headers["role"].split(",")
    request_id = headers.get("request_id", "")
    
    # Set RLS context
    await set_rls_context(db, user_id, headers["role"], request_id)
    
    # We need to get the employee first to get manager_id for Cerbos
    emp_result = await db.execute(select(Employee).where(Employee.id == id))
    employee = emp_result.scalars().first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
        
    resource_attrs = {
        "id": str(employee.id),
        "manager_id": str(employee.manager_id) if employee.manager_id else None,
        "department": employee.department,
        "status": employee.status
    }
    
    cerbos_result = await check_cerbos(
        principal_id=user_id,
        principal_roles=roles,
        resource_kind="employee_profile",
        resource_id=str(employee.id),
        action="view_sensitive",
        resource_attrs=resource_attrs,
        request_id=request_id
    )
    
    if not cerbos_result["allowed"]:
        raise HTTPException(status_code=403, detail="Forbidden by Cerbos")
        
    result = await db.execute(select(EmployeeFinancials).where(EmployeeFinancials.employee_id == id))
    financials = result.scalars().first()
    if not financials:
        raise HTTPException(status_code=404, detail="Employee Financials not found")
        
    visible_fields = cerbos_result["outputs"].get("visible_fields", [])
    masked_data = apply_masking(financials.__dict__, visible_fields)
    
    return masked_data

@app.post("/api/employees/{id}/financials", response_model=EmployeeFinancialsResponse, status_code=status.HTTP_201_CREATED)
async def create_employee_financials(
    id: UUID,
    financials: EmployeeFinancialsCreate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    await authorize_hr_write(db, headers, resource_id=str(id))
    existing = await db.execute(select(EmployeeFinancials).where(EmployeeFinancials.employee_id == id))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="Financials for this employee already exist")

    new_financials = EmployeeFinancials(employee_id=id, **financials.model_dump())
    db.add(new_financials)
    await db.commit()
    await db.refresh(new_financials)
    return new_financials

@app.put("/api/employees/{id}/financials", response_model=EmployeeFinancialsResponse)
async def update_employee_financials(
    id: UUID,
    financials_update: EmployeeFinancialsUpdate,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    result = await db.execute(select(EmployeeFinancials).where(EmployeeFinancials.employee_id == id))
    existing_financials = result.scalars().first()
    if not existing_financials:
        raise HTTPException(status_code=404, detail="Employee Financials not found")

    await authorize_hr_write(db, headers, resource_id=str(id))

    for key, value in financials_update.model_dump(exclude_unset=True).items():
        setattr(existing_financials, key, value)

    await db.commit()
    await db.refresh(existing_financials)
    return existing_financials

@app.delete("/api/employees/{id}/financials", status_code=status.HTTP_204_NO_CONTENT)
async def delete_employee_financials(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    headers: dict = Depends(require_hr_admin)
):
    result = await db.execute(select(EmployeeFinancials).where(EmployeeFinancials.employee_id == id))
    existing_financials = result.scalars().first()
    if not existing_financials:
        raise HTTPException(status_code=404, detail="Employee Financials not found")

    await authorize_hr_write(db, headers, resource_id=str(id))

    await db.delete(existing_financials)
    await db.commit()
    return None
