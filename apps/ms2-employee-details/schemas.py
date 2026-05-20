from pydantic import BaseModel, ConfigDict, EmailStr, Field
from typing import Optional
from datetime import date
from uuid import UUID
from decimal import Decimal

# --- Employee Schemas ---

class EmployeeBase(BaseModel):
    first_name: str
    last_name: str
    work_email: EmailStr
    work_phone: Optional[str] = None
    job_title: str
    department: str
    manager_id: Optional[UUID] = None
    hire_date: date
    status: str

class EmployeeCreate(EmployeeBase):
    pass

class EmployeeUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    work_email: Optional[EmailStr] = None
    work_phone: Optional[str] = None
    job_title: Optional[str] = None
    department: Optional[str] = None
    manager_id: Optional[UUID] = None
    hire_date: Optional[date] = None
    status: Optional[str] = None

class EmployeeResponse(EmployeeBase):
    id: UUID
    model_config = ConfigDict(from_attributes=True)


# --- Employee PII Schemas ---

class EmployeePIIBase(BaseModel):
    ssn: str
    date_of_birth: date
    personal_phone: Optional[str] = None
    home_address: Optional[str] = None
    gender: Optional[str] = None

class EmployeePIICreate(EmployeePIIBase):
    pass

class EmployeePIIUpdate(BaseModel):
    ssn: Optional[str] = None
    date_of_birth: Optional[date] = None
    personal_phone: Optional[str] = None
    home_address: Optional[str] = None
    gender: Optional[str] = None

class EmployeePIIResponse(EmployeePIIBase):
    employee_id: UUID
    model_config = ConfigDict(from_attributes=True)


# --- Employee Financials Schemas ---

class EmployeeFinancialsBase(BaseModel):
    base_salary: Decimal = Field(..., decimal_places=2)
    bonus: Optional[Decimal] = Field(None, decimal_places=2)
    bank_account_number: Optional[str] = None
    routing_number: Optional[str] = None

class EmployeeFinancialsCreate(EmployeeFinancialsBase):
    pass

class EmployeeFinancialsUpdate(BaseModel):
    base_salary: Optional[Decimal] = Field(None, decimal_places=2)
    bonus: Optional[Decimal] = Field(None, decimal_places=2)
    bank_account_number: Optional[str] = None
    routing_number: Optional[str] = None

class EmployeeFinancialsResponse(EmployeeFinancialsBase):
    employee_id: UUID
    model_config = ConfigDict(from_attributes=True)
