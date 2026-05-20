from pydantic import BaseModel, ConfigDict
from typing import Optional
from decimal import Decimal

class OfficeLocationBase(BaseModel):
    city_name: str
    address: str
    country_code: str
    capacity: int
    status: Optional[str] = "Open"
    latitude: Optional[Decimal] = None
    longitude: Optional[Decimal] = None

class OfficeLocationCreate(OfficeLocationBase):
    established_date: str

class OfficeLocationUpdate(BaseModel):
    city_name: Optional[str] = None
    address: Optional[str] = None
    country_code: Optional[str] = None
    capacity: Optional[int] = None
    status: Optional[str] = None
    latitude: Optional[Decimal] = None
    longitude: Optional[Decimal] = None
    established_date: Optional[str] = None

class OfficeLocationResponse(OfficeLocationBase):
    id: int
    established_date: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)
