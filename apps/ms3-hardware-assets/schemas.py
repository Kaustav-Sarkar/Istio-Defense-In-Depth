from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import date
from uuid import UUID

class HardwareAssetBase(BaseModel):
    employee_id: Optional[UUID] = None
    device_type: str
    model_name: str
    serial_number: Optional[str] = None
    mac_address: Optional[str] = None
    issue_date: date
    status: str

class HardwareAssetCreate(HardwareAssetBase):
    asset_tag: str

class HardwareAssetUpdate(BaseModel):
    employee_id: Optional[UUID] = None
    device_type: Optional[str] = None
    model_name: Optional[str] = None
    serial_number: Optional[str] = None
    mac_address: Optional[str] = None
    issue_date: Optional[date] = None
    status: Optional[str] = None

class HardwareAssetResponse(HardwareAssetBase):
    asset_tag: str

    model_config = ConfigDict(from_attributes=True)
