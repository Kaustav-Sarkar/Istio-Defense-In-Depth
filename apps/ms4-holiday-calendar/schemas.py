from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import date

class HolidayBase(BaseModel):
    holiday_date: date
    holiday_name: str
    country_code: Optional[str] = None

class HolidayCreate(HolidayBase):
    pass

class HolidayUpdate(BaseModel):
    holiday_date: Optional[date] = None
    holiday_name: Optional[str] = None
    country_code: Optional[str] = None

class HolidayResponse(HolidayBase):
    id: int
    
    model_config = ConfigDict(from_attributes=True)
