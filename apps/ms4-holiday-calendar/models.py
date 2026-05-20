from sqlalchemy import Column, Integer, String, Date
from database import Base

class CompanyHoliday(Base):
    __tablename__ = "company_holidays"
    __table_args__ = {"schema": "public_data"}

    id = Column(Integer, primary_key=True, index=True)
    holiday_date = Column(Date, nullable=False)
    holiday_name = Column(String(100), nullable=False)
    country_code = Column(String(10))
