from sqlalchemy import Column, Integer, String, Numeric
from database import Base

class OfficeLocation(Base):
    __tablename__ = "office_locations"
    __table_args__ = {"schema": "public_data"}

    id = Column(Integer, primary_key=True, index=True)
    city_name = Column(String(100), nullable=False)
    address = Column(String(255), nullable=False)
    country_code = Column(String(10), nullable=False)
    capacity = Column(Integer, nullable=False)
    status = Column(String(50), default="Open")
    latitude = Column(Numeric(10, 7))
    longitude = Column(Numeric(10, 7))
    established_date = Column(String(50))
