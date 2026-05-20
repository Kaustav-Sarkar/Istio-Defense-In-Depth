from sqlalchemy import Column, String, Date, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from database import Base

class HardwareAsset(Base):
    __tablename__ = "hardware_assets"
    __table_args__ = {"schema": "it"}

    asset_tag = Column(String(50), primary_key=True, index=True)
    employee_id = Column(UUID(as_uuid=True), ForeignKey("hr.employees.id"), nullable=True)
    device_type = Column(String(50), nullable=False)
    model_name = Column(String(100), nullable=False)
    serial_number = Column(String(100), nullable=True)
    mac_address = Column(String(50), nullable=True)
    issue_date = Column(Date, nullable=False)
    status = Column(String(50), nullable=False)
