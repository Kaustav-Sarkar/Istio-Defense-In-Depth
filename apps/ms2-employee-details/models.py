from sqlalchemy import Column, String, Date, Numeric, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from database import Base
import uuid

class Employee(Base):
    __tablename__ = "employees"
    __table_args__ = {"schema": "hr"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    work_email = Column(String(255), unique=True, nullable=False)
    work_phone = Column(String(50), nullable=True)
    job_title = Column(String(100), nullable=False)
    department = Column(String(100), nullable=False)
    manager_id = Column(UUID(as_uuid=True), ForeignKey("hr.employees.id"), nullable=True)
    hire_date = Column(Date, nullable=False)
    status = Column(String(50), nullable=False)

class EmployeePII(Base):
    __tablename__ = "employee_pii"
    __table_args__ = {"schema": "hr"}

    employee_id = Column(UUID(as_uuid=True), ForeignKey("hr.employees.id"), primary_key=True)
    ssn = Column(String(20), unique=True, nullable=False)
    date_of_birth = Column(Date, nullable=False)
    personal_phone = Column(String(50), nullable=True)
    home_address = Column(Text, nullable=True)
    gender = Column(String(20), nullable=True)

class EmployeeFinancials(Base):
    __tablename__ = "employee_financials"
    __table_args__ = {"schema": "hr"}

    employee_id = Column(UUID(as_uuid=True), ForeignKey("hr.employees.id"), primary_key=True)
    base_salary = Column(Numeric(12, 2), nullable=False)
    bonus = Column(Numeric(12, 2), nullable=True)
    bank_account_number = Column(String(50), nullable=True)
    routing_number = Column(String(20), nullable=True)
