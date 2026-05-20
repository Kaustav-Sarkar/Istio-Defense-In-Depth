"""DB Seeder microservice - populates the postgres database on startup."""

import os
import time
import uuid
from datetime import date
from decimal import Decimal
from uuid import UUID

from faker import Faker
from sqlalchemy import create_engine, text, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.types import String, Text, Date, Integer, Numeric

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/hr_directory"
)

DEMO_USER_SALARIES: dict[str, Decimal] = {
    "mary.manager": Decimal("300000.00"),
    "alice.employee": Decimal("160000.00"),
    "henry.hradmin": Decimal("70000.00"),
    "ivan.itadmin": Decimal("140000.00"),
}


def demo_user_id(username: str) -> UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"istio-security://users/{username}")


def update_demo_user_salaries(session: Session) -> None:
    """Refresh demo persona salaries when HR data was seeded earlier."""
    for username, salary in DEMO_USER_SALARIES.items():
        session.execute(
            text(
                "UPDATE hr.employee_financials SET base_salary = :salary "
                "WHERE employee_id = :emp_id"
            ),
            {"salary": salary, "emp_id": demo_user_id(username)},
        )


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


# ---------------------------------------------------------------------------
# HR Schema
# ---------------------------------------------------------------------------


class Employee(Base):
    """hr.employees - Public directory data."""

    __tablename__ = "employees"
    __table_args__ = {"schema": "hr"}

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    work_email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    work_phone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    job_title: Mapped[str] = mapped_column(String(100), nullable=False)
    department: Mapped[str] = mapped_column(String(100), nullable=False)
    manager_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("hr.employees.id"), nullable=True
    )
    hire_date: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)


class EmployeePii(Base):
    """hr.employee_pii - Highly sensitive personal data."""

    __tablename__ = "employee_pii"
    __table_args__ = {"schema": "hr"}

    employee_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("hr.employees.id"), primary_key=True
    )
    ssn: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    date_of_birth: Mapped[date] = mapped_column(Date, nullable=False)
    personal_phone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    home_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    gender: Mapped[str | None] = mapped_column(String(20), nullable=True)


class EmployeeFinancials(Base):
    """hr.employee_financials - Highly sensitive financial data."""

    __tablename__ = "employee_financials"
    __table_args__ = {"schema": "hr"}

    employee_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("hr.employees.id"), primary_key=True
    )
    base_salary: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    bonus: Mapped[Decimal | None] = mapped_column(Numeric(12, 2), nullable=True)
    bank_account_number: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )
    routing_number: Mapped[str | None] = mapped_column(String(20), nullable=True)


# ---------------------------------------------------------------------------
# IT Schema
# ---------------------------------------------------------------------------


class HardwareAsset(Base):
    """it.hardware_assets - Hardware assets."""

    __tablename__ = "hardware_assets"
    __table_args__ = {"schema": "it"}

    asset_tag: Mapped[str] = mapped_column(String(50), primary_key=True)
    employee_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("hr.employees.id"), nullable=True
    )
    device_type: Mapped[str] = mapped_column(String(50), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(50), nullable=True)
    issue_date: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)


# ---------------------------------------------------------------------------
# Public Data Schema
# ---------------------------------------------------------------------------


class OfficeLocation(Base):
    """public_data.office_locations - Offices & locations."""

    __tablename__ = "office_locations"
    __table_args__ = {"schema": "public_data"}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    city_name: Mapped[str] = mapped_column(String(100), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    country_code: Mapped[str] = mapped_column(String(10), nullable=False)
    capacity: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), server_default=text("'Open'")
    )
    latitude: Mapped[Decimal | None] = mapped_column(
        Numeric(10, 7), nullable=True
    )
    longitude: Mapped[Decimal | None] = mapped_column(
        Numeric(10, 7), nullable=True
    )
    established_date: Mapped[str | None] = mapped_column(String(50), nullable=True)


class CompanyHoliday(Base):
    """public_data.company_holidays - Company holidays."""

    __tablename__ = "company_holidays"
    __table_args__ = {"schema": "public_data"}

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    holiday_date: Mapped[date] = mapped_column(Date, nullable=False)
    holiday_name: Mapped[str] = mapped_column(String(100), nullable=False)
    country_code: Mapped[str | None] = mapped_column(String(10), nullable=True)


# ---------------------------------------------------------------------------
# Engine & Seeding
# ---------------------------------------------------------------------------

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

fake = Faker()
fake.seed_instance(42)


def seed_public_data(session: Session) -> None:
    """Seed public_data schema (office_locations, company_holidays)."""
    # Check if data already exists
    existing_offices = session.execute(text("SELECT COUNT(*) FROM public_data.office_locations")).scalar()
    if existing_offices and existing_offices > 0:
        print("Public data already exists. Skipping seed.")
        return

    offices = [
        OfficeLocation(
            city_name="New York",
            address="123 Tech Ave",
            country_code="US",
            capacity=500,
            latitude=Decimal("40.7128"),
            longitude=Decimal("-74.0060"),
            established_date="2010-01-15",
        ),
        OfficeLocation(
            city_name="San Francisco",
            address="456 SF St",
            country_code="US",
            capacity=400,
            latitude=Decimal("37.7749"),
            longitude=Decimal("-122.4194"),
            established_date="2015-06-20",
        ),
        OfficeLocation(
            city_name="London",
            address="456 UK St",
            country_code="UK",
            capacity=300,
            latitude=Decimal("51.5074"),
            longitude=Decimal("-0.1278"),
            established_date="2018-03-10",
        ),
        OfficeLocation(
            city_name="Tokyo",
            address="789 JP Blvd",
            country_code="JP",
            capacity=200,
            latitude=Decimal("35.6762"),
            longitude=Decimal("139.6503"),
            established_date="2021-09-01",
        ),
    ]
    holidays = [
        CompanyHoliday(
            holiday_date=date(2026, 1, 1),
            holiday_name="New Year's Day",
            country_code=None,
        ),
        CompanyHoliday(
            holiday_date=date(2026, 12, 25),
            holiday_name="Christmas",
            country_code=None,
        ),
    ]
    session.add_all(offices)
    session.add_all(holidays)


def seed_hr_and_it_data(session: Session) -> None:
    """Seed hr and it schemas (employees, employee_pii, employee_financials, hardware_assets)."""
    # Check if data already exists
    existing_employees = session.execute(text("SELECT COUNT(*) FROM hr.employees")).scalar()
    if existing_employees and existing_employees > 0:
        update_demo_user_salaries(session)
        print("HR data already exists. Updated demo user salaries.")
        return

    departments = [
        "Engineering",
        "Sales",
        "Marketing",
        "HR",
        "Finance",
        "Operations",
        "IT",
        "Legal",
    ]
    device_types = ["Laptop", "Monitor", "Phone", "Tablet", "Desktop"]
    device_models = {
        "Laptop": ["MacBook Pro", "ThinkPad X1", "Dell XPS 15", "Surface Laptop"],
        "Monitor": ["Dell U2720Q", "LG 27UK850", "ASUS ProArt", "BenQ PD2700U"],
        "Phone": ["iPhone 15", "Samsung Galaxy S24", "Google Pixel 8"],
        "Tablet": ["iPad Pro", "Surface Pro", "Samsung Tab S9"],
        "Desktop": ["Mac Studio", "Dell OptiPlex", "HP Z2"],
    }

    employees: list[Employee] = []
    employee_pii_list: list[EmployeePii] = []
    employee_financials_list: list[EmployeeFinancials] = []
    hardware_assets: list[HardwareAsset] = []
    director_ids: list[UUID] = []
    asset_counter = 0

    # 1. Seed deterministic demo users
    demo_users = [
        {
            "username": "mary.manager",
            "first_name": "Mary",
            "last_name": "Manager",
            "email": "mary.manager@example.com",
            "job_title": "Engineering Manager",
            "department": "Engineering",
            "is_director": True,
            "reports_to": None,
            "base_salary": DEMO_USER_SALARIES["mary.manager"],
        },
        {
            "username": "alice.employee",
            "first_name": "Alice",
            "last_name": "Employee",
            "email": "alice.employee@example.com",
            "job_title": "Software Engineer",
            "department": "Engineering",
            "is_director": False,
            "reports_to": "mary.manager",
            "base_salary": DEMO_USER_SALARIES["alice.employee"],
        },
        {
            "username": "henry.hradmin",
            "first_name": "Henry",
            "last_name": "HR Admin",
            "email": "henry.hradmin@example.com",
            "job_title": "HR Director",
            "department": "HR",
            "is_director": True,
            "reports_to": None,
            "base_salary": DEMO_USER_SALARIES["henry.hradmin"],
        },
        {
            "username": "ivan.itadmin",
            "first_name": "Ivan",
            "last_name": "IT Admin",
            "email": "ivan.itadmin@example.com",
            "job_title": "IT Director",
            "department": "IT",
            "is_director": True,
            "reports_to": None,
            "base_salary": DEMO_USER_SALARIES["ivan.itadmin"],
        },
    ]

    demo_user_ids = {}
    for user in demo_users:
        emp_id = demo_user_id(user["username"])
        demo_user_ids[user["username"]] = emp_id
        if user["is_director"]:
            director_ids.append(emp_id)

    for user in demo_users:
        emp_id = demo_user_ids[user["username"]]
        manager_id = demo_user_ids[user["reports_to"]] if user["reports_to"] else None
        hire_date = date(2020, 1, 15)
        
        employees.append(
            Employee(
                id=emp_id,
                first_name=user["first_name"],
                last_name=user["last_name"],
                work_email=user["email"],
                work_phone="555-0100",
                job_title=user["job_title"],
                department=user["department"],
                manager_id=manager_id,
                hire_date=hire_date,
                status="Active",
            )
        )

        employee_pii_list.append(
            EmployeePii(
                employee_id=emp_id,
                ssn=fake.unique.ssn().replace("-", ""),
                date_of_birth=date(1985, 5, 20),
                personal_phone="555-0101",
                home_address="123 Demo St, Demo City, CA",
                gender="Other",
            )
        )

        employee_financials_list.append(
            EmployeeFinancials(
                employee_id=emp_id,
                base_salary=user["base_salary"],
                bonus=Decimal("10000.00"),
                bank_account_number="123456789",
                routing_number="987654321",
            )
        )

        asset_counter += 1
        hardware_assets.append(
            HardwareAsset(
                asset_tag=f"ASSET-{asset_counter:06d}",
                employee_id=emp_id,
                device_type="Laptop",
                model_name="MacBook Pro",
                serial_number="DEMO123456",
                mac_address="00:11:22:33:44:55",
                issue_date=hire_date,
                status="Active",
            )
        )

    # 2. Seed random employees
    for i in range(996):
        emp_id = uuid.uuid4()
        first_name = fake.first_name()
        last_name = fake.last_name()
        # Workaround Faker unique email exhaustion by generating deterministic emails
        # Ensure name is stripped of spaces/apostrophes to create valid emails
        # Fallback to defaults if the names are entirely non-alphanumeric
        safe_first = "".join(c for c in first_name.lower() if c.isalnum()) or "employee"
        safe_last = "".join(c for c in last_name.lower() if c.isalnum()) or "unknown"
        work_email = f"{safe_first}.{safe_last}{i}@example.com"
        work_phone = fake.phone_number() if fake.boolean(chance_of_getting_true=70) else None
        job_title = fake.job()
        department = fake.random_element(departments)
        
        if i < 10:
            director_ids.append(emp_id)
            job_title = fake.random_element(["Director", "VP of Engineering", "VP of Sales", "VP of Marketing", "VP of Finance", "VP of Operations", "Chief Technology Officer", "Chief Financial Officer", "Chief People Officer", "General Counsel"])
            
        manager_id = None if i < 10 else fake.random_element(director_ids)
        hire_date = fake.date_between(start_date=date(2015, 1, 1), end_date=date(2025, 1, 1))
        status = "Active"

        employees.append(
            Employee(
                id=emp_id,
                first_name=first_name,
                last_name=last_name,
                work_email=work_email,
                work_phone=work_phone,
                job_title=job_title,
                department=department,
                manager_id=manager_id,
                hire_date=hire_date,
                status=status,
            )
        )

        ssn = fake.unique.ssn().replace("-", "")
        date_of_birth = fake.date_of_birth(minimum_age=22, maximum_age=65)
        personal_phone = fake.phone_number() if fake.boolean(chance_of_getting_true=60) else None
        home_address = fake.address()
        gender = fake.random_element(["M", "F", "Other"])

        employee_pii_list.append(
            EmployeePii(
                employee_id=emp_id,
                ssn=ssn,
                date_of_birth=date_of_birth,
                personal_phone=personal_phone,
                home_address=home_address,
                gender=gender,
            )
        )

        base_salary = Decimal(str(fake.random_int(50000, 200000)))
        bonus = Decimal(str(fake.random_int(0, 25000))) if fake.boolean(chance_of_getting_true=40) else None
        bank_account_number = fake.bban() if fake.boolean(chance_of_getting_true=90) else None
        routing_number = str(fake.random_number(digits=9, fix_len=True)) if bank_account_number else None

        employee_financials_list.append(
            EmployeeFinancials(
                employee_id=emp_id,
                base_salary=base_salary,
                bonus=bonus,
                bank_account_number=bank_account_number,
                routing_number=routing_number,
            )
        )

        num_assets = fake.random_int(1, 3)
        for _ in range(num_assets):
            asset_counter += 1
            device_type = fake.random_element(device_types)
            model_name = fake.random_element(device_models[device_type])
            serial_number = fake.bothify(text="??########", letters="ABCDEFGHJKLMNPQRSTUVWXYZ")
            mac_address = fake.mac_address()
            issue_date = fake.date_between(start_date=hire_date, end_date=date.today())
            status_asset = "Active"

            hardware_assets.append(
                HardwareAsset(
                    asset_tag=f"ASSET-{asset_counter:06d}",
                    employee_id=emp_id,
                    device_type=device_type,
                    model_name=model_name,
                    serial_number=serial_number,
                    mac_address=mac_address,
                    issue_date=issue_date,
                    status=status_asset,
                )
            )

    # Insert directors first so manager_id FKs resolve, then the rest
    session.add_all(employees[:10])
    session.flush()
    session.add_all(employees[10:])
    session.add_all(employee_pii_list)
    session.add_all(employee_financials_list)
    session.add_all(hardware_assets)


def test_connection() -> bool:
    """Test database connection. Raises on failure."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True


def wait_for_db(max_attempts: int = 30, delay_seconds: float = 2.0) -> bool:
    """Wait for database to be ready (try/except loop to ping)."""
    last_error: Exception | None = None
    for attempt in range(max_attempts):
        try:
            if test_connection():
                return True
        except Exception as e:
            last_error = e
        print(f"Waiting for database... (attempt {attempt + 1}/{max_attempts})")
        time.sleep(delay_seconds)
    if last_error is not None:
        print(f"Last connection error: {last_error}")
    return False


if __name__ == "__main__":
    if not wait_for_db():
        print("Database connection failed after max attempts.")
        exit(1)

    with SessionLocal() as session:
        # Note: We do NOT call Base.metadata.create_all(engine) because 
        # db/init.sql is strictly responsible for all DDL.
        seed_public_data(session)
        seed_hr_and_it_data(session)
        session.commit()

    print("Database seeded successfully.")
    exit(0)
