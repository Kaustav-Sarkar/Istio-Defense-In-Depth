from typing import Dict, Any, List
from decimal import Decimal

def apply_masking(data: Dict[str, Any], visible_fields: List[str]) -> Dict[str, Any]:
    """
    Apply Cerbos masking to the data dictionary.
    Only keeps fields that are in visible_fields.
    """
    if not visible_fields:
        return {}
        
    # We map the generic visible_fields from Cerbos to our schema fields
    # Cerbos visible_fields: ["name", "title", "department", "salary_band", "ssn"]
    
    # Map Cerbos fields to our schema fields
    field_mapping = {
        "name": ["first_name", "last_name"],
        "title": ["job_title"],
        "department": ["department"],
        "ssn": ["ssn", "date_of_birth", "personal_phone", "home_address", "gender"],
        "base_salary": ["base_salary", "bonus", "bank_account_number", "routing_number"]
    }
    
    allowed_schema_fields = set(["id", "employee_id", "work_email", "work_phone", "manager_id", "hire_date", "status"]) # Always allowed basic fields
    
    for field in visible_fields:
        if field in field_mapping:
            allowed_schema_fields.update(field_mapping[field])
            
    masked_data = {}
    for key, value in data.items():
        if key in allowed_schema_fields:
            masked_data[key] = value

    if "salary_band" in visible_fields and data.get("base_salary") is not None:
        salary = Decimal(str(data["base_salary"]))
        lower = int(salary // Decimal("50000")) * 50
        upper = lower + 49
        masked_data["salary_band"] = f"{lower}k-{upper}k"

    return masked_data
