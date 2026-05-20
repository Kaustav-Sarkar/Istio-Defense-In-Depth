from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class ProfileResponse(BaseModel):
    employee: Dict[str, Any]
    assets: Optional[List[Dict[str, Any]]] = None
    assets_error: Optional[str] = None
    pii_error: Optional[str] = None
    fin_error: Optional[str] = None
