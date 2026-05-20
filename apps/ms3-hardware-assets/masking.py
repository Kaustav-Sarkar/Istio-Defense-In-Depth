from typing import Dict, Any

def apply_masking(data: Dict[str, Any], serial_mode: str) -> Dict[str, Any]:
    """
    Apply Cerbos masking to the hardware asset.
    serial_mode can be 'full' or 'truncated'.
    """
    masked_data = data.copy()
    masked_data.pop("_sa_instance_state", None)
    
    if serial_mode == "truncated":
        if masked_data.get("serial_number"):
            masked_data["serial_number"] = masked_data["serial_number"][-4:] if len(masked_data["serial_number"]) > 4 else "****"
        if masked_data.get("mac_address"):
            masked_data["mac_address"] = "XX:XX:XX:XX:" + masked_data["mac_address"][-5:] if len(masked_data["mac_address"]) > 5 else "XX:XX:XX:XX:XX:XX"
            
    return masked_data
