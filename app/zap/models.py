from typing import Optional, Any
from pydantic import BaseModel, Field

class ZAPAlert(BaseModel):
    pluginId: str
    alertRef: str
    alert: str
    name: str
    riskcode: str
    confidence: str
    risk: str
    description: str
    instances: str = "1"
    solution: str = ""
    otherinfo: str = ""
    reference: str = ""
    cweid: str = ""
    wascid: str = ""
    sourceid: str = ""
    url: str = ""
    method: str = ""
    param: str = ""
    evidence: str = ""
