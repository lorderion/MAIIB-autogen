from pydantic import BaseModel, Field
from typing import Optional, List

class NmapService(BaseModel):
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    state: str

class ScanResult(BaseModel):
    target: str
    services: List[NmapService]
    raw_output: str  = Field(exclude=True)

class CVEItem(BaseModel):
    cve_id: str
    description: str
    severity: str
    recommendation: str

class VulnReport(BaseModel):
    target: str
    scan_result: ScanResult
    vulnerabilities: List[CVEItem]
