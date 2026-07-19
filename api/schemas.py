from pydantic import BaseModel, Field
from typing import Optional, List

# --------------------------------------------------- AGENT SCHEMAS ---------------------------------------------------
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

# --------------------------------------------------- API SCHEMAS ---------------------------------------------------
class ScanRequest(BaseModel):
    target: str = Field(..., description="Цель сканирования, например localhost или 192.168.1.0/24")
    extra_flags: Optional[str] = None

class AgentReport(BaseModel):
    status: str  # "success" | "partial" | "failed"
    messages: list[dict]
    final_report: Optional[str] = None
    error: Optional[str] = None
