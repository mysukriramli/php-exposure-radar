from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class Directive(str, Enum):
    EMERGENCY_PATCH_CORE = "EMERGENCY_PATCH_CORE"
    ISOLATE_EOL_RUNTIME = "ISOLATE_EOL_RUNTIME"
    APPLY_WAF_VIRTUAL_PATCH = "APPLY_WAF_VIRTUAL_PATCH"
    AUDIT_COMPOSER_POLICY = "AUDIT_COMPOSER_POLICY"
    UP_TO_DATE = "UP_TO_DATE"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class VulnerabilityRecord(BaseModel):
    cve_id: str
    name: str
    cvss_score: float
    affected_versions: str
    patched_versions: str
    rce_vector: str

class PHPBranchStatus(BaseModel):
    branch: str
    latest_version: str
    is_eol: bool
    is_vulnerable_to_php2shell: bool
    is_vulnerable_to_cgi_injection: bool
    minimum_patched_version: Optional[str]
    exposure_score: float = Field(ge=0.0, le=100.0)
    directive: Directive
    recommended_action: str
    active_cves: List[str]
