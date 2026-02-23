from pydantic import BaseModel
from typing import List
from pydantic import Field

class LogRequest(BaseModel):
    logs: str = Field(..., min_length=1, max_length=50000)

class AnalysisResponse(BaseModel):
    issue_summary: str
    severity: str
    root_cause: str
    affected_hosts: List[str]
    firewall_policy: str
    action_required: str
    recommendations: List[str]
    next_cli_checks: List[str]
    confidence_score: int = Field(..., ge=0, le=100)
    related_log_lines: List[str]