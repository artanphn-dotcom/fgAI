from pydantic import BaseModel
from typing import List

class LogRequest(BaseModel):
    logs: str

class AnalysisResponse(BaseModel):
    issue_summary: str
    severity: str
    root_cause: str
    affected_hosts: List[str]
    firewall_policy: str
    action_required: str
    recommendations: List[str]
    next_cli_checks: List[str]
    confidence_score: int
    related_log_lines: List[str]