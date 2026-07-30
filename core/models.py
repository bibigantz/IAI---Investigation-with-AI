from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ForensicAnomaly(BaseModel):
    filepath: str = Field(description="The full path of the suspicious artifact")
    anomaly_type: str = Field(description="E.g., 'Double Extension', 'Unsigned Binary', 'Suspicious Path'")
    severity: str = Field(description="High, Medium, or Low")
    justification: str = Field(description="Why this was flagged based on the parsed data")
    recommended_action: str = Field(description="What the HITL analyst should investigate next")


class AgentAnalysisReport(BaseModel):
    agent_name: str
    status: str = Field(description="Clean, Suspicious, or Critical")
    anomalies_found: List[ForensicAnomaly] = []
    summary: str = Field(description="A brief overview of the findings")


class AgentResponse(BaseModel):
    agent_name: str
    raw_data_parsed: Any
    ai_analysis: Dict
    status: str = "PENDING_APPROVAL"


class HumanFeedback(BaseModel):
    action: str
    feedback: Optional[str] = None
