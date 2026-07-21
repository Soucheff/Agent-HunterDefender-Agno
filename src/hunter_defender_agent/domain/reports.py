from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from hunter_defender_agent.domain.risk import RiskAssessment


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_tool: str
    summary: str
    observed_at: datetime | None = None
    reference: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["fact", "hypothesis"]
    statement: str
    evidence_references: tuple[str, ...] = ()


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: Literal["low", "medium", "high", "urgent"]
    title: str
    rationale: str
    requires_human_approval: bool = True


class IdentityInvestigationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    subject_upn: str
    window_start: datetime
    window_end: datetime
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assessment: RiskAssessment
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]
    recommendations: tuple[Recommendation, ...]
    limitations: tuple[str, ...] = ()
    correlation_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def window_must_be_ordered(self) -> "IdentityInvestigationReport":
        if self.window_end <= self.window_start:
            raise ValueError("window end must be after window start")
        return self
