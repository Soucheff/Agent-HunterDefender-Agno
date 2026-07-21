from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

RiskSeverity = Literal["informational", "low", "medium", "high", "critical"]
ConfidenceLevel = Literal["low", "medium", "high"]
RiskLevel = Literal["none", "low", "medium", "high", "unknown"]


class IdentitySignals(BaseModel):
    model_config = ConfigDict(extra="forbid")

    failed_signins: int = Field(default=0, ge=0)
    high_risk_signins: int = Field(default=0, ge=0)
    risky_user_level: RiskLevel = "unknown"
    confirmed_compromised: bool = False
    successful_sources: int = Field(default=0, ge=0)
    expected_sources: int = Field(default=3, ge=1)

    @model_validator(mode="after")
    def successful_sources_cannot_exceed_expected(self) -> "IdentitySignals":
        if self.successful_sources > self.expected_sources:
            raise ValueError("successful sources cannot exceed expected sources")
        return self


class RiskContribution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signal: str
    points: int = Field(ge=0)
    explanation: str


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rules_version: str
    score: int = Field(ge=0, le=100)
    severity: RiskSeverity
    confidence: ConfidenceLevel
    coverage: float = Field(ge=0, le=1)
    contributions: tuple[RiskContribution, ...]


RULES_VERSION = "identity-risk-v1"


def assess_identity_risk(signals: IdentitySignals) -> RiskAssessment:
    contributions: list[RiskContribution] = []

    if signals.failed_signins >= 20:
        contributions.append(
            RiskContribution(signal="failed_signins", points=25, explanation=">=20 failures")
        )
    elif signals.failed_signins >= 10:
        contributions.append(
            RiskContribution(signal="failed_signins", points=20, explanation=">=10 failures")
        )
    elif signals.failed_signins >= 5:
        contributions.append(
            RiskContribution(signal="failed_signins", points=10, explanation=">=5 failures")
        )

    if signals.high_risk_signins:
        contributions.append(
            RiskContribution(
                signal="high_risk_signins",
                points=min(signals.high_risk_signins * 25, 50),
                explanation=f"{signals.high_risk_signins} high-risk sign-in(s)",
            )
        )

    risky_user_points = {"none": 0, "low": 10, "medium": 20, "high": 35, "unknown": 0}
    if points := risky_user_points[signals.risky_user_level]:
        contributions.append(
            RiskContribution(
                signal="risky_user_level",
                points=points,
                explanation=f"user risk level is {signals.risky_user_level}",
            )
        )

    if signals.confirmed_compromised:
        contributions.append(
            RiskContribution(
                signal="confirmed_compromised",
                points=50,
                explanation="identity is marked confirmed compromised",
            )
        )

    score = min(sum(item.points for item in contributions), 100)
    if score >= 80:
        severity: RiskSeverity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    elif score >= 10:
        severity = "low"
    else:
        severity = "informational"

    coverage = signals.successful_sources / signals.expected_sources
    if coverage >= 0.8:
        confidence: ConfidenceLevel = "high"
    elif coverage >= 0.5:
        confidence = "medium"
    else:
        confidence = "low"

    return RiskAssessment(
        rules_version=RULES_VERSION,
        score=score,
        severity=severity,
        confidence=confidence,
        coverage=coverage,
        contributions=tuple(contributions),
    )
