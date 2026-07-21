from hunter_defender_agent.domain.risk import IdentitySignals, assess_identity_risk


def test_high_risk_signin_and_failures_produce_high_severity() -> None:
    assessment = assess_identity_risk(
        IdentitySignals(
            failed_signins=12,
            high_risk_signins=1,
            risky_user_level="medium",
            successful_sources=3,
        )
    )

    assert assessment.score == 65
    assert assessment.severity == "high"
    assert assessment.confidence == "high"


def test_missing_sources_reduce_confidence_not_score() -> None:
    complete = assess_identity_risk(
        IdentitySignals(high_risk_signins=1, successful_sources=3)
    )
    incomplete = assess_identity_risk(
        IdentitySignals(high_risk_signins=1, successful_sources=1)
    )

    assert complete.score == incomplete.score == 25
    assert complete.confidence == "high"
    assert incomplete.confidence == "low"


def test_score_is_capped_at_one_hundred() -> None:
    assessment = assess_identity_risk(
        IdentitySignals(
            failed_signins=50,
            high_risk_signins=4,
            risky_user_level="high",
            confirmed_compromised=True,
            successful_sources=3,
        )
    )

    assert assessment.score == 100
    assert assessment.severity == "critical"
