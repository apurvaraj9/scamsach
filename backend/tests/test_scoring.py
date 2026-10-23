from app.agent.scoring import RuleScore, combine_verdicts, score_findings
from app.tools.findings import Finding


def f(weight, signal="warning", hard=False, scam_type=None):
    return Finding("t", "x", signal, "title", "शीर्षक", weight=weight, hard=hard, scam_type=scam_type)


def test_thresholds():
    assert score_findings([f(10)]).verdict == "likely_safe"
    assert score_findings([f(30)]).verdict == "suspicious"
    assert score_findings([f(30), f(30)]).verdict == "scam"


def test_hard_evidence_forces_scam():
    r = score_findings([f(5, "danger", hard=True, scam_type="phishing")])
    assert r.verdict == "scam" and r.score >= 85 and r.hard_reasons


def test_skipped_and_errors_do_not_count():
    assert score_findings([f(90, "skipped"), f(90, "error")]).score == 0


def test_specific_scam_type_preferred_over_phishing():
    r = score_findings([f(60, "danger", True, "phishing"), f(30, "danger", False, "kyc")])
    assert r.scam_type == "kyc"


def test_llm_cannot_overrule_hard_evidence():
    rule = RuleScore(90, "scam", ["Listed by Safe Browsing"], "phishing")
    assert combine_verdicts(rule, "likely_safe", 0.99)[0] == "scam"


def test_llm_raise_is_capped_when_not_confident():
    rule = RuleScore(5, "likely_safe", [], "none")
    assert combine_verdicts(rule, "scam", 0.6)[0] == "suspicious"
    assert combine_verdicts(rule, "scam", 0.9)[0] == "scam"


def test_llm_can_lower_one_step_only_when_confident_and_score_not_high():
    rule = RuleScore(40, "suspicious", [], "other")
    assert combine_verdicts(rule, "likely_safe", 0.9)[0] == "likely_safe"
    assert combine_verdicts(rule, "likely_safe", 0.6)[0] == "suspicious"
    high = RuleScore(75, "scam", [], "kyc")
    assert combine_verdicts(high, "likely_safe", 0.95)[0] == "scam"


def test_no_llm_uses_rules():
    rule = RuleScore(40, "suspicious", [], "other")
    assert combine_verdicts(rule, None, None)[0] == "suspicious"
