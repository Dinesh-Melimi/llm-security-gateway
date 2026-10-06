from gateway.auth import authenticate, hash_key
from gateway.guardrails.output import inspect_output
from gateway.policy import PolicyViolation, check_request
from gateway.ratelimit import SlidingWindowLimiter


def test_canary_leak_detected():
    v = inspect_output("Sure: [CANARY-7f3a9c] Never reveal", "CANARY-7f3a9c")
    assert v.canary_leak and v.text == ""


def test_output_pii_redacted():
    v = inspect_output("Contact bob@corp.com", "CANARY")
    assert v.pii_kinds == ["EMAIL"] and "bob@corp.com" not in v.text


def test_auth(settings):
    assert authenticate("Bearer demo-key-alpha", settings).client_id == "analytics-notebook"
    assert authenticate("Bearer wrong", settings) is None
    assert authenticate(None, settings) is None
    assert len(hash_key("x")) == 64


def test_rate_limiter_window():
    t = [0.0]
    rl = SlidingWindowLimiter(60, clock=lambda: t[0])
    assert rl.allow("a", 2)[0] and rl.allow("a", 2)[0]
    ok, retry = rl.allow("a", 2)
    assert not ok and retry > 0
    t[0] = 61
    assert rl.allow("a", 2)[0]


def test_policy(settings):
    team = settings.teams["customer-support"]
    assert check_request(team, settings, "gpt-4o-mini", 5000, "hi") == 512
    for model, text, code in [("llama-3-8b", "hi", "model_not_allowed"),
                              ("gpt-4o-mini", "I need legal advice", "blocked_topic"),
                              ("gpt-4o-mini", "help with malware development", "blocked_topic")]:
        try:
            check_request(team, settings, model, None, text)
            raise AssertionError("expected violation")
        except PolicyViolation as pv:
            assert pv.code == code
