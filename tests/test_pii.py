import pytest

from gateway.guardrails.pii import detect, luhn_valid, redact


@pytest.mark.parametrize("num,ok", [("4111111111111111", True), ("4111 1111 1111 1111", True),
                                    ("4111111111111112", False), ("1234", False)])
def test_luhn(num, ok):
    assert luhn_valid(num) is ok


def kinds(t):
    return {f.kind for f in detect(t)}


def test_email_phone_ssn():
    t = "Mail jane.doe@example.com or call (940) 555-1234, SSN 123-45-6789"
    assert kinds(t) == {"EMAIL", "PHONE", "SSN"}
    r = redact(t)
    assert "jane.doe" not in r and "[REDACTED_SSN]" in r and "[REDACTED_PHONE]" in r


def test_invalid_ssn_and_non_luhn_card_ignored():
    assert "SSN" not in kinds("id 000-12-3456")
    assert "CREDIT_CARD" not in kinds("order 4111111111111112")


def test_credit_card():
    assert "CREDIT_CARD" in kinds("card 4111-1111-1111-1111 exp 12/29")


def test_secrets():
    assert detect("key AKIAIOSFODNN7EXAMPLE")[0].category == "secret"
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert kinds(pem) == {"PRIVATE_KEY"}
    assert "AWS_SECRET_KEY" in kinds("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


def test_clean_text():
    assert detect("The meeting is at 3pm in room 204.") == []
