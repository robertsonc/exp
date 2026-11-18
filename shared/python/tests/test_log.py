import io
import json
import logging

import pytest

from exp_common import ids
from exp_common.log import REDACTED, SecretScrubFilter, scrub, setup_logging

TOKEN = ids.new_token("expi_")


@pytest.mark.parametrize("raw,secret", [
    (f"token is {TOKEN}", TOKEN[5:]),
    ("agent expa_" + "A" * 43 + " ok", "A" * 43),
    ("enrol expe_abcdefgh12345678 x", "abcdefgh12345678"),
    ("dash expd_" + "b-_" * 14 + "b", "b-_b-_b-_"),
    ("noc expn_" + "Z" * 43, "Z" * 43),
    ("Authorization: Bearer abc.def-ghi_123", "abc.def-ghi_123"),
    ("authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("Proxy-Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ('{"Authorization": "Bearer sekret.value"}', "sekret.value"),
    ("headers {'Authorization': 'Token abcdef123456'}", "abcdef123456"),
    ("sent Bearer eyJhbGciOi.payload.sig to server", "eyJhbGciOi"),
    ("post https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX failed", "XXXXSECRETXXXX"),
    ("post https://contoso.webhook.office.com/webhookb2/aaaa-bbbb/IncomingWebhook/cccc/dddd done", "aaaa-bbbb"),
    ("https://discord.com/api/webhooks/123/SECRETTOKEN", "SECRETTOKEN"),
    ("GET https://api.example.com/v1/x?apiKey=SEKRET123&a=1", "SEKRET123"),
    ("GET https://x/y?a=1&token=SEKRET123", "SEKRET123"),
    ("GET https://x/y?key=SEKRET123#f", "SEKRET123"),
    ("GET https://x/y?access_token=SEKRET123", "SEKRET123"),
    ("connect password=hunter2 user=bob", "hunter2"),
    ('password: "hunter 2 with spaces"', "hunter 2 with spaces"),
    ("passwd='hunter2'", "hunter2"),
    ("secret=abcd1234 more", "abcd1234"),
    ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\nkqhkiG9w0BAQ\n-----END PRIVATE KEY-----", "MIIEvQIBADANBg"),
    ("k: -----BEGIN EC PRIVATE KEY-----\nAAAA1234\n-----END EC PRIVATE KEY----- tail", "AAAA1234"),
    ("-----BEGIN RSA PRIVATE KEY-----\nTRUNCATEDSECRET", "TRUNCATEDSECRET"),
])
def test_scrub_redacts(raw, secret):
    out = scrub(raw)
    assert secret not in out, out
    assert REDACTED in out or "PRIVATE KEY" in out


def test_scrub_keeps_harmless_text():
    for s in ("probe probe-a1 shipped 12 measurements", "tokens are great", "GET https://x/y?a=1&b=2",
              "expected value", "keyboard=us"):
        assert scrub(s) == s
    assert scrub("probe expi_ prefix only") == "probe expi_ prefix only"


def test_scrub_idempotent():
    s = scrub(f"a {TOKEN} password=x Bearer abc")
    assert scrub(s) == s


@pytest.fixture()
def capture():
    buf = io.StringIO()
    log = setup_logging("exp-test", "DEBUG", stream=buf)
    yield log, buf
    for h in list(logging.getLogger().handlers):
        if h.get_name() == "exp-log":
            logging.getLogger().removeHandler(h)


def test_filter_scrubs_msg_args_and_child_loggers(capture):
    log, buf = capture
    child = logging.getLogger("exp-test.child")
    child.info("got %s and %s", TOKEN, "Bearer abc123")
    child.info("dict %(t)s", {"t": TOKEN})
    child.warning("url https://hooks.slack.com/services/T/B/SECRETPATH")
    child.info("obj %s", ValueError("password=hunter2"))
    out = buf.getvalue()
    for s in (TOKEN, "abc123", "SECRETPATH", "hunter2"):
        assert s not in out, out
    assert out.count(REDACTED) >= 4


def test_traceback_and_stack_info_scrubbed(capture):
    log, buf = capture
    try:
        raise RuntimeError(f"failed with token={TOKEN} password=hunter2")
    except RuntimeError:
        log.exception("boom")
    log.error("stack", stack_info=True)
    out = buf.getvalue()
    assert "Traceback" in out and TOKEN not in out and "hunter2" not in out


def test_bad_format_args_do_not_crash_or_leak(capture):
    log, buf = capture
    log.info("%d needs int", "password=hunter2")
    assert "hunter2" not in buf.getvalue()


def test_text_format_has_timestamp_without_journald(monkeypatch):
    monkeypatch.delenv("JOURNAL_STREAM", raising=False)
    buf = io.StringIO()
    setup_logging("c", "INFO", stream=buf).info("hello")
    assert buf.getvalue().startswith("20") and "INFO" in buf.getvalue() and "hello" in buf.getvalue()


def test_journald_format_has_no_timestamp_and_priority_prefix(monkeypatch):
    monkeypatch.setenv("JOURNAL_STREAM", "8:12345")
    buf = io.StringIO()
    log = setup_logging("c", "INFO", stream=buf)
    log.info("hello")
    log.error("bad\nsecond line")
    lines = buf.getvalue().splitlines()
    assert lines[0] == "<6>INFO c: hello"
    assert lines[1].startswith("<3>ERROR") and lines[2].startswith("<3>second line")


def test_json_mode(monkeypatch):
    monkeypatch.delenv("JOURNAL_STREAM", raising=False)
    buf = io.StringIO()
    setup_logging("exp-x", "INFO", json=True, stream=buf).warning("token %s", TOKEN)
    rec = json.loads(buf.getvalue())
    assert rec["level"] == "warning" and rec["component"] == "exp-x" and "ts" in rec
    assert TOKEN not in buf.getvalue() and REDACTED in rec["msg"]
    monkeypatch.setenv("JOURNAL_STREAM", "1:1")
    buf2 = io.StringIO()
    setup_logging("exp-x", "INFO", json=True, stream=buf2).info("x")
    assert "ts" not in json.loads(buf2.getvalue())


def test_setup_is_idempotent_and_level_validated(monkeypatch):
    setup_logging("a", "INFO", stream=io.StringIO())
    setup_logging("a", "DEBUG", stream=io.StringIO())
    assert sum(1 for h in logging.getLogger().handlers if h.get_name() == "exp-log") == 1
    with pytest.raises(ValueError):
        setup_logging("a", "LOUD")


def test_logs_go_to_stderr_not_stdout(capsys):
    setup_logging("a", "INFO").info("diag")
    cap = capsys.readouterr()
    assert cap.out == "" and "diag" in cap.err


def test_filter_never_drops():
    rec = logging.LogRecord("n", logging.INFO, __file__, 1, "x %s", ("y",), None)
    assert SecretScrubFilter().filter(rec) is True
