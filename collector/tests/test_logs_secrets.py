"""SR-14: no token / webhook URL value ever reaches a log line or an HTTP response body, whatever the
request does. The capture handler sits BEFORE the production scrub filter, so a leak is visible even if
exp_common.log would have redacted it."""
from __future__ import annotations

import io
import json
import logging
import re

from colhelpers import https, ingest, rec, wait_for
from exp_common import ids
from exp_common import log as exp_log

WEBHOOK = "https://hooks.slack.com/services/T000/B000/SECRETSECRETSECRET"


def test_no_secret_reaches_logs_or_responses(env, log_capture):
    env.write_creds({"probe-a1": ids.token_hash(env.ingest_token)},
                    {"dash-main": ids.token_hash(env.dash_token)},
                    [{"id": "wh_1", "format": "slack", "url": WEBHOOK}])
    app = env.start()
    port = app.address[1]
    bad_ingest, bad_dash = ids.new_token("expi"), ids.new_token("expd")
    responses = []
    responses.append(ingest(port, env.ingest_token, [rec(), b"{bad json"]))
    responses.append(ingest(port, bad_ingest, [rec()]))
    responses.append(ingest(port, env.dash_token, [rec()]))
    responses.append(https(port, "GET", "/api/v1/health", headers={"Authorization": f"Bearer {env.ingest_token}"}))
    responses.append(https(port, "GET", "/api/v1/health", headers={"Authorization": f"Bearer {bad_dash}"}))
    responses.append(https(port, "GET", "/api/v1/health", headers={"Authorization": f"Bearer {env.dash_token}"}))
    responses.append(https(port, "GET", "/nope", headers={"Authorization": f"Bearer {env.dash_token}"}))
    responses.append(https(port, "GET", "/api/v1/probes?limit=abc", headers={"Authorization": f"Bearer {env.dash_token}"}))
    # rotation + a broken credential file exercise the reload logging
    (env.creds / "ingest_tokens.json").write_text('{"probe-a1": "' + env.ingest_token + '"')   # invalid JSON containing a token
    assert wait_for(lambda: app.creds.last_error != "", 10)
    (env.creds / "ingest_tokens.json").write_text('{"probe-a1": "' + env.dash_token + '"}')    # token instead of hash
    assert wait_for(lambda: app.creds.reload_errors >= 2, 10)
    assert wait_for(lambda: "probe-a1" in app.creds.last_error, 10)
    app.stop()
    env.apps.clear()
    text = log_capture()
    assert "authentication failed" in text                        # the failures WERE logged ...
    secrets_ = [env.ingest_token, env.ingest_token2, env.dash_token, bad_ingest, bad_dash,
                ids.token_hash(env.ingest_token), ids.token_hash(env.dash_token), WEBHOOK, "SECRETSECRETSECRET"]
    for s in secrets_:
        assert s not in text, f"secret leaked into logs: {s[:8]}..."
    assert not re.search(r"exp[aeidn]_[A-Za-z0-9_-]{8,}", text)
    assert "Bearer" not in text and "Authorization" not in text
    for r in responses:                                           # ... and nothing is echoed back
        body = r.body.decode("utf-8", "replace")
        for s in (env.ingest_token, bad_ingest, bad_dash, env.dash_token, WEBHOOK):
            if r.status == 200 and s == env.dash_token:
                continue
            assert s not in body
        assert "Traceback" not in body


def test_production_log_setup_scrubs_even_a_deliberate_leak():
    """Defence in depth: the handler installed by `run` redacts tokens that a future bug might log."""
    buf = io.StringIO()
    exp_log.setup_logging("exp-collector", "DEBUG", stream=buf)
    try:
        tok = ids.new_token("expi")
        logging.getLogger("exp_collector.test").error("oops Authorization: Bearer %s and %s", tok, WEBHOOK)
    finally:
        for h in list(logging.getLogger().handlers):
            if h.get_name() == "exp-log":
                logging.getLogger().removeHandler(h)
    out = buf.getvalue()
    assert tok not in out and "SECRETSECRET" not in out and "[REDACTED]" in out


def test_credential_errors_never_contain_values(tmp_path):
    import pytest
    from exp_common.creds import CredentialError

    from exp_collector.config import CredStore
    secret = "expi_" + "Z" * 43
    contents = ['{"probe-a1": "' + secret, json.dumps({"probe-a1": secret}), json.dumps([secret]),
                json.dumps({secret: "a" * 64})]
    for content in contents:
        d = tmp_path / "c"
        d.mkdir(exist_ok=True)
        (d / "ingest_tokens.json").write_text(content)
        (d / "dashboard_tokens.json").write_text("{}")
        (d / "webhooks.json").write_text("[]")
        with pytest.raises(CredentialError) as e:
            CredStore(d).load()
        assert secret not in str(e.value)
