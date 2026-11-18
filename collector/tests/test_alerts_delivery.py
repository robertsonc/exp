"""Alert payloads and webhook delivery: escaping (SR-13, acceptance 6), SSRF guard and no redirects (SR-15),
retries with backoff, and secrets (the URL) never in logs (SR-14)."""
from __future__ import annotations

import json
import logging
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import synth
from exp_common import tlspin

from exp_collector.alerts import (
    HttpsTransport,
    WebhookRefused,
    WebhookSender,
    build_message,
    check_destination,
    payload,
    slack_escape,
    teams_escape,
)
from exp_collector.engine import state_doc
from exp_collector.rules import evaluate_records

T = 1_800_000_000_000
SECRET_PATH = "/services/T0SECRET/B0SECRET/XYZSECRETTOKEN123"
EVIL = ("<http://evil.example|click here to fix> & <!channel> <!here> <@U123> [fix](http://evil.example) "
        "@everyone www.evil.example javascript://x ![i](https://e.example/a.png) <at>Admin</at>")


def msg(**kw):
    inc = {"start": T, "end": T + 120_000, "flaps": 2,
           "facts": {"sev": "fail", "what": EVIL, "since_open": False, "where": {"seg": "ssid", "tg": EVIL, "sd": EVIL},
                     "also": ["dns", "wifi"]}}
    base = dict(probe="probe-a1", label=EVIL, tz="America/Chicago", voice="sysadmin", edge_label=EVIL,
                board_url="https://10.32.98.30")
    base.update(kw)
    kind = base.pop("kind", "down")
    key = base.pop("key", "wifi")
    return build_message(kind, key, inc, T + 200_000, **base)


# -------------------------------------------------------------------------------------------- escaping
@pytest.mark.parametrize("kind", ["down", "again", "flapping", "resolved"])
@pytest.mark.parametrize("voice", ["plain", "sysadmin"])
def test_slack_text_cannot_make_links_or_mentions(kind, voice):
    m = msg(kind=kind, voice=voice)
    text = payload("slack", m)["text"]
    assert text.count("<") == 1 and text.count(">") == 1            # only the board link
    assert "<http://evil" not in text and "<!channel>" not in text and "<!here>" not in text and "<@U123>" not in text
    assert "http://evil.example" not in text and "javascript://" not in text
    assert "@everyone" not in text
    assert text.endswith("|Open the board at the start>") or text.endswith("|Rewind to the start>")
    link = text[text.rindex("<") + 1:text.rindex("|")]
    assert link.startswith("https://10.32.98.30/probe/probe-a1?at=2027-01-15T08:00:00Z")


def test_at_mentions_are_defanged_wherever_they_appear():
    m = msg(label="@everyone @here", kind="down")
    for fmt in ("slack", "teams", "json"):
        blob = json.dumps(payload(fmt, m), ensure_ascii=False)
        assert "@everyone" not in blob and "@here" not in blob and "@\u200beveryone" in blob


def test_teams_text_cannot_make_links_or_mentions():
    for kind in ("down", "resolved"):
        body = payload("teams", msg(kind=kind))
        card = body["attachments"][0]["content"]
        blob = " ".join(b["text"] for b in card["body"])
        assert "](" not in blob and "[" not in blob and "<" not in blob and ">" not in blob
        assert "http://evil.example" not in blob and "<at>" not in blob and "@everyone" not in blob.replace("@​", "")
        assert card["actions"][0]["url"].startswith("https://10.32.98.30/probe/probe-a1?at=")


def test_json_format_neutralises_text_but_keeps_structure():
    out = payload("json", msg())
    blob = json.dumps(out)
    assert "<http://evil" not in blob and "<!channel>" not in blob and "<@U123>" not in blob
    assert "http://evil.example" not in blob
    assert out["kind"] == "down" and out["line"] == "wifi" and out["start"] == T and out["link"].startswith("https://")
    assert isinstance(out["lines"], list) and out["text"]


def test_escape_helpers_directly():
    assert slack_escape("<@U1> & <!channel>") == "&lt;@​U1&gt; &amp; &lt;!channel&gt;"
    assert "<" not in teams_escape("<b>x</b>") and "[" not in teams_escape("[a](http://x)")
    assert "http://" not in slack_escape("see http://x.example") and "https://" not in slack_escape("HTTPS://x.example")
    assert "ftp:​//" in slack_escape("ftp://h")


def test_probe_supplied_error_text_flows_through_the_whole_pipeline_escaped():
    """A failing probe record whose error text is hostile: State is data, the alert is escaped."""
    recs = synth.healthy(T, T + 120_000, ports=2)
    for t in range(T + 120_000, T + 160_000, 10_000):
        for d in synth.gateway(t, ports=2, bad=2):
            d["error"] = EVIL[:500]
            recs.append(d)
    ev = evaluate_records(recs, T + 160_000, probe="probe-a1", site="hall-b")
    from exp_collector.verdict import what_of
    inc = {"start": T + 120_000, "facts": {"sev": "fail", "what": what_of(ev, "network"), "where": ev.where, "also": []}}
    m = build_message("down", "network", inc, T + 160_000, probe="probe-a1", board_url="https://10.32.98.30")
    text = payload("slack", m)["text"]
    assert text.count("<") == 1 and "<!channel>" not in text and "http://evil.example" not in text
    doc = state_doc(ev, voice="sysadmin", tz="UTC")
    assert doc["failing"][0]["items"]                   # State carries the text as DATA (UIs use textContent)


def test_link_is_probe_slug_and_iso_start():
    m = msg(probe="probe-a1")
    assert m["link"] == "https://10.32.98.30/probe/probe-a1?at=2027-01-15T08:00:00Z"
    assert msg(board_url=None)["link"] is None
    assert "|" not in payload("slack", msg(board_url="https://x.example/a b|c"))["text"].split("<")[-1].split("|")[0]


# ------------------------------------------------------------------------------------------- SR-15
PUB = lambda host, port: ["93.184.216.34"]  # noqa: E731


@pytest.mark.parametrize("url", [
    "http://hooks.example/x", "ftp://hooks.example/x", "https://user:pw@hooks.example/x", "https:///x", "//hooks.example",
    "https://hooks.example:99999/x", "javascript:alert(1)", "file:///etc/passwd", "hooks.example/x", "",
])
def test_non_https_or_malformed_urls_are_refused(url):
    with pytest.raises(WebhookRefused):
        check_destination(url, (), PUB)


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.1.2.3", "::1", "10.0.0.5", "172.16.9.9", "192.168.1.1", "169.254.169.254", "fe80::1", "0.0.0.0",
    "100.64.0.1", "::ffff:127.0.0.1", "::ffff:10.1.1.1", "224.0.0.1", "fc00::1", "192.0.2.1",
])
def test_private_loopback_linklocal_destinations_are_refused(addr):
    with pytest.raises(WebhookRefused):
        check_destination("https://hooks.example/x", (), lambda h, p: [addr])
    with pytest.raises(WebhookRefused):                 # literal addresses in the URL too
        host = f"[{addr}]" if ":" in addr else addr
        check_destination(f"https://{host}/x", (), default_literal)


def default_literal(host, port):
    return [host.strip("[]")]


def test_one_private_answer_among_public_ones_refuses_dns_rebinding_style():
    with pytest.raises(WebhookRefused):
        check_destination("https://hooks.example/x", (), lambda h, p: ["93.184.216.34", "10.0.0.1"])


def test_public_destination_passes_and_the_checked_address_is_the_one_to_connect_to():
    host, port, path, ip = check_destination("https://hooks.example:8443/a/b?c=d", (), lambda h, p: ["93.184.216.34"])
    assert (host, port, path, ip) == ("hooks.example", 8443, "/a/b?c=d", "93.184.216.34")
    assert check_destination("https://hooks.example", (), PUB)[2] == "/"


def test_allowlist_by_address_cidr_or_hostname():
    private = lambda h, p: ["10.9.8.7"]  # noqa: E731
    with pytest.raises(WebhookRefused):
        check_destination("https://chat.corp/x", ("10.9.9.0/24", "other.corp"), private)
    assert check_destination("https://chat.corp/x", ("10.9.8.7",), private)[3] == "10.9.8.7"
    assert check_destination("https://chat.corp/x", ("10.9.8.0/24",), private)[3] == "10.9.8.7"
    assert check_destination("https://chat.corp/x", ("CHAT.corp",), private)[3] == "10.9.8.7"
    # an allowlisted IPv4 range does not allow an IPv6 loopback
    with pytest.raises(WebhookRefused):
        check_destination("https://chat.corp/x", ("127.0.0.0/8",), lambda h, p: ["::1"])


def test_unresolvable_host_is_refused():
    def boom(h, p):
        raise WebhookRefused("the host name does not resolve")
    with pytest.raises(WebhookRefused):
        check_destination("https://nope.invalid/x", (), boom)
    with pytest.raises(WebhookRefused):
        check_destination("https://nope.invalid/x", (), lambda h, p: [])


# ----------------------------------------------------------------------------------------- real HTTPS
class Hook:
    """A local HTTPS webhook receiver with scripted behaviour."""

    def __init__(self, tmp: Path, script=None):
        cert, key = tlspin.generate_self_signed_cert(tmp / "hook")
        self.cert = cert
        self.script = list(script or [])
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                with outer.lock:
                    outer.requests.append({"path": self.path, "body": body, "ct": self.headers.get("Content-Type")})
                    step = outer.script.pop(0) if outer.script else 200
                if step == "hang":
                    time.sleep(3)
                    step = 200
                if isinstance(step, tuple):                       # ("redirect", location)
                    self.send_response(302)
                    self.send_header("Location", step[1])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(step)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))

        class S(ThreadingHTTPServer):
            daemon_threads = True

        self.httpd = S(("127.0.0.1", 0), H)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}{SECRET_PATH}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def client_ctx(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.cert))

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def hook(tmp_path):
    made: list[Hook] = []

    def make(script=None) -> Hook:
        h = Hook(tmp_path / f"h{len(made)}", script)
        made.append(h)
        return h
    yield make
    for h in made:
        h.stop()


def sender_for(h: Hook, fmt="slack", allow=("127.0.0.1",), backoff=(0, 0, 0), timeout=5.0, **kw):
    tr = HttpsTransport(allow=allow, ssl_context=h.client_ctx(), timeout=timeout)
    return WebhookSender(lambda: [{"id": "wh_1", "format": fmt, "url": h.url}], tr, backoff_s=backoff, **kw)


def test_delivery_posts_the_escaped_payload_as_json(hook):
    h = hook()
    s = sender_for(h)
    s.start()
    try:
        s.post(msg())
        assert s.drain()
    finally:
        s.stop()
    assert s.sent == 1 and len(h.requests) == 1
    r = h.requests[0]
    assert r["path"] == SECRET_PATH and r["ct"] == "application/json"
    body = json.loads(r["body"])
    assert body["text"].count("<") == 1 and "<!channel>" not in body["text"]


def test_each_format_is_delivered_to_each_webhook(hook):
    h = hook()
    hooks = [{"id": f"w{i}", "format": f, "url": h.url} for i, f in enumerate(("slack", "teams", "json"))]
    s = WebhookSender(lambda: hooks, HttpsTransport(allow=("127.0.0.1",), ssl_context=h.client_ctx()), backoff_s=(0,))
    s.start()
    try:
        s.post(msg(kind="resolved"))
        assert s.drain()
    finally:
        s.stop()
    bodies = [json.loads(r["body"]) for r in h.requests]
    assert len(bodies) == 3
    assert any("text" in b and "attachments" not in b and "kind" not in b for b in bodies)      # slack
    assert any("attachments" in b for b in bodies) and any(b.get("kind") == "resolved" for b in bodies)


def test_a_loopback_webhook_is_refused_unless_allowlisted(hook, caplog):
    h = hook()
    s = sender_for(h, allow=())
    caplog.set_level(logging.DEBUG)
    s.start()
    try:
        s.post(msg())
        assert s.drain()
    finally:
        s.stop()
    assert h.requests == [] and s.sent == 0 and s.failed == 1       # never even connected
    assert "private, loopback or link-local" in caplog.text
    assert SECRET_PATH not in caplog.text and "XYZSECRETTOKEN123" not in caplog.text


def test_redirects_are_never_followed(hook, caplog):
    target = hook()
    h = hook([("redirect", target.url)])
    s = sender_for(h)
    caplog.set_level(logging.DEBUG)
    s.start()
    try:
        s.post(msg())
        assert s.drain()
    finally:
        s.stop()
    assert len(h.requests) == 1 and target.requests == [] and s.sent == 0 and s.failed == 1
    assert "redirect" in caplog.text and "XYZSECRETTOKEN123" not in caplog.text


def test_three_retries_with_backoff_then_give_up_and_never_log_the_url(hook, caplog):
    h = hook([500, 500, 500, 500, 500])
    s = sender_for(h, backoff=(0.01, 0.02, 0.03))
    caplog.set_level(logging.DEBUG)
    t0 = time.monotonic()
    s.start()
    try:
        s.post(msg())
        assert s.drain()
    finally:
        s.stop()
    assert len(h.requests) == 4 and s.sent == 0 and s.failed == 1       # 1 try + 3 retries
    assert time.monotonic() - t0 >= 0.06                                # the backoff happened
    assert caplog.text.count("delivery to wh_1 failed (http 500)") == 4
    for secret in (SECRET_PATH, "XYZSECRETTOKEN123", "127.0.0.1:" + str(h.port), h.url):
        assert secret not in caplog.text


def test_a_retry_that_succeeds_stops_retrying(hook):
    h = hook([503, 200])
    s = sender_for(h)
    s.start()
    try:
        s.post(msg())
        assert s.drain()
    finally:
        s.stop()
    assert len(h.requests) == 2 and s.sent == 1 and s.failed == 0


def test_connection_failure_is_logged_without_the_url_or_exception_text(hook, caplog):
    h = hook()
    port = h.port
    h.stop()                                                            # nothing listens any more
    s = WebhookSender(lambda: [{"id": "wh_1", "format": "slack", "url": f"https://127.0.0.1:{port}{SECRET_PATH}"}],
                      HttpsTransport(allow=("127.0.0.1",), ssl_context=h.client_ctx(), timeout=1), backoff_s=(0, 0))
    caplog.set_level(logging.DEBUG)
    s.start()
    try:
        s.post(msg())
        assert s.drain()
    finally:
        s.stop()
    assert s.failed == 1 and "ConnectionRefusedError" in caplog.text
    assert "XYZSECRETTOKEN123" not in caplog.text and str(port) not in caplog.text.replace("ConnectionRefusedError", "")


def test_a_hanging_endpoint_times_out_instead_of_hanging_the_sender(hook):
    h = hook(["hang", "hang"])
    s = sender_for(h, timeout=0.3, backoff=(0,))
    s.start()
    t0 = time.monotonic()
    try:
        s.post(msg())
        assert s.drain(10)
    finally:
        s.stop()
    assert time.monotonic() - t0 < 5 and s.failed == 1


def test_webhook_list_is_read_at_send_time_so_rotation_needs_no_restart(hook):
    h = hook()
    current = [[]]
    s = WebhookSender(lambda: current[0], HttpsTransport(allow=("127.0.0.1",), ssl_context=h.client_ctx()), backoff_s=(0,))
    s.start()
    try:
        s.post(msg())
        assert s.drain() and h.requests == []                          # no webhooks configured: nothing happens
        current[0] = [{"id": "w", "format": "json", "url": h.url}]
        s.post(msg())
        assert s.drain()
    finally:
        s.stop()
    assert len(h.requests) == 1


def test_full_queue_drops_instead_of_blocking():
    s = WebhookSender(lambda: [], queue_size=2)                         # worker not started
    for _ in range(5):
        s.post(msg())
    assert s.dropped == 3


def test_webhook_allow_comes_from_the_validated_config(hook, tmp_path):
    """alerts.webhook_allow in the schema-validated config permits a private (loopback) destination;
    without the entry the same destination is refused (CR-wp2-webhook-allowlist)."""
    import copy

    from colhelpers import Env
    from exp_common import config as exp_config

    from exp_collector.app import CollectorApp
    from exp_collector.config import CredStore, load_config

    h = hook()
    e = Env(tmp_path / "e", "http://127.0.0.1:1")
    e.write_creds({}, {}, [{"id": "wh_1", "format": "json", "url": h.url}])
    outcomes = {}
    for name, allow in (("allowed", ["127.0.0.1", "Chat.Corp"]), ("refused", ["10.0.0.0/8", "other.example"])):
        doc = copy.deepcopy(e.cfg_doc)
        doc.setdefault("alerts", {})["webhook_allow"] = allow
        cfg_path = tmp_path / f"{name}.json"
        cfg_path.write_text(json.dumps(doc))
        cfg = load_config(cfg_path)                               # schema-validated
        assert list(cfg.alerts["webhook_allow"]) == allow
        a = CollectorApp(cfg, e.paths(), creds=CredStore(e.creds, poll_s=1), vm_url=e.vm_url,
                         listen=("127.0.0.1", 0))
        try:
            a.creds.load()
            a.webhooks.transport.ssl_context = h.client_ctx()
            a.webhooks.backoff_s = (0,)
            a.webhooks.start()
            a.webhooks.post(msg())
            assert a.webhooks.drain()
            outcomes[name] = (a.webhooks.sent, a.webhooks.failed, len(h.requests))
        finally:
            a.webhooks.stop()
            a.store.close()
    assert outcomes["allowed"] == (1, 0, 1)
    assert outcomes["refused"][:2] == (0, 1) and outcomes["refused"][2] == 1     # no new request arrived

    bad = copy.deepcopy(e.cfg_doc)
    bad.setdefault("alerts", {})["webhook_allow"] = ["not a host!"]
    with pytest.raises(exp_config.ConfigError):
        exp_config.validate(bad, "exp.collector.config/1")
