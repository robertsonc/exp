"""Manager client: auth, ETag/304, errors, backoff, TLS verification, HTTPS_PROXY, only-the-manager rule."""

from __future__ import annotations

import socket
import ssl
import threading

import pytest
from agent_helpers import Env
from exp_common import ids as exp_ids

from exp_agent.client import Backoff, ManagerClient, jittered
from exp_agent.errors import ClientError, ManagerUnreachable, Refused, Unauthorized


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.standard_release(comps=("collector",))
    e.push(e.desired([e.comp("collector")]))
    yield e
    e.close()


def test_desired_200_then_304_hot_path(env):
    code, doc, etag = env.client.get_desired(None)
    assert code == 200 and doc["version"] == 1 and etag == f'"{env.host_id}:1"'
    code, doc, etag2 = env.client.get_desired(etag)
    assert code == 304 and doc is None and etag2 == etag
    env.push(env.desired([env.comp("collector")]))
    code, doc, _ = env.client.get_desired(etag)
    assert code == 200 and doc["version"] == 2


def test_wrong_secret_is_unauthorized(env):
    c = ManagerClient(env.cfg.manager_url, exp_ids.new_token("expa"), allow_http=True, use_proxy=False)
    with pytest.raises(Unauthorized):
        c.get_desired(None)


def test_manager_down_is_unreachable_not_a_crash(env):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c = ManagerClient(
        f"http://127.0.0.1:{port}", env.secret, allow_http=True, use_proxy=False, connect_timeout=1
    )
    with pytest.raises(ManagerUnreachable):
        c.get_desired(None)


def test_forced_503_and_429_carry_retry_after(env):
    env.app.set_force(503, count=1, retry_after=7)
    with pytest.raises(ManagerUnreachable) as e:
        env.client.get_desired(None)
    assert e.value.retry_after == 7
    env.app.set_force(unreachable=True, count=1)
    with pytest.raises(ManagerUnreachable):
        env.client.get_desired(None)
    assert env.client.get_desired(None)[0] == 200


def test_4xx_is_a_client_error(env):
    with pytest.raises(ClientError) as e:
        env.client.get_manifest("9.9.9")
    assert e.value.status == 404


def test_backoff_30s_to_5min_and_reset():
    b = Backoff()
    assert [b.next() for _ in range(6)] == [30, 60, 120, 240, 300, 300]
    b.reset()
    assert b.next() == 30


def test_jitter_is_within_20_percent():
    import random

    rng = random.Random(1)
    vals = [jittered(30, 0.2, rng) for _ in range(500)]
    assert min(vals) >= 24 and max(vals) <= 36 and len({round(v, 3) for v in vals}) > 100


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/api/agent/v1/../v2/x",
        "/api/agent/v1//x",
        "http://evil/x",
        "//evil.example/api/agent/v1/desired",
        "/api/agent/v2/desired",
        "/api/agent/v1/a b",
    ],
)
def test_only_manager_agent_api_paths_are_requested(env, path):
    with pytest.raises(Refused):
        env.client.request("GET", path)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/x",
        "/api/agent/v1/artifacts/../../etc",
        "/api/agent/v1/desired",
        "/api/agent/v1/artifacts/art_short",
        "http://127.0.0.1:1/api/agent/v1/artifacts/art_" + "0" * 26,
    ],
)
def test_artifact_downloads_only_from_artifact_paths(env, url):
    with pytest.raises(Refused):
        env.client.download_artifact(url, 1, 10)


def test_artifact_download_size_is_bounded(env, tmp_path):
    a = env.artifacts["exp-collector-0.1.0-amd64.tar.gz"]
    url = f"/api/agent/v1/artifacts/{a['id']}"
    fd = (tmp_path / "f").open("wb").fileno()
    with pytest.raises(Refused, match="larger"):
        env.client.download_artifact(url, fd, a["size"] - 1)
    with pytest.raises(ManagerUnreachable, match="truncated"):
        env.client.download_artifact(url, fd, a["size"] + 1)
    import os

    fd2 = os.open(tmp_path / "g", os.O_WRONLY | os.O_CREAT)
    try:
        assert env.client.download_artifact(url, fd2, a["size"]) == a["sha256"]
    finally:
        os.close(fd2)


def test_artifact_not_referenced_by_this_host_is_forbidden(env):
    other = env.add_raw_artifact("exp-probe-0.1.0-noarch.tar.gz", "probe", "noarch", b"x")
    del other
    url = f"/api/agent/v1/artifacts/{env.artifacts['exp-probe-0.1.0-noarch.tar.gz']['id']}"
    with pytest.raises(ClientError) as e:
        env.client.download_artifact(url, 1, 1)
    assert e.value.status == 403


# ------------------------------------------------------------------------------------------- TLS
def test_tls_verified_against_a_trusted_certificate(tmp_path):
    e = Env(tmp_path, tls=True)
    try:
        e.standard_release(comps=("collector",))
        e.push(e.desired([e.comp("collector")]))
        cert = e.app.state_dir / "tls" / "cert.pem"
        ctx = ssl.create_default_context(cafile=str(cert))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        c = ManagerClient(e.cfg.manager_url, e.secret, ssl_context=ctx, use_proxy=False)
        assert c.get_desired(None)[0] == 200
        # the system trust store does not know this self-signed certificate: refused, never downgraded
        strict = ManagerClient(e.cfg.manager_url, e.secret, use_proxy=False)
        with pytest.raises(ManagerUnreachable, match="SSL"):
            strict.get_desired(None)
        # plain http to the same origin is refused at construction
        with pytest.raises(Exception, match="https"):
            ManagerClient(e.cfg.manager_url.replace("https", "http"), e.secret)
        assert strict._ctx.minimum_version >= ssl.TLSVersion.TLSv1_2 and strict._ctx.check_hostname
        assert strict._ctx.verify_mode == ssl.CERT_REQUIRED
    finally:
        e.close()


def test_https_proxy_is_honoured_with_connect_tunnel(tmp_path, monkeypatch):
    e = Env(tmp_path, tls=True)
    seen: list[str] = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    pport = srv.getsockname()[1]

    def pipe(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def proxy():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            seen.append(req.split(b"\r\n")[0].decode())
            up = socket.create_connection(("127.0.0.1", e.fake.port))
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            threading.Thread(target=pipe, args=(conn, up), daemon=True).start()
            threading.Thread(target=pipe, args=(up, conn), daemon=True).start()

    threading.Thread(target=proxy, daemon=True).start()
    try:
        e.standard_release(comps=("collector",))
        e.push(e.desired([e.comp("collector")]))
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{pport}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        ctx = ssl.create_default_context(cafile=str(e.app.state_dir / "tls" / "cert.pem"))
        c = ManagerClient(e.cfg.manager_url, e.secret, ssl_context=ctx)
        assert c.get_desired(None)[0] == 200
        assert seen and seen[0].startswith(f"CONNECT 127.0.0.1:{e.fake.port} HTTP/1.")
    finally:
        srv.close()
        e.close()


def test_enrol_validates_token_shape_and_never_puts_it_in_a_url(tmp_path):
    e = Env(tmp_path)
    try:
        c = ManagerClient(e.cfg.manager_url, None, allow_http=True, use_proxy=False)
        with pytest.raises(Refused):
            c.enrol("not-a-token", {"hostname": "h", "arch": "amd64"})
        pend = e.app.add_host(name="srv-9")
        tok = e.app.issue_enrol_token(pend["host_id"])
        doc = c.enrol(tok, {"hostname": "srv-9", "arch": "amd64"})
        assert doc["agent_id"] == pend["host_id"] and exp_ids.is_token(doc["agent_secret"], "expa")
        with pytest.raises(ClientError) as ex:
            c.enrol(tok, {"hostname": "srv-9", "arch": "amd64"})  # single use
        assert ex.value.status == 410
    finally:
        e.close()
