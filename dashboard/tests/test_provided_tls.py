"""End-to-end check of the provided-certificate path (CR p2, 01-contracts.md section 9.3): the manager delivers
creds ``tls.crt`` / ``tls.key`` with ``tls.mode = provided``; the dashboard must serve exactly that certificate (not a
self-signed one of its own), report its fingerprint, and pick up a renewed pair without a restart."""
from __future__ import annotations

import dataclasses
import shutil
import time

from exp_common import tlspin
from exp_dashboard import health
from exp_dashboard.config import load_settings
from exp_dashboard.server import DashboardApp


def served_fingerprint(port: int) -> str:
    return tlspin.probe_fingerprint("127.0.0.1", port)


def test_dashboard_serves_the_provided_certificate_and_reloads_a_renewed_one(make_world, tmp_path):
    w = make_world(tls_mode="provided", start=False)
    prov = tmp_path / "provided"
    cert, key = tlspin.generate_self_signed_cert(prov / "a", cn="dash.provided.example.test")
    shutil.copyfile(cert, w.creds / "tls.crt")
    shutil.copyfile(key, w.creds / "tls.key")
    # NO tls_cert / tls_key override: the location comes from tls.mode = provided (creds/tls.crt, creds/tls.key)
    s = load_settings(w.config_path, state_dir=w.state_dir, creds_dir=w.creds, run_dir=w.run_dir)
    s = dataclasses.replace(s, https=("127.0.0.1", 0), http_redirect=("127.0.0.1", 0))
    assert s.tls_mode == "provided" and s.tls_cert == w.creds / "tls.crt" and s.tls_key == w.creds / "tls.key"
    app = DashboardApp(s, watch_interval=0.2)
    app.start()
    try:
        want = tlspin.fingerprint_of_pem_file(cert)
        assert served_fingerprint(app.https_port) == want
        assert health.tls_fingerprint(s) == want  # what the agent reports as tls_fingerprint_sha256
        assert not (w.state_dir / "tls").exists(), "a provided certificate must not trigger self-signed generation"
        # renewal: the agent rewrites creds/tls.crt + tls.key; the running dashboard serves the new pair
        cert2, key2 = tlspin.generate_self_signed_cert(prov / "b", cn="dash.provided.example.test")
        assert tlspin.fingerprint_of_pem_file(cert2) != want
        shutil.copyfile(key2, w.creds / "tls.key")
        shutil.copyfile(cert2, w.creds / "tls.crt")
        want2 = tlspin.fingerprint_of_pem_file(cert2)
        deadline = time.time() + 10
        while time.time() < deadline and served_fingerprint(app.https_port) != want2:
            time.sleep(0.2)
        assert served_fingerprint(app.https_port) == want2
        assert health.tls_fingerprint(s) == want2
    finally:
        app.stop()
