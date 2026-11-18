import os

import pytest
from exp_common import creds
from exp_common.creds import CredentialError


def put(d, name, data, mode=0o600):
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    p.chmod(mode)
    return p


def test_reads_from_credentials_directory_env(tmp_path, monkeypatch):
    put(tmp_path, "agent-secret", "expa_ABC\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert creds.read_credential("agent-secret") == "expa_ABC"


def test_explicit_directory_and_single_newline_strip(tmp_path):
    put(tmp_path, "a", "v\n\n")
    put(tmp_path, "b", "v")
    put(tmp_path, "c", b"")
    assert creds.read_credential("a", tmp_path) == "v\n"      # exactly one newline stripped
    assert creds.read_credential("b", tmp_path) == "v"
    assert creds.read_credential("c", tmp_path) == ""


def test_missing_credential_names_file_not_value(tmp_path):
    with pytest.raises(creds.CredentialMissing) as ei:
        creds.read_credential("nope", tmp_path)
    assert str(tmp_path / "nope") in str(ei.value)
    assert creds.optional_credential("nope", tmp_path) is None
    assert not creds.has_credential("nope", tmp_path)


def test_no_directory_configured(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(CredentialError, match="CREDENTIALS_DIRECTORY"):
        creds.read_credential("x")


def test_symlink_credential_refused(tmp_path):
    secret = tmp_path / "elsewhere"
    secret.write_text("TOPSECRET")
    d = tmp_path / "creds"
    d.mkdir()
    os.symlink(secret, d / "link")
    with pytest.raises(CredentialError) as ei:
        creds.read_credential("link", d)
    assert "TOPSECRET" not in str(ei.value) and "symlink" in str(ei.value)
    with pytest.raises(CredentialError):
        creds.optional_credential("link", d)        # unsafe is never "absent"


def test_non_regular_file_refused(tmp_path):
    (tmp_path / "dir").mkdir()
    with pytest.raises(CredentialError):
        creds.read_credential("dir", tmp_path)
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(CredentialError):            # must refuse (and not hang opening/reading)
        creds.read_credential("fifo", tmp_path)


@pytest.mark.parametrize("name", ["../x", "a/b", "", ".hidden", "a b", "x\x00y", "-rf", "a" * 200, None])
def test_bad_names_refused(tmp_path, name):
    with pytest.raises(CredentialError, match="invalid credential name"):
        creds.read_credential(name, tmp_path)


def test_size_bound(tmp_path):
    put(tmp_path, "big", b"x" * 2000)
    with pytest.raises(CredentialError, match="exceeds"):
        creds.read_credential("big", tmp_path, max_bytes=1000)
    assert len(creds.read_credential("big", tmp_path, max_bytes=2000)) == 2000
    with pytest.raises(CredentialError):
        creds.read_credential("big", tmp_path, max_bytes=1999)


def test_default_bound_is_1mib(tmp_path):
    put(tmp_path, "big", b"x" * (creds.MAX_CREDENTIAL_BYTES + 1))
    with pytest.raises(CredentialError):
        creds.read_credential("big", tmp_path)


def test_json_helper_and_errors_do_not_leak(tmp_path):
    put(tmp_path, "j", '{"api_key": "k"}\n')
    assert creds.read_credential_json("j", tmp_path) == {"api_key": "k"}
    put(tmp_path, "badj", "{TOPSECRETVALUE")
    with pytest.raises(CredentialError) as ei:
        creds.read_credential_json("badj", tmp_path)
    assert "TOPSECRETVALUE" not in str(ei.value) and "TOPSECRETVALUE" not in repr(ei.value.__cause__)


def test_non_utf8_refused_without_leak(tmp_path):
    put(tmp_path, "bin", b"\xff\xfeSECRET")
    with pytest.raises(CredentialError) as ei:
        creds.read_credential("bin", tmp_path)
    assert "SECRET" not in str(ei.value)
    assert creds.read_credential_bytes("bin", tmp_path) == b"\xff\xfeSECRET"


def test_require_private_refuses_group_readable(tmp_path):
    put(tmp_path, "open", "v", mode=0o644)
    put(tmp_path, "priv", "v", mode=0o400)
    with pytest.raises(CredentialError, match="group/other"):
        creds.read_credential("open", tmp_path, require_private=True)
    assert creds.read_credential("priv", tmp_path, require_private=True) == "v"


def test_values_never_logged(tmp_path, caplog):
    put(tmp_path, "tok", "VERY-SECRET-VALUE")
    with caplog.at_level("DEBUG"):
        creds.read_credential("tok", tmp_path)
        creds.read_credential_bytes("tok", tmp_path)
    assert "VERY-SECRET-VALUE" not in caplog.text


def test_bad_directory(tmp_path):
    with pytest.raises(CredentialError, match="not usable"):
        creds.read_credential("x", tmp_path / "missing-dir")
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(CredentialError):
        creds.read_credential("x", f)
