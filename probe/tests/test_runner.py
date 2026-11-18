"""The command runner: argv lists only, timeouts, no shell."""
from __future__ import annotations

import pytest

from exp_probe.runner import CommandRunner, ns_exec_argv, ns_name


def test_ns_wrapper_argv():
    assert ns_name("c01") == "exp-c01"
    assert ns_exec_argv("c01", ["curl", "-s", "x"]) == ["ip", "netns", "exec", "exp-c01", "curl", "-s", "x"]


@pytest.mark.parametrize("bad", ["ls -l", b"ls", [], ["ls", 3], ["ls", "a\x00b"], None])
def test_non_argv_is_refused(bad):
    with pytest.raises(TypeError):
        CommandRunner().run(bad, 1)


def test_timeout_is_mandatory_and_positive():
    with pytest.raises(ValueError):
        CommandRunner().run(["true"], 0)


def test_captures_output_and_rc():
    r = CommandRunner().run(["sh", "-c", "echo out; echo err >&2; exit 3"], 5)
    assert (r.rc, r.stdout.strip(), r.stderr.strip(), r.ok) == (3, "out", "err", False)


def test_missing_binary_is_rc_127_not_an_exception():
    r = CommandRunner().run(["definitely-not-a-binary-xyz"], 2)
    assert r.rc == 127 and "not found" in r.stderr


def test_timeout_kills_and_flags():
    r = CommandRunner().run(["sleep", "5"], 0.3)
    assert r.timed_out and r.rc == 124 and not r.ok


def test_no_shell_interpretation():
    r = CommandRunner().run(["echo", "a; echo injected $(id)"], 2)
    assert r.stdout.strip() == "a; echo injected $(id)"


def test_stdin_is_devnull():
    assert CommandRunner().run(["cat"], 2).stdout == ""
