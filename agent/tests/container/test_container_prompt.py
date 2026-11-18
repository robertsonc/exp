"""install.sh with no argument and no /etc/exp/agent.json prompts for the token with echo off (read from /dev/tty)."""

from __future__ import annotations

from harness import token_used

DRIVER = r"""
import os, pty, select, sys, time
token = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "/tmp/served.sh"])
out, sent, deadline = b"", False, time.time() + 240
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1.0)
    if r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
        if b"Enrol token" in out and not sent:
            time.sleep(0.5)
            os.write(fd, token.encode() + b"\n")
            sent = True
_, status = os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status) if sent else 99)
"""


def test_no_argument_prompts_for_the_token_without_echo(world, host24):
    host24.reset_host()
    world.standard_release("0.1.0")
    hid, token = world.add_host("srv-prompt")
    world.set_desired(hid, "0.1.0")
    host24.write("/tmp/served.sh", world.serve_install_sh().read_text())
    host24.write("/tmp/driver.py", DRIVER)
    r = host24.run(f"python3 /tmp/driver.py {token}", timeout=300)
    assert r.rc == 0, r
    assert "Enrol token (input hidden)" in r.out
    assert token not in r.out, "the token was echoed back to the terminal"
    assert "installed and running" in r.out
    assert token_used(world, token) and host24.active("exp-agent.service")
