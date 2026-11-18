"""06-agent.md section 9 item 7 (second half): `exp-agent uninstall --local` works with the manager gone."""

from __future__ import annotations

from harness import run_install, token_used, wait_for


def test_uninstall_local_removes_everything_while_the_manager_is_down(world, host24):
    host24.reset_host()
    world.standard_release("0.1.0", components=("collector",))
    hid, token = world.add_host("srv-local")
    world.set_desired(hid, "0.1.0", components=[world.collector_component("0.1.0")])
    r = run_install(host24, world, token)
    assert r.rc == 0, r
    wait_for(lambda: host24.active("exp-collector.service"), 180, 2, "the component to converge")
    world.app.set_force(unreachable=True)
    try:
        r = host24.run("exp-agent uninstall --local")
        assert r.rc == 0, r
        assert "uninstalled" in r.out
    finally:
        world.app.set_force()
    wait_for(lambda: not host24.active("exp-agent.service"), 60, 1, "the agent to stop")
    assert not host24.active("exp-collector.service")
    left = host24.files_under("/opt/exp", "/etc/exp", "/var/lib/exp", "/run/exp", "/usr/local/bin/exp-*")
    left += host24.run(
        "ls -d /etc/systemd/system/exp-* /etc/systemd/system/*.wants/exp-* 2>/dev/null"
    ).out.split()
    assert left == [], left
    # the manager was never told: the host stays listed until an admin removes it
    assert world.host(hid).state == "enrolled" and token_used(world, token)
