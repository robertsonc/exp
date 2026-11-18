"""Fakes for the probe tests: a stateful fake of the `ip` command (behind the injectable runner) and a
fake clock. `FakeIp.run` implements exactly the `ip` invocations the probe uses and records every call;
`mutations` lists only the calls that change something, so "nothing changed" is an assertion on it."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from exp_probe.runner import CmdResult


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> float:
        self.t += s
        return self.t


@dataclass
class Link:
    name: str
    up: bool = False
    carrier: bool = True
    virtual: bool = False          # destroyed when its namespace is deleted (veth, VF ...)
    addrs: list[str] = field(default_factory=list)
    master: str | None = None
    kind: str | None = None
    parent: str | None = None
    rx: int = 0

    def flags(self) -> list[str]:
        f = ["BROADCAST", "MULTICAST"]
        if self.up:
            f.append("UP")
            f.append("LOWER_UP" if self.carrier else "NO-CARRIER")
        return f

    def as_json(self, stats: bool = False) -> dict:
        d: dict = {"ifname": self.name, "flags": self.flags(), "operstate": "UP" if self.up and self.carrier else "DOWN"}
        if self.master:
            d["master"] = self.master
        li: dict = {}
        if self.kind:
            li["info_kind"] = self.kind
        if li:
            d["linkinfo"] = li
        if self.parent:
            d["link"] = self.parent
        if stats:
            d["stats64"] = {"rx": {"bytes": self.rx, "packets": self.rx // 100, "errors": 0, "dropped": 0},
                            "tx": {"bytes": self.rx // 2, "packets": self.rx // 200, "errors": 0, "dropped": 0}}
        return d


class FakeIp:
    HOST = ""

    def __init__(self) -> None:
        self.ns: dict[str, dict[str, Link]] = {self.HOST: {}}
        self.default_routes: list[str] = []
        self.calls: list[list[str]] = []
        self.mutations: list[list[str]] = []
        self.fail_move_back: set[str] = set()
        self.fail_all = False
        self.extra: dict[tuple[str, ...], CmdResult] = {}
        self.pids: dict[str, list[str]] = {}

    # ---- topology helpers
    def add_host_link(self, name: str, **kw) -> Link:
        lk = Link(name, **kw)
        self.ns[self.HOST][name] = lk
        return lk

    def where(self, name: str) -> str | None:
        for ns, links in self.ns.items():
            if name in links:
                return ns
        return None

    def host_names(self) -> set[str]:
        return set(self.ns[self.HOST])

    # ---- runner interface
    def run(self, argv, timeout=10, **_kw) -> CmdResult:
        a = list(argv)
        self.calls.append(a)
        key = tuple(a)
        if key in self.extra:
            return self.extra[key]
        if self.fail_all and a[:1] == ["ip"]:
            return self._r(a, 1, err="RTNETLINK answers: Operation not permitted")
        if a[0] != "ip":
            return self._r(a, 127, err=f"{a[0]}: command not found")
        is_query = "show" in a or a[1:3] in (["netns", "list"], ["netns", "pids"])
        if not is_query:
            self.mutations.append(a)
        return self._dispatch(a)

    def run_ns(self, port_id, argv, timeout=10, **kw):
        return self.run(["ip", "netns", "exec", f"exp-{port_id}", *argv], timeout, **kw)

    @staticmethod
    def _r(a, rc=0, out="", err=""):
        return CmdResult(tuple(a), rc, out, err)

    def _json(self, a, obj):
        return self._r(a, 0, json.dumps(obj))

    def _dispatch(self, a: list[str]) -> CmdResult:  # noqa: C901
        args = a[1:]
        v6 = False
        if args[:1] == ["-6"]:
            v6, args = True, args[1:]
        ns = self.HOST
        if args[:1] == ["-n"]:
            ns, args = args[1], args[2:]
            if ns not in self.ns:
                return self._r(a, 1, err=f'Cannot open network namespace "{ns}": No such file or directory')
        want_json = False
        stats = False
        while args and args[0] in ("-j", "-d", "-s"):
            want_json |= args[0] == "-j"
            stats |= args[0] == "-s"
            args = args[1:]
        links = self.ns[ns]
        # ----- netns management
        if args[:2] == ["netns", "list"]:
            return self._r(a, 0, "".join(f"{n} (id: {i})\n" for i, n in enumerate(sorted(x for x in self.ns if x))))
        if args[:2] == ["netns", "add"]:
            self.ns.setdefault(args[2], {"lo": Link("lo", up=False)})
            return self._r(a)
        if args[:2] == ["netns", "del"]:
            gone = self.ns.pop(args[2], {})
            for name, lk in gone.items():
                if name != "lo" and not lk.virtual:
                    lk.up = False
                    self.ns[self.HOST][name] = lk          # physical ports return to the host
            return self._r(a)
        if args[:2] == ["netns", "pids"]:
            return self._r(a, 0, " ".join(self.pids.get(args[2], [])))
        if args[:2] == ["netns", "exec"]:
            if args[2] not in self.ns:
                return self._r(a, 1, err="no such namespace")
            return self._r(a)
        # ----- queries
        if args[:2] == ["route", "show"] and "default" in args:
            if v6:
                return self._json(a, [])
            return self._json(a, [{"dst": "default", "gateway": "10.0.0.1", "dev": d} for d in self.default_routes])
        if args[:1] == ["addr"] and args[1] == "show":
            if "dev" in args:
                names = [args[args.index("dev") + 1]]
            else:
                names = list(links)
            return self._json(a, [{"ifname": n, "addr_info": [
                {"family": "inet", "local": ad.split("/")[0], "prefixlen": int(ad.split("/")[1]),
                 "scope": "global" if not ad.startswith("169.254") else "link"} for ad in links[n].addrs]}
                for n in names if n in links])
        if args[:1] == ["link"] and args[1] == "show":
            if "dev" in args:
                n = args[args.index("dev") + 1]
                if n not in links:
                    return self._r(a, 1, err=f'Device "{n}" does not exist.')
                return self._json(a, [links[n].as_json(stats)]) if want_json else self._r(a, 0, f"{n}: <...>\n")
            return self._json(a, [lk.as_json(stats) for lk in links.values()])
        # ----- mutations
        if args[:2] == ["link", "set"]:
            return self._link_set(a, ns, args[2:])
        if args[:2] == ["link", "add"] and "vlan" in args:
            name = args[args.index("name") + 1]
            parent = args[args.index("link") + 1]
            links[name] = Link(name, kind="vlan", parent=parent, virtual=True)
            return self._r(a)
        if args[:2] == ["link", "del"]:
            links.pop(args[3], None)
            return self._r(a)
        if args[:3] == ["-4", "addr", "flush"] or args[:2] == ["addr", "replace"] or args[:2] == ["route", "replace"]:
            return self._r(a)
        return self._r(a, 1, err=f"fake ip: unhandled {a}")

    def _link_set(self, a, ns, rest):
        links = self.ns[ns]
        if rest[0] == "lo":
            links["lo"].up = rest[1] == "up"
            return self._r(a)
        name = rest[1]
        if name not in links:
            return self._r(a, 1, err=f'Cannot find device "{name}"')
        action = rest[2:]
        if action[0] == "netns":
            dest = "" if action[1] == "1" else action[1]
            if dest not in self.ns:
                return self._r(a, 1, err="no such namespace")
            if dest == self.HOST and name in self.fail_move_back:
                return self._r(a, 2, err="RTNETLINK answers: Invalid argument")
            self.ns[dest][name] = links.pop(name)
            return self._r(a)
        if action[0] in ("up", "down"):
            links[name].up = action[0] == "up"
            return self._r(a)
        if action[0] in ("mtu",):
            return self._r(a)
        return self._r(a, 1, err=f"fake ip: unhandled link set {action}")
