"""Harness for the r2 connector tests: the c1 vendor fakes (Mist, EdgeConnect Orchestrator), the real services/connectors, the
runner's own pipeline (``Correlator.build_documents``) so every produced evidence document is schema-validated like in production."""
from __future__ import annotations

import copy
import logging
import time
from pathlib import Path
from typing import Any

import fake_st_collector as fst
from fakes_common import det_id, iso_from_epoch
from mist import server as fmist
from orchestrator import server as forch
from rthelpers import base_config, load_fixture, runner_token, secret

from exp_runner import evidence as ev
from exp_runner.baseline import BaselineConnector
from exp_runner.collector_client import CollectorClient
from exp_runner.config import RunnerConfig, parse_config
from exp_runner.connectors import CallBudget, Connector, Context, SyslogConnector
from exp_runner.correlator import Correlator, StateStore, to_testref
from exp_runner.ec import EcConnector, EcService
from exp_runner.identity import IdentityResolver
from exp_runner.mist import MistConnector, MistService
from exp_runner.ring import Ring

IP = "10.60.14.77"
MAC = "f0:18:98:aa:bb:01"


def make_config(mist: bool = True, ec: bool = True) -> RunnerConfig:
    doc = base_config(mist=mist)
    if ec:
        doc["correlation"]["sources"]["ec"] = copy.deepcopy(load_fixture("configs/runner.correlation.json")["correlation"]["sources"]["ec"])
    return parse_config(doc)


class World:
    def __init__(self, tmp_path: Path, *, mist: bool = True, ec: bool = True, baseline: bool = True, cfg: RunnerConfig | None = None,
                 mist_kw: dict[str, Any] | None = None, ec_kw: dict[str, Any] | None = None) -> None:
        self.tmp = tmp_path
        self.now = time.time()
        self.cfg = cfg or make_config(mist, ec)
        self.fmist = fmist.start() if mist else None
        self.forch = forch.start() if ec else None
        toks = fst.default_tokens()
        self.fcoll = fst.start(tokens=toks)
        self.runner_tok = runner_token(toks)
        self.collector_client = CollectorClient(f"http://127.0.0.1:{self.fcoll.port}", None, self.runner_tok, sleep=lambda _s: None)
        self.ring = Ring(tmp_path / "syslog.db").open()
        self.state = StateStore(tmp_path / "runner.db").open()
        self.mist_svc: MistService | None = None
        self.ec_svc: EcService | None = None
        self.connectors: list[Connector] = [SyslogConnector(self.cfg)]
        if mist:
            self.mist_svc = MistService(self.cfg.mist, {"api_base": self.fmist.base_url, "token": fmist.default_token()}, **(mist_kw or {}))
            self.connectors.append(MistConnector(self.mist_svc))
        if ec:
            self.ec_svc = EcService(self.cfg.ec, {"url": self.forch.base_url, "api_key": forch.default_credentials()[0]}, **(ec_kw or {}))
            self.connectors.append(EcConnector(self.ec_svc))
        if baseline:
            self.connectors.append(BaselineConnector(lambda: self.collector_client))
        self.resolver = IdentityResolver(self.cfg, self.ring, secret(), self.mist_svc)
        self.corr = Correlator(self.cfg, self.collector_client, self.ring, self.resolver, self.connectors, self.state, now_fn=time.time,
                               workers=1)

    # ---------------------------------------------------------------------------------------------------- scenarios
    @property
    def at(self) -> float:
        return self.now - 800.0

    def mist_scenario(self, name: str, ip: str = IP, mac: str = MAC) -> dict[str, Any]:
        return self.fmist.state.load_scenario(name, at=self.at, ip=ip, mac=mac)

    def ec_scenario(self, name: str, ip: str = IP) -> dict[str, Any]:
        return self.forch.state.load_scenario(name, at=self.at, client_ip=ip)

    # ------------------------------------------------------------------------------------------------------- running
    def item(self, ip: str = IP, n: int = 1) -> dict[str, Any]:
        started = self.now - 900.0
        return {"id": det_id("st_", f"r2-{n}"), "site": "hall-b", "client_ip": ip, "started": iso_from_epoch(started),
                "ended": iso_from_epoch(started + 20)}

    def run(self, ip: str = IP, *, budget: int | None = None) -> tuple[dict[str, dict[str, Any]], Any, Context]:
        """Identity + every connector through the production pipeline. Returns ({kind: validated evidence doc}, identity, context)."""
        test = to_testref(self.item(ip), self.cfg)
        n = budget if budget is not None else int((self.cfg.mist or {}).get("max_calls_per_test", 6))
        budgets = {"mist": CallBudget(n)}
        ident = self.resolver.resolve(test, test.window, budgets["mist"])
        ctx = Context(test, test.window, ident, self.ring, self.cfg, time.time, budgets)
        docs = self.corr.build_documents(test, ident, ctx)
        for d in docs:
            assert ev.validation_errors(d) == [], (d["kind"], ev.validation_errors(d))  # noqa: S101
        return {d["kind"]: d for d in docs}, ident, ctx

    def close(self) -> None:
        self.corr.close()
        for s in (self.fmist, self.forch, self.fcoll):
            if s is not None:
                s.stop()
        self.ring.close()
        self.state.close()


def capture_logs(caplog: Any) -> str:
    caplog.set_level(logging.DEBUG)
    return "\n".join(r.getMessage() for r in caplog.records)
