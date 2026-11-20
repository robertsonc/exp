"""Speedtest analytics routes (12 section 8, WP-11): federation of the collector `speedtests` query API.

* list / aggregate fan out to every collector (3 s each) and merge, adding
  ``"collectors":[{collector_id, ok, error?}]`` exactly like the probe lists, so a collector that is down
  gives flagged partial results, never an error;
* ``speedtests/{id}`` is looked up on every collector (a test lives on its site's collector); first hit wins;
* ``speedtests/purge`` (admin only, audited) goes to every collector: a device may have tested in any hall;
* raw identifiers (client IP/MAC/hostname/username) are requested from a collector (``identifiers=true``) ONLY
  for an admin session that asks for them (SR-25). The browser can never set the flag itself, and every
  response for a non-admin session is additionally run through :func:`sanitize_detail` (defence in depth:
  a collector that leaked would still not reach a viewer).
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import logging
import re
from typing import Any

from .federate import ApiProblem, Federation, UpstreamResult, _enum, _int, _slug, _text, _time

log = logging.getLogger(__name__)

ST_ID = re.compile(r"^st_[0-9A-HJKMNP-TV-Z]{26}$")
_DEVICE_KEY = re.compile(r"^[0-9a-f]{64}$")
_MAC = re.compile(r"^[0-9A-Fa-f]{2}([:\-.]?[0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{4}(\.[0-9A-Fa-f]{4}){2}$")
_IP = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
MASK = "[scrubbed]"
MAX_PURGE_BODY = 1024

LIST_PARAMS = {"site": _slug, "zone": _text(64), "ap": _text(128), "ssid": _text(64), "cause": _text(64),
               "from": _time, "to": _time, "min_score": _int(0, 100), "max_score": _int(0, 100),
               "q": _text(128), "limit": _int(1, 1000), "cursor": lambda v: _composite_ok(v)}
AGG_PARAMS = {"group_by": _enum("zone", "ap", "ssid", "band", "os_family", "hour", "cause"),
              "metric": _enum("down_p50", "up_p50", "loaded_p50", "score_p50", "count"),
              "leg": _enum("local", "internet"), "site": _slug, "from": _time, "to": _time}
DETAIL_PARAMS: dict[str, Any] = {}

# keys that hold a raw client identifier wherever they appear in a payload (the collector's privacy.py is the
# authority; this list only has to cover what the collector would have removed)
_NAME_KEYS = ("hostname", "username", "dhcp_hostname", "dhcp_fqdn")
_RAW_KEYS = {"client_ip", "src_ip_raw", "hostname", "username", "dhcp_hostname", "dhcp_fqdn", "mac_address"}


def _composite_ok(v: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_=.\-]{1,2048}", v):
        raise ValueError
    return v


def _clean(params: dict[str, Any], raw: dict[str, list[str]],
           required: tuple[str, ...] = ()) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, vals in raw.items():
        fn = params.get(k)
        if fn is None or not vals:
            continue
        try:
            out[k] = fn(vals[0])
        except ValueError:
            raise ApiProblem(400, "invalid_request", f"bad value for '{k}'") from None
    for k in required:
        if k not in out:
            raise ApiProblem(400, "invalid_request", f"missing '{k}'")
    return out


# ------------------------------------------------------------------------------------------------ sanitizing
def _identifiers_of(doc: Any) -> tuple[set[str], set[str], set[str]]:
    """ips, macs, names found for the client anywhere in a (possibly leaky) detail document."""
    ips: set[str] = set()
    macs: set[str] = set()
    names: set[str] = set()

    def mac(v: Any) -> None:
        if isinstance(v, str) and _MAC.match(v):
            macs.add(re.sub(r"[^0-9a-f]", "", v.lower()))

    def walk(node: Any, parent: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "ip" and parent in ("client", "identity", "data") and isinstance(v, str):
                    ips.add(v)
                elif k == "ip" and isinstance(v, list):
                    ips.update(x for x in v if isinstance(x, str))
                elif k == "mac" and parent in ("client", "data") and isinstance(v, str):
                    mac(v)                    # the client's own MAC; ap.mac / switch macs are infrastructure
                elif k in _NAME_KEYS and isinstance(v, str) and len(v) >= 3:
                    names.add(v)
                walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, parent)

    walk(doc)
    return ips, macs, names


def _mac_pattern(macs: set[str]) -> list[str]:
    out = []
    for m in macs:
        pairs = [m[i:i + 2] for i in range(0, 12, 2)]
        out += [m, ":".join(pairs), "-".join(pairs), ".".join(m[i:i + 4] for i in range(0, 12, 4))]
    return out


def sanitize_detail(doc: Any) -> Any:
    """A copy of one `speedtests/{id}` document with no raw client identifiers (SR-25). device_key is kept."""
    if not isinstance(doc, dict):
        return doc
    ips, macs, names = _identifiers_of(doc)
    out = copy.deepcopy(doc)
    toks = sorted({t for t in [*ips, *names, *_mac_pattern(macs)] if t}, key=len, reverse=True)
    pat = re.compile(r"(?<![0-9A-Za-z])(?:" + "|".join(re.escape(t) for t in toks) + r")(?![0-9A-Za-z])",
                     re.IGNORECASE) if toks else None

    def scrub(node: Any, parent: str = "") -> Any:
        if isinstance(node, dict):
            res = {}
            for k, v in node.items():
                if k in _RAW_KEYS or k == "username":
                    continue
                if k in ("mac", "ip") and parent in ("client", "data"):
                    continue          # the client's own MAC / IP; ap and switch macs use other key names
                res[k] = scrub(v, k)
            return res
        if isinstance(node, list):
            return [scrub(v, parent) for v in node]
        if isinstance(node, str) and pat is not None:
            return pat.sub(MASK, node)
        return node

    out = scrub(out)
    # the identity evidence document (kind=identity) is flagged so the UI can say "identifiers hidden"
    for ev in out.get("evidence", []) if isinstance(out.get("evidence"), list) else []:
        if isinstance(ev, dict) and ev.get("kind") == "identity" and isinstance(ev.get("data"), dict):
            ev["data"]["scrubbed"] = True
    # flow rows keep their (required) ip fields: any that equalled the client's address were masked by the
    # sweep to "[scrubbed]", which is not an address; show the neutral placeholder instead
    for ev in out.get("evidence", []) if isinstance(out.get("evidence"), list) else []:
        if isinstance(ev, dict) and ev.get("kind") == "flows" and isinstance(ev.get("data"), dict):
            for f in ev["data"].get("flows") or []:
                if isinstance(f, dict):
                    for k in ("ip1", "ip2"):
                        if f.get(k) == MASK:
                            f[k] = "0.0.0.0"  # noqa: S104 - schema-valid placeholder
    return out


def sanitize_list_item(item: Any) -> Any:
    if not isinstance(item, dict):
        return item
    return {k: v for k, v in item.items() if k not in _RAW_KEYS and k not in ("ip", "mac")}


# ------------------------------------------------------------------------------------------------ federation
class SpeedtestApi:
    def __init__(self, fed: Federation) -> None:
        self.fed = fed

    # -- helpers --------------------------------------------------------------------------------
    def _doc(self, r: UpstreamResult) -> dict[str, Any] | None:
        try:
            doc = r.json()
        except (ValueError, UnicodeDecodeError):
            return None
        return doc if isinstance(doc, dict) else None

    def _fan(self, path: str, params: dict[str, str],
             user: str) -> tuple[list[UpstreamResult], list[dict[str, Any]]]:
        results = self.fed.fan_out(path, params, user)
        statuses = self.fed.status_list(results)
        for r, st in zip(results, statuses, strict=True):
            if r.ok and r.status == 404:
                st["ok"], st["error"] = False, "speedtests_disabled"      # analytics off on that collector
            elif r.ok and r.status != 200:
                st["ok"], st["error"] = False, "upstream_error"
        return results, statuses

    @staticmethod
    def _enc_cursor(cur: dict[str, str]) -> str | None:
        if not cur:
            return None
        raw = json.dumps(cur, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @staticmethod
    def _dec_cursor(token: str | None) -> dict[str, str]:
        if not token:
            return {}
        try:
            doc = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            raise ApiProblem(400, "invalid_request", "bad cursor") from None
        if not isinstance(doc, dict) or len(doc) > 64 or not all(
                isinstance(k, str) and isinstance(v, str) and len(v) <= 1024 for k, v in doc.items()):
            raise ApiProblem(400, "invalid_request", "bad cursor")
        return doc

    # -- list -----------------------------------------------------------------------------------
    def list(self, raw: dict[str, list[str]], user: str, admin: bool) -> tuple[int, bytes, dict[str, str]]:
        params = _clean(LIST_PARAMS, raw)
        ident = admin and (raw.get("identifiers") or [""])[0] in ("1", "true")
        cursors = self._dec_cursor(params.pop("cursor", None))
        results = self.fed.fan_out_each(
            "speedtests", user, lambda cid: self._list_params(params, cursors, cid, ident))
        statuses = self.fed.status_list(results)
        items: list[dict[str, Any]] = []
        next_cur: dict[str, str] = {}
        for r, st in zip(results, statuses, strict=True):
            if r.ok and r.status == 404:
                st["ok"], st["error"] = False, "speedtests_disabled"
                continue
            if r.ok and r.status != 200:
                st["ok"], st["error"] = False, "upstream_error"
                continue
            if not r.ok:
                continue
            doc = self._doc(r)
            if doc is None or not isinstance(doc.get("items"), list):
                st["ok"], st["error"] = False, "bad_response"
                continue
            for it in doc["items"]:
                if isinstance(it, dict):
                    it = it if ident else sanitize_list_item(it)
                    it["collector_id"] = r.collector_id
                    items.append(it)
            nc = doc.get("next_cursor")
            if isinstance(nc, str) and nc:
                next_cur[r.collector_id] = nc
        items.sort(key=lambda i: (str(i.get("started", "")), str(i.get("id", ""))), reverse=True)
        out = {"items": items, "next_cursor": self._enc_cursor(next_cur), "collectors": statuses,
               "identifiers": bool(ident)}
        return 200, json.dumps(out, separators=(",", ":")).encode(), {}

    @staticmethod
    def _list_params(params: dict[str, str], cursors: dict[str, str], cid: str,
                     ident: bool) -> dict[str, str] | None:
        p = dict(params)
        if cursors:
            if cid not in cursors:
                return None                  # that collector was exhausted on an earlier page
            p["cursor"] = cursors[cid]
        if ident:
            p["identifiers"] = "true"
        return p

    # -- aggregate ------------------------------------------------------------------------------
    def aggregate(self, raw: dict[str, list[str]], user: str) -> tuple[int, bytes, dict[str, str]]:
        params = _clean(AGG_PARAMS, raw, required=("group_by", "metric"))
        results, statuses = self._fan("speedtests/aggregate", params, user)
        merged: dict[str, dict[str, Any]] = {}
        head: dict[str, Any] = {}
        for r, st in zip(results, statuses, strict=True):
            if not (r.ok and st["ok"]):
                continue
            doc = self._doc(r)
            if doc is None or not isinstance(doc.get("items"), list):
                st["ok"], st["error"] = False, "bad_response"
                continue
            head = head or {k: doc.get(k) for k in ("group_by", "metric", "leg", "from", "to")}
            for it in doc["items"]:
                if not (isinstance(it, dict) and isinstance(it.get("key"), str)
                        and isinstance(it.get("value"), (int, float)) and isinstance(it.get("count"), int)):
                    continue
                cur = merged.get(it["key"])
                if cur is None:
                    merged[it["key"]] = {"key": it["key"], "value": it["value"], "count": it["count"],
                                         "_n": 1}
                    continue
                n = cur["count"] + it["count"]
                if params["metric"] == "count":
                    cur["value"] = cur["value"] + it["value"]
                elif n > 0:
                    # a median cannot be merged exactly: the count-weighted mean of the collectors' medians
                    cur["value"] = (cur["value"] * cur["count"] + it["value"] * it["count"]) / n
                cur["count"], cur["_n"] = n, cur["_n"] + 1
        items = []
        for v in merged.values():
            n = v.pop("_n")
            if n > 1:
                v["approximate"] = params["metric"] != "count"
            items.append(v)
        if params["group_by"] == "hour":
            items.sort(key=lambda i: i["key"])
        else:
            items.sort(key=lambda i: (-i["count"], i["key"]))
        out = {**head, "items": items[:1000], "collectors": statuses}
        out.setdefault("group_by", params["group_by"])
        out.setdefault("metric", params["metric"])
        return 200, json.dumps(out, separators=(",", ":")).encode(), {}

    # -- detail ---------------------------------------------------------------------------------
    def detail(self, test_id: str, raw: dict[str, list[str]], user: str,
               admin: bool) -> tuple[int, bytes, dict[str, str]]:
        if not ST_ID.match(test_id):
            raise ApiProblem(404, "not_found", "no such test")
        ident = admin and (raw.get("identifiers") or [""])[0] in ("1", "true")
        params = {"identifiers": "true"} if ident else {}
        results, statuses = self._fan(f"speedtests/{test_id}", params, user)
        for r, st in zip(results, statuses, strict=True):
            if r.ok and st["ok"]:
                doc = self._doc(r)
                if doc is None:
                    continue
                if not ident:
                    doc = sanitize_detail(doc)
                doc["collector_id"] = r.collector_id
                doc["identifiers"] = bool(ident)
                body = json.dumps(doc, separators=(",", ":")).encode()
                return 200, body, {"X-Exp-Collector": r.collector_id}
        down = [s for s in statuses if not s["ok"] and s.get("error") != "speedtests_disabled"]
        if down:
            raise ApiProblem(502, "collector_unreachable", "a collector could not be asked",
                             {"collector_id": down[0]["collector_id"],
                              "reason": down[0].get("error", "unreachable")})
        raise ApiProblem(404, "not_found", "no such test")

    # -- purge ----------------------------------------------------------------------------------
    def purge(self, body: dict[str, Any], user: str) -> tuple[int, bytes, dict[str, str]]:
        """Admin only (checked by the caller). Goes to every collector; each audits it with X-Exp-User."""
        by, value, dry = body.get("by"), body.get("value"), body.get("dry_run", False)
        if by not in ("device_key", "mac", "ip", "test") or not isinstance(value, str) \
                or not isinstance(dry, bool):
            raise ApiProblem(400, "invalid_request", "by must be device_key|mac|ip|test with a string value")
        value = value.strip()
        ok = {"device_key": _DEVICE_KEY.match(value.lower()), "mac": _MAC.match(value),
              "ip": _IP.match(value), "test": ST_ID.match(value)}[by]
        if not ok:
            raise ApiProblem(400, "invalid_request", f"value is not a valid {by.replace('_', ' ')}")
        if by == "device_key":
            value = value.lower()
        if not dry and body.get("confirm") is not True:
            raise ApiProblem(400, "confirmation_required", "a purge must be confirmed (confirm: true)")
        payload = json.dumps({"by": by, "value": value, "dry_run": dry}).encode()
        results = self.fed.post_all("speedtests/purge", user, payload)
        statuses = self.fed.status_list(results)
        total = {"tests": 0, "evidence": 0, "diagnoses": 0}
        matched = 0
        key_matched = False
        per: list[dict[str, Any]] = []
        for r, st in zip(results, statuses, strict=True):
            if r.ok and r.status == 404:
                st["ok"], st["error"] = False, "speedtests_disabled"
            elif r.ok and r.status != 200:
                st["ok"], st["error"] = False, "upstream_error"
            if not (r.ok and st["ok"]):
                continue
            doc = self._doc(r)
            if doc is None or not isinstance(doc.get("deleted"), dict):
                st["ok"], st["error"] = False, "bad_response"
                continue
            matched += int(doc.get("matched_tests") or 0)
            for k in total:
                total[k] += int(doc["deleted"].get(k) or 0)
            key_matched = key_matched or bool(doc.get("device_key_matched"))
            per.append({"collector_id": r.collector_id, "matched_tests": doc.get("matched_tests", 0)})
        # dashboard-side audit: who, what kind, a hash prefix of the subject (never the identifier), result
        actor = re.sub(r"[^A-Za-z0-9@._-]", "?", user)[:64]
        log.info("speedtest purge by=%s subject=sha256:%s actor=%s dry_run=%s matched=%d",
                 by, hashlib.sha256(value.encode()).hexdigest()[:12], actor, dry, matched)
        out = {"dry_run": dry, "matched_tests": matched, "deleted": total, "device_key_matched": key_matched,
               "per_collector": per, "collectors": statuses, "partial": any(not s["ok"] for s in statuses)}
        return 200, json.dumps(out, separators=(",", ":")).encode(), {}
