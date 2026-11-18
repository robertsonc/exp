"""Guards for the ``query_range`` proxy (01-contracts.md section 5, 07-security.md).

The dashboard may only read the ``exp_*`` series. MetricsQL is a rich language, so instead of trying to
understand all of it the guard is a *conservative allow-list parser*: it tokenizes the query with a
small fixed grammar and refuses anything it does not positively recognise (non-ASCII, comments,
backslash escapes, ``WITH`` templates, a selector without an ``exp_`` metric name, any use of
``__name__`` except ``__name__="exp_..."``, a bare identifier that is not an ``exp_`` metric, a function
call or a known keyword in a legitimate position).

``check_query`` raises ``QueryRefused`` (-> HTTP 400 ``invalid_query``); ``parse_*`` helpers validate the
time parameters.
"""
from __future__ import annotations

import re

MAX_QUERY_BYTES = 2048
MAX_RANGE_S = 30 * 86400
MIN_STEP_S = 10
MAX_POINTS = 11_000          # points per series: keeps the answer (<= 500 series) inside a few MiB
METRIC_RE = re.compile(r"exp_[A-Za-z0-9_:]*\Z")

_IDENT = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")
_NUMBER = re.compile(r"[0-9.][0-9A-Za-z_.]*")      # literal (1, 1e3, 0x1f, 5m, 1.5Ki): selects nothing
_DURATION_BODY = re.compile(r"[0-9smhdwyi:. ]*\Z")
_OPS = ("==", "!=", "<=", ">=", "=~", "!~", "+", "-", "*", "/", "%", "^", "<", ">", "=", "@", ",")
_SPACE = " \t\r\n"

LABEL_KEYWORDS = frozenset({"by", "without", "on", "ignoring", "group_left", "group_right"})
BINARY_KEYWORDS = frozenset({"and", "or", "unless", "if", "ifnot", "default", "atan2"})
CONSTANTS = frozenset({"inf", "nan", "Inf", "NaN", "INF", "NAN"})
_VALUE_END = frozenset({")", "]", "}", "num", "str", "metric"})
_ARITH = frozenset({"+", "-", "*", "/", "%", "^", "==", "!=", "<", ">", "<=", ">=", "atan2"})


class QueryRefused(ValueError):
    """The query is not allowed. The message is safe to show to the caller."""


def _tokenize(q: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    i, n = 0, len(q)
    while i < n:
        c = q[i]
        if c in _SPACE:
            i += 1
            continue
        if c in "\"'`":
            j = i + 1
            while j < n and q[j] != c:
                if q[j] == "\\" and c != "`":
                    j += 1
                j += 1
            if j >= n:
                raise QueryRefused("unterminated string")
            toks.append(("str", q[i + 1:j]))
            i = j + 1
            continue
        if c == "[":
            j = q.find("]", i)
            if j < 0 or not _DURATION_BODY.match(q[i + 1:j]):
                raise QueryRefused("unsupported range or subquery syntax")
            toks.append(("[", "["))
            toks.append(("dur", q[i + 1:j]))
            toks.append(("]", "]"))
            i = j + 1
            continue
        if c in "(){}":
            toks.append((c, c))
            i += 1
            continue
        if c.isdigit() or (c == "." and i + 1 < n and q[i + 1].isdigit()):
            m = _NUMBER.match(q, i)
            end = m.end() if m else i + 1
            toks.append(("num", q[i:end]))
            i = end
            continue
        m2 = _IDENT.match(q, i)
        if m2 is not None:
            toks.append(("id", m2.group(0)))
            i = m2.end()
            continue
        for op in _OPS:
            if q.startswith(op, i):
                toks.append((op, op))
                i += len(op)
                break
        else:
            raise QueryRefused(f"unsupported character {c!r}" if c.isprintable() and c.isascii()
                               else "unsupported character")
    return toks


def _check_selector(toks: list[tuple[str, str]], i: int) -> tuple[int, bool]:
    """`toks[i]` is `{`. Returns (index after the matching `}`, whether it pins `__name__="exp_..."`)."""
    j = i + 1
    group_pinned, all_pinned = False, True
    expect_label = True
    while j < len(toks):
        kind, val = toks[j]
        if kind == "}":
            return j + 1, all_pinned and group_pinned
        if kind == "," or (kind == "id" and val == "or" and not expect_label):
            if kind == "id":                      # `or` starts a new filter group: each must pin the name
                all_pinned = all_pinned and group_pinned
                group_pinned = False
            expect_label = True
            j += 1
            continue
        if not expect_label or kind != "id":
            raise QueryRefused("unsupported label matcher")
        if j + 2 >= len(toks) or toks[j + 1][0] not in ("=", "!=", "=~", "!~") or toks[j + 2][0] != "str":
            raise QueryRefused("unsupported label matcher")
        op, value = toks[j + 1][0], toks[j + 2][1]
        if val == "__name__":
            if op != "=" or not METRIC_RE.match(value):
                raise QueryRefused("only exp_* metric names may be queried")
            group_pinned = True
        elif val.startswith("__") and val not in ("__name__",):
            raise QueryRefused("reserved labels may not be matched")
        expect_label = False
        j += 3
    raise QueryRefused("unterminated selector")


def check_query(q: str) -> None:
    """Raise QueryRefused unless `q` provably reads only ``exp_*`` series."""
    if not isinstance(q, str) or not q.strip():
        raise QueryRefused("query is empty")
    if len(q.encode("utf-8", "replace")) > MAX_QUERY_BYTES:
        raise QueryRefused(f"query is longer than {MAX_QUERY_BYTES} bytes")
    if not q.isascii() or any(ord(ch) < 32 and ch not in _SPACE for ch in q) or "\x7f" in q:
        raise QueryRefused("query must be printable ASCII")
    if "#" in re.sub(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`[^`]*`)", "", q):
        raise QueryRefused("comments are not allowed")
    toks = _tokenize(q)
    kinds: list[str] = []          # "kind of the previous significant token" for position checks
    i, depth = 0, 0
    while i < len(toks):
        kind, val = toks[i]
        prev = kinds[-1] if kinds else ""
        nxt = toks[i + 1][0] if i + 1 < len(toks) else ""
        nxt2 = toks[i + 2][0] if i + 2 < len(toks) else ""
        if kind == "{":
            # a selector must hang off an exp_ metric name, or pin __name__ itself
            end, pinned = _check_selector(toks, i)
            if not (prev == "metric" or pinned):
                raise QueryRefused("every selector needs an exp_* metric name")
            kinds.append("}")
            i = end
            continue
        if kind in "()":
            depth += 1 if kind == "(" else -1
            if depth < 0:
                raise QueryRefused("unbalanced parentheses")
            kinds.append(kind)
            i += 1
            continue
        if kind == "id":
            if val == "with":
                raise QueryRefused("WITH templates are not allowed")
            if val in LABEL_KEYWORDS:
                if nxt != "(":
                    raise QueryRefused(f"unexpected {val!r}")
                j = i + 2                      # label list: identifiers and commas only
                while j < len(toks) and toks[j][0] != ")":
                    if toks[j][0] not in ("id", ",") and not (toks[j][0] == "str"):
                        raise QueryRefused("unsupported label list")
                    j += 1
                if j >= len(toks):
                    raise QueryRefused("unbalanced parentheses")
                kinds.append(")")
                i = j + 1
                continue
            if nxt == "(" or (nxt == "id" and toks[i + 1][1] in ("by", "without") and nxt2 == "("):
                kinds.append("func")           # function / aggregation name
                i += 1
                continue
            if val in BINARY_KEYWORDS:
                if prev not in _VALUE_END:
                    raise QueryRefused(f"unexpected {val!r}")
                kinds.append("atan2" if val == "atan2" else "binop")
                i += 1
                continue
            if val == "bool":
                if prev not in _ARITH:
                    raise QueryRefused("unexpected 'bool'")
                kinds.append("binop")
                i += 1
                continue
            if val == "offset":
                if prev not in _VALUE_END:
                    raise QueryRefused("unexpected 'offset'")
                kinds.append("offset")
                i += 1
                continue
            if val == "keep_metric_names":
                if prev != ")":
                    raise QueryRefused("unexpected 'keep_metric_names'")
                kinds.append("kmn")
                i += 1
                continue
            if val in CONSTANTS:
                kinds.append("num")
                i += 1
                continue
            if not METRIC_RE.match(val):
                raise QueryRefused("only exp_* metric names may be queried")
            kinds.append("metric")
            i += 1
            continue
        if kind == "str":
            kinds.append("str")
        elif kind == "num":
            kinds.append("num")
        elif kind == "dur":
            kinds.append("dur")
        elif kind in ("[", "]"):
            kinds.append(kind)
        else:
            kinds.append(kind)                 # operators and commas
        i += 1
    if depth != 0:
        raise QueryRefused("unbalanced parentheses")


# ----------------------------------------------------------------------------- time parameters
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z")
_EPOCH = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,3})?\Z")
_STEP = re.compile(r"([0-9]{1,9})(s|m|h)?\Z")


def parse_time_s(raw: str) -> float:
    """ISO-8601 Z timestamp or epoch seconds -> epoch seconds."""
    from exp_common import schema as exp_schema
    if _EPOCH.match(raw):
        return float(raw)
    if _TS.match(raw):
        try:
            return exp_schema.iso_to_ms(raw) / 1000.0
        except ValueError:
            pass
    raise ValueError("not a timestamp")


def parse_step_s(raw: str) -> int:
    m = _STEP.match(raw)
    if m is None:
        raise ValueError("not a step")
    mult = {None: 1, "s": 1, "m": 60, "h": 3600}[m.group(2)]
    return int(m.group(1)) * mult
