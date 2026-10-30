"""Exit selection: rules first, then health-weighted ranking, then stickiness.

Scoring
-------
    score = weight
            * health_factor          (1.0 healthy, 0.35 degraded, 0.0 dead)
            / (1 + latency_ms / 120)
            / (1 + failures_in_a_row * 0.5)

A dead exit never wins; a degraded one only wins if nothing healthy is left.
"""

import fnmatch
import ipaddress
import time


class Breaker:
    """In-memory circuit breaker per exit, fed by probes and live traffic."""

    def __init__(self, threshold=3, on_trip=None):
        self.threshold = threshold
        self.on_trip = on_trip     # optional callback(eid, fails, backoff)
        self._opened = {}          # eid -> ts of the last trip we reported
        self.state = {}   # eid -> {"fails": n, "until": ts, "latency": ms, "ok": bool}

    def record(self, eid, ok, latency=None):
        s = self.state.setdefault(eid, {"fails": 0, "until": 0, "latency": None, "ok": True})
        if ok:
            s["fails"] = 0
            s["ok"] = True
            s["until"] = 0
            if latency is not None:
                s["latency"] = latency
            self._opened.pop(eid, None)   # any success arms the next trip report
        else:
            s["fails"] += 1
            s["ok"] = False
            if s["fails"] >= self.threshold:
                backoff = min(300, 15 * (2 ** (s["fails"] - self.threshold)))
                s["until"] = time.time() + backoff
                # Report the trip exactly once per opening, not once per
                # failed probe, so the audit log stays readable.
                if eid not in self._opened:
                    self._opened[eid] = time.time()
                    if self.on_trip:
                        self.on_trip(eid, s["fails"], backoff)

    def get(self, eid):
        return self.state.get(eid, {"fails": 0, "until": 0, "latency": None, "ok": True})

    def is_open(self, eid):
        return self.get(eid)["until"] > time.time()

    def factor(self, eid):
        s = self.get(eid)
        if s["until"] > time.time():
            return 0.0
        if s["fails"] >= self.threshold:
            return 0.35
        if s["fails"] > 0:
            return 0.7
        return 1.0


def _client_match(client_ip, pattern):
    """Match a client address against a rule pattern.

    Accepts a bare glob (``192.168.1.*``), a CIDR network (``10.0.0.0/8`` or
    ``fd00::/8``) and an exact address.
    """
    if fnmatch.fnmatch(client_ip, pattern):
        return True
    if "/" in pattern:
        try:
            return ipaddress.ip_address(client_ip) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    return False


class Selector:
    def __init__(self, store, breaker=None, timeout: float = 8):
        self.store = store
        self.breaker = breaker or Breaker()
        self.timeout = timeout

    # ------------------------------------------------------------- ranking
    def ranked(self):
        exits = [e for e in self.store.list_exits() if e.get("enabled")]
        out = []
        for e in exits:
            eid = e["id"]
            h = self.store.last_health(eid) or {}
            latency = h.get("latency_ms") or self.breaker.get(eid)["latency"] or 400
            fails = self.store.consecutive_failures(eid)
            score = (
                max(1, int(e.get("weight") or 100))
                * self.breaker.factor(eid)
                / (1 + latency / 120.0)
                / (1 + fails * 0.5)
            )
            if not h and not self.breaker.get(eid)["latency"]:
                score *= 0.8          # never probed yet: slight penalty, still usable
            out.append({**e, "score": round(score, 3), "latency_ms": latency,
                        "fails": fails})
        out.sort(key=lambda x: x["score"], reverse=True)
        return out

    # --------------------------------------------------------------- rules
    def _rule_match(self, rule, host, port, peer):
        m = rule.get("match") or {}
        if m.get("default"):
            return True
        if "domain" in m:
            pat = str(m["domain"]).lower().lstrip(".")
            h = (host or "").lower()
            if not (h == pat or h.endswith("." + pat) or fnmatch.fnmatch(h, pat)):
                return False
        if "port" in m:
            ports = m["port"]
            ports = ports if isinstance(ports, list) else [ports]
            if int(port) not in [int(p) for p in ports]:
                return False
        if "client" in m:
            cip = peer[0] if isinstance(peer, tuple) else str(peer)
            if not _client_match(cip, str(m["client"])):
                return False
        return True

    def match_rule(self, host, port, peer):
        for rule in self.store.rules().get("rules", []):
            if self._rule_match(rule, host, port, peer):
                return rule
        return None

    # ---------------------------------------------------------------- pick
    def pick(self, peer, host, port, sticky=None):
        rule = self.match_rule(host, port, peer)
        action = (rule or {}).get("exit", "auto")

        if action == "block":
            return None
        if action == "direct":
            return {"id": "__direct__", "name": "direct", "kind": "direct",
                    "endpoint_host": None, "socks_port": 0, "score": 0}

        if action not in ("auto", None, ""):
            e = self.store.get_exit(action)
            if e and e.get("enabled") and not self.breaker.is_open(e["id"]):
                return {**e, "endpoint_host": _host_of(e), "score": 999}

        ranked = [e for e in self.ranked() if e["score"] > 0]
        if not ranked:
            return None

        if sticky:
            pinned = sticky.get(peer)
            if pinned:
                for e in ranked:
                    if e["id"] == pinned:
                        return {**e, "endpoint_host": _host_of(e)}
        best = ranked[0]
        return {**best, "endpoint_host": _host_of(best)}


def _host_of(exit_row):
    """For socks5 exits, endpoint is host:port of the proxy."""
    ep = exit_row.get("endpoint") or ""
    if ":" in ep:
        return ep.rsplit(":", 1)[0]
    return ep or "127.0.0.1"
