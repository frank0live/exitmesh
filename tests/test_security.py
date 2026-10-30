"""Security regression tests for the reported vulnerabilities."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --------------------------------------------------- security regressions
# Every test below corresponds to a reported vulnerability. They are written to
# fail loudly if the fix is ever reverted, not to exercise happy paths.

def test_exit_id_rejects_traversal():
    from exitmesh.store import safe_exit_id
    for hostile in ["../../x", "..", ".", "/etc/passwd", "a/b", "..\\..\\x",
                    "....//x", "   ", "", None]:
        eid = safe_exit_id(hostile)
        assert "/" not in eid and "\\" not in eid, (hostile, eid)
        assert eid not in (".", ".."), (hostile, eid)
        assert eid, hostile
    # A hostile name must not produce a path outside the config dir.
    import posixpath
    base = "/etc/exitmesh/xray"
    for hostile in ["../../x", "/etc/passwd", "a/b", ".."]:
        p = posixpath.join(base, safe_exit_id(hostile) + ".json")
        assert posixpath.dirname(p) == base, (hostile, p)


def test_exit_id_is_stable_and_readable():
    from exitmesh.store import safe_exit_id
    assert safe_exit_id("Tokyo 1") == "tokyo-1"
    assert safe_exit_id("  DE-Nuremberg ") == "de-nuremberg"
    assert safe_exit_id("US West (2)") == "us-west-2"


def test_conf_path_refuses_traversal_row():
    """A row that predates sanitisation must still not escape the dir."""
    from exitmesh.xray import XraySupervisor
    d = tempfile.mkdtemp()
    try:
        m = XraySupervisor(binary="/bin/true", conf_dir=d, store=None)
        for hostile in ["../../etc/passwd", "/etc/passwd", "..", "a/b", ""]:
            try:
                m.conf_path(hostile)
            except (ValueError, Exception) as e:
                assert "unsafe" in str(e) or "outside" in str(e), (hostile, e)
            else:
                raise AssertionError("conf_path accepted %r" % hostile)
        # and the normal case still works
        assert m.conf_path("tokyo-1").startswith(d)
    finally:
        import shutil; shutil.rmtree(d, ignore_errors=True)


def test_panel_rejects_public_router_bind():
    """The API must refuse 0.0.0.0 before the value is persisted."""
    import inspect
    from exitmesh import panel as P
    src = inspect.getsource(P.Handler.api_set_settings)
    assert "is_loopback" in src and "allow_public_listen" in src
    assert "router_listen" in src


def test_loopback_detection():
    from exitmesh.socks import is_loopback
    assert is_loopback("127.0.0.1")
    assert is_loopback("127.0.0.53")
    assert is_loopback("::1")
    assert is_loopback("localhost")
    assert not is_loopback("0.0.0.0")
    assert not is_loopback("192.168.1.5")
    assert not is_loopback("")


def test_public_socks_bind_requires_optin():
    """Router.start must refuse a public bind unless the env flag is set."""
    import asyncio as aio
    from exitmesh.socks import Router

    async def run():
        r = Router(store=None, selector=None, listen="0.0.0.0", port=0)
        try:
            await r.start()
        except RuntimeError as e:
            assert "refusing to bind" in str(e), e
        else:
            raise AssertionError("public bind was allowed without opt-in")
    aio.run(run())


def test_https_detection_for_cookie_flag():
    import inspect
    from exitmesh import panel as P
    src = inspect.getsource(P.Handler._send)
    assert "Set-Cookie" in src or "set-cookie" in src
    assert "Secure" in src
    hsrc = inspect.getsource(P.Handler._is_https)
    assert "X-Forwarded-Proto" in hsrc


def test_password_not_logged_and_file_is_0600():
    """The startup path must not print the secret; it writes a 0600 file."""
    import inspect
    from exitmesh import panel as P
    src = inspect.getsource(P.serve)
    assert "initial admin password: {pw}" not in src
    assert "EXITMESH_PASSWORD_FILE" in src
    assert "0o600" in src


def test_web_has_no_onclick_with_exit_id():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html = open(os.path.join(here, "web", "index.html")).read()
    assert "onclick=\"probe(" not in html
    assert "onclick=\"delExit(" not in html
    assert "data-act=" in html
    assert "data-eid=" in html


def test_private_ranges_are_blackholed():
    """The 'direct' fallback must not reach LAN/loopback/metadata addresses."""
    from exitmesh.xray import build_config, parse_link
    link = ("vless://11111111-2222-3333-4444-555555555555@example.com:443"
            "?type=tcp&security=tls#t")
    cfg = build_config(parse_link(link), 20199)
    rules = cfg["routing"]["rules"]
    assert rules, "no routing rules: the direct outbound is unrestricted"
    blocked = set()
    for r in rules:
        if r.get("outboundTag") == "block":
            blocked.update(r.get("ip") or [])
    for net in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                "::1/128", "fc00::/7", "fe80::/10"]:
        assert net in blocked, "missing block rule for %s" % net
    # and the block rule must not be shadowed by an earlier catch-all
    for r in rules:
        if r is rules[-1] or r.get("outboundTag") == "block":
            continue
        assert not (r.get("network") and not r.get("ip") and not r.get("domain")), \
            "a catch-all rule precedes the private-range block"


def test_installer_verifies_checksum():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sh = open(os.path.join(here, "install.sh")).read()
    assert ".dgst" in sh
    assert "SHA2-256" in sh
    assert "checksum mismatch" in sh
    # must abort rather than continue on a bad checksum
    assert "refusing to install" in sh


# ------------------------------------------- rule + audit claims in the README

def test_client_rule_accepts_cidr_and_glob():
    """The README documents `client` as CIDR-or-glob; both must really work."""
    from exitmesh.selector import _client_match
    # CIDR
    assert _client_match("10.1.2.3", "10.0.0.0/8")
    assert _client_match("192.168.1.5", "192.168.1.0/24")
    assert not _client_match("192.168.2.5", "192.168.1.0/24")
    assert _client_match("fd00::1", "fd00::/8")
    assert not _client_match("fe80::1", "fd00::/8")
    # glob
    assert _client_match("192.168.1.5", "192.168.1.*")
    assert not _client_match("10.0.0.1", "192.168.1.*")
    # exact
    assert _client_match("127.0.0.1", "127.0.0.1")
    assert not _client_match("127.0.0.2", "127.0.0.1")
    # garbage must not raise
    assert not _client_match("not-an-ip", "10.0.0.0/8")


def test_client_cidr_rule_routes_through_selector():
    """End-to-end: a CIDR client rule actually steers the pick."""
    import os as _os, tempfile as _tf
    from exitmesh.selector import Selector
    from exitmesh.store import Store
    with _tf.TemporaryDirectory() as d:
        s = Store(_os.path.join(d, "t.db"))
        a = s.add_exit("a", "socks5", endpoint="1.1.1.1:1080")
        b = s.add_exit("b", "socks5", endpoint="2.2.2.2:1080")
        s.record_health(a, True, 10, "1.1.1.1")
        s.record_health(b, True, 10, "2.2.2.2")
        s.set_rules({"rules": [
            {"match": {"client": "10.0.0.0/8"}, "exit": b},
            {"match": {"default": True}, "exit": a},
        ]})
        sel = Selector(s)
        assert sel.pick(("10.5.5.5", 1), "example.com", 443)["id"] == b
        assert sel.pick(("8.8.8.8", 1), "example.com", 443)["id"] == a


def test_breaker_trip_is_written_to_the_audit_log():
    """The README claims breaker trips land in the audit table."""
    from exitmesh.selector import Breaker
    trips = []
    br = Breaker(threshold=2, on_trip=lambda eid, fails, backoff: trips.append((eid, fails, backoff)))
    br.record("x", False)
    assert trips == [], "a trip below the threshold must not be reported"
    br.record("x", False)
    assert len(trips) == 1, "the trip was not reported once"
    assert trips[0][0] == "x" and trips[0][1] == 2
    # repeated failures while open must not spam the log
    br.record("x", False)
    br.record("x", False)
    assert len(trips) == 1, "trip reported more than once per opening"
    # a success closes it and arms the next report
    br.record("x", True, 20)
    br.record("x", False)
    br.record("x", False)
    assert len(trips) == 2, "a re-opened breaker must be reported again"


def test_panel_wires_the_breaker_callback():
    """App must connect Breaker.on_trip, or nothing reaches the audit table."""
    import inspect as _i
    from exitmesh import panel as P
    src = _i.getsource(P.App.__init__)
    assert "on_trip=" in src
    assert "_log_breaker_trip" in _i.getsource(P.App)


def test_readme_client_rule_claim_is_true():
    """Guard the documented `client` semantics against the implementation."""
    import inspect as _i
    from exitmesh.selector import _client_match
    src = _i.getsource(_client_match)
    assert "ipaddress" in src or "ip_network" in src, \
        "README says `client` takes CIDR, but the matcher has no CIDR support"


def test_shipped_service_sample_is_hardened():
    """The committed unit must not contradict the security section.

    It used to ship `User=root` + `ProtectSystem=full`, which is the opposite of
    what the README documents and what install.sh writes.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    unit = open(os.path.join(here, "systemd", "exitmesh-panel.service")).read()
    assert "User=root" not in unit, "the sample unit still runs as root"
    for directive in ("NoNewPrivileges=yes", "PrivateTmp=yes", "PrivateDevices=yes",
                      "ProtectSystem=strict", "ProtectHome=yes",
                      "RestrictSUIDSGID=yes", "RestrictNamespaces=yes",
                      "LockPersonality=yes",
                      "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"):
        assert directive in unit, "sample unit is missing %s" % directive
    # and it must agree with the unit the installer actually writes
    sh = open(os.path.join(here, "install.sh")).read()
    for directive in ("ProtectSystem=strict", "PrivateDevices=yes", "ProtectHome=yes",
                      "LockPersonality=yes"):
        assert directive in sh, "installer unit is missing %s" % directive


def test_exploit_check_is_path_independent():
    """It must run from a clone at any path, and clean up after itself."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(here, "tests", "exploit_check.py")).read()
    assert "/root/exitmesh" not in src, "exploit_check.py hardcodes a dev path"
    assert "atexit" in src, "no cleanup hook: a failed run would orphan a listener"


def test_documented_test_command_runs_the_whole_suite():
    """README says `python3 tests/test_exitmesh.py`; it must include security."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    main = open(os.path.join(here, "tests", "test_exitmesh.py")).read()
    sec = open(os.path.join(here, "tests", "test_security.py")).read()
    assert "test_security" in main, \
        "the documented single command silently skips the security regressions"
    assert "__main__" in sec, "test_security.py has no standalone entry point"


if __name__ == "__main__":
    import types
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and isinstance(f, types.FunctionType)]
    ok = fail = 0
    for name, fn in fns:
        try:
            fn()
            print(f"  PASS  {name}")
            ok += 1
        except Exception as e:
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
            fail += 1
    print(f"\n{ok} passed, {fail} failed")
    sys.exit(1 if fail else 0)
