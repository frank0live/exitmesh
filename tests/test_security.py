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


def test_installer_verifies_checksum():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sh = open(os.path.join(here, "install.sh")).read()
    assert ".dgst" in sh
    assert "SHA2-256" in sh
    assert "checksum mismatch" in sh
    # must abort rather than continue on a bad checksum
    assert "refusing to install" in sh
