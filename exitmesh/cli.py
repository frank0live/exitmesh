"""exitmesh — command line control for the ExitMesh panel and router."""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

DEFAULT_DB = os.environ.get("EXITMESH_DB", "/var/lib/exitmesh/exitmesh.db")
DEFAULT_URL = os.environ.get("EXITMESH_URL", "http://127.0.0.1:8099")
COOKIE = os.path.expanduser("~/.exitmesh-cookie")


def _req(url, data=None, cookie=None, method=None):
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method or ("POST" if body else "GET"))
    r.add_header("Content-Type", "application/json")
    if cookie:
        r.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            raw = resp.read().decode()
            setc = resp.headers.get("Set-Cookie") or ""
            return json.loads(raw or "{}"), setc
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode()), ""
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}"}, ""
    except Exception as e:
        return {"ok": False, "error": str(e)}, ""


def login(password):
    j, setc = _req(DEFAULT_URL + "/api/login", {"password": password})
    if not j.get("ok"):
        print("login failed:", j.get("error"))
        sys.exit(1)
    tok = setc.split("em_sess=")[1].split(";")[0] if "em_sess=" in setc else ""
    with open(COOKIE, "w") as f:
        f.write("em_sess=" + tok)
    os.chmod(COOKIE, 0o600)
    print("signed in")


def cookie():
    if os.path.exists(COOKIE):
        return open(COOKIE).read().strip()
    return ""


def fmt_b(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def cmd_list(args):
    j, _ = _req(DEFAULT_URL + "/api/status", cookie=cookie())
    if not j.get("ok"):
        print(j.get("error", "failed")); return 1
    ex = j["exits"]
    if not ex:
        print("no exits configured"); return 0
    print(f"{'NAME':<18} {'TYPE':<8} {'STATE':<10} {'LAT':>7} {'EXIT IP':<16} "
          f"{'UP':>8} {'DOWN':>8}  WEIGHT")
    print("-" * 92)
    for e in ex:
        h = e["health"]
        state = "disabled" if not e["enabled"] else ("up" if h["ok"] else "down")
        lat = f"{h['latency_ms']}ms" if h.get("latency_ms") is not None else "-"
        print(f"{e['name'][:17]:<18} {e['kind']:<8} {state:<10} {lat:>7} "
              f"{(h.get('exit_ip') or '-'):<16} "
              f"{fmt_b(e['traffic']['up']):>8} {fmt_b(e['traffic']['down']):>8}  {e['weight']}")
    print(f"\nrouter  {j['router']['listen']}:{j['router']['port']}   "
          f"active  {j.get('active_exit') or '-'}")
    return 0


def cmd_add(args):
    payload = {"name": args.name, "weight": args.weight}
    if args.link:
        payload["link"] = args.link
    if args.endpoint:
        payload["endpoint"] = args.endpoint
    j, _ = _req(DEFAULT_URL + "/api/exits", payload, cookie=cookie())
    print("added" if j.get("ok") else j.get("error"))
    return 0 if j.get("ok") else 1


def cmd_rm(args):
    j, _ = _req(f"{DEFAULT_URL}/api/exits/{args.name}", cookie=cookie(), method="DELETE")
    print("deleted" if j.get("ok") else j.get("error"))
    return 0 if j.get("ok") else 1


def cmd_act(args):
    j, _ = _req(f"{DEFAULT_URL}/api/exits/{args.name}/{args.action}", {}, cookie=cookie())
    print(json.dumps(j, indent=1, ensure_ascii=False))
    return 0 if j.get("ok") else 1


def cmd_probe(args):
    if args.name:
        j, _ = _req(f"{DEFAULT_URL}/api/exits/{args.name}/probe", {}, cookie=cookie())
        r = j.get("result", {})
        print(f"{args.name}: {'ok' if r.get('ok') else 'fail'} "
              f"{r.get('latency_ms','')}ms {r.get('exit_ip','')} {r.get('country','')} {r.get('error','')}")
    else:
        j, _ = _req(DEFAULT_URL + "/api/probe", {}, cookie=cookie())
        for k, r in (j.get("results") or {}).items():
            print(f"{k:<18} {'ok' if r.get('ok') else 'fail':<5} "
                  f"{str(r.get('latency_ms') or '-'):>6}ms  {r.get('exit_ip') or '-'}")
    return 0


def cmd_rules(args):
    if args.file:
        with open(args.file) as f:
            data = json.load(f)
        rules = data["rules"] if isinstance(data, dict) else data
        j, _ = _req(DEFAULT_URL + "/api/rules", {"rules": rules}, cookie=cookie())
        print("saved" if j.get("ok") else j.get("error"))
        return 0 if j.get("ok") else 1
    j, _ = _req(DEFAULT_URL + "/api/rules", cookie=cookie())
    print(json.dumps(j.get("rules", []), indent=2, ensure_ascii=False))
    return 0


def cmd_export(args):
    j, _ = _req(DEFAULT_URL + "/api/status", cookie=cookie())
    print(json.dumps(j, indent=2, ensure_ascii=False))
    return 0


def cmd_url(args):
    print(DEFAULT_URL)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="exitmesh", description="ExitMesh control CLI")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("login", help="authenticate and cache a session cookie")
    s.add_argument("password", nargs="?", help="omit to be prompted")
    s.set_defaults(fn=lambda a: (login(a.password or input("password: ")), 0)[1])

    s = sub.add_parser("list", help="show exits, health, traffic")
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("add", help="add an exit")
    s.add_argument("name")
    s.add_argument("--link", help="vless:// vmess:// trojan:// ss://")
    s.add_argument("--endpoint", help="host:port of an upstream socks5 proxy")
    s.add_argument("--weight", type=int, default=100)
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("rm", help="delete an exit")
    s.add_argument("name")
    s.set_defaults(fn=cmd_rm)

    s = sub.add_parser("probe", help="probe one or all exits")
    s.add_argument("name", nargs="?")
    s.set_defaults(fn=cmd_probe)

    s = sub.add_parser("start", help="enable an exit")
    s.add_argument("name"); s.set_defaults(fn=cmd_act, action="toggle")
    s = sub.add_parser("stop", help="disable an exit")
    s.add_argument("name"); s.set_defaults(fn=cmd_act, action="toggle")
    s = sub.add_parser("restart", help="restart an xray-backed exit")
    s.add_argument("name"); s.set_defaults(fn=cmd_act, action="restart")

    s = sub.add_parser("rules", help="show or replace routing rules")
    s.add_argument("--file", help="JSON file with rules")
    s.set_defaults(fn=cmd_rules)

    s = sub.add_parser("export", help="dump full status as JSON")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("url", help="print the panel URL")
    s.set_defaults(fn=cmd_url)

    s = sub.add_parser("logs", help="tail the panel journal")
    s.set_defaults(fn=lambda a: subprocess.call(
        ["journalctl", "-u", "exitmesh-panel", "-n", "80", "--no-pager"]))

    s = sub.add_parser("status", help="systemd status of panel + router")
    s.set_defaults(fn=lambda a: subprocess.call(
        ["systemctl", "status", "exitmesh-panel", "--no-pager", "-n", "12"]))

    args = p.parse_args(argv)
    if not getattr(args, "fn", None):
        p.print_help()
        return 1
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
