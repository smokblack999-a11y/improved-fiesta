#!/usr/bin/env python3
"""SAMURAI Incident Zero v0.2 - defensive incident evidence collector.

Read-only collection. It does not kill processes, alter firewall rules, delete files,
or attempt exploitation. Run it on systems you own or are authorized to investigate.
"""
import argparse, hashlib, json, os, platform, socket, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"
REPORTS = ROOT / "reports"
MAX_OUTPUT = 30000


def now():
    return datetime.now(timezone.utc).isoformat()


def run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"command": cmd, "returncode": p.returncode,
                "stdout": p.stdout[-MAX_OUTPUT:], "stderr": p.stderr[-8000:]}
    except Exception as e:
        return {"command": cmd, "error": str(e)}


def write_json(name, data):
    EVIDENCE.mkdir(exist_ok=True)
    p = EVIDENCE / name
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return p


def init():
    EVIDENCE.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True)
    write_json("case.json", {"created_at": now(), "hostname": socket.gethostname(),
                              "platform": platform.platform(), "collector_version": "0.2"})
    print(f"initialized {EVIDENCE}")


def collect():
    EVIDENCE.mkdir(exist_ok=True)
    commands = {
        "uname": ["uname", "-a"],
        "processes": ["ps", "-ef"],
        "network": ["ss", "-tunap"],
        "routes": ["ip", "route"],
        "listening": ["ss", "-lntup"],
        "auth": ["last", "-n", "50"],
        "failed_auth": ["lastb", "-n", "30"],
    }
    data = {"collected_at": now(), "host": socket.gethostname(),
            "platform": platform.platform(), "uid": os.getuid()}
    data["commands"] = {name: run(cmd) for name, cmd in commands.items()}
    # Metadata only: do not read arbitrary file contents.
    data["filesystem"] = run(["find", "/tmp", "-xdev", "-type", "f",
                               "-printf", "%TY-%Tm-%TdT%TH:%TM:%TS %p\\n"])
    write_json("collection.json", data)
    create_manifest()
    print("collected", len(commands) + 1, "datasets")


def create_manifest():
    manifest = {"algorithm": "sha256", "generated_at": now(), "files": {}}
    for p in sorted(EVIDENCE.glob("*.json")):
        if p.name == "manifest.json":
            continue
        manifest["files"][p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    write_json("manifest.json", manifest)


def timeline():
    p = EVIDENCE / "collection.json"
    if not p.exists(): raise SystemExit("run collect first")
    d = json.loads(p.read_text())
    events = [{"time": d["collected_at"], "type": "collection", "detail": "evidence collection completed"}]
    out = {"generated_at": now(), "events": events}
    write_json("timeline.json", out)
    print(f"timeline: {len(events)} event(s)")


def analyze():
    p = EVIDENCE / "collection.json"
    if not p.exists(): raise SystemExit("run collect first")
    c = json.loads(p.read_text())
    findings = []
    for name, result in c.get("commands", {}).items():
        if "error" in result or result.get("returncode") not in (0, None):
            findings.append({"severity": "info", "signal": f"collection_{name}_failed",
                             "detail": result.get("stderr") or result.get("error", "unknown")})
    # A collection failure is NOT evidence of compromise.
    risk = "unknown" if findings else "no_signal"
    write_json("analysis.json", {"generated_at": now(), "risk": risk,
                                  "findings": findings,
                                  "note": "No compromise is inferred from absence of findings; this is a collector, not a forensic verdict."})
    print("risk:", risk)


def report():
    a = json.loads((EVIDENCE / "analysis.json").read_text())
    r = REPORTS / "incident-report.json"
    r.write_text(json.dumps({"product": "SAMURAI Incident Zero", "version": "0.2",
                             "generated_at": now(), "analysis": a}, indent=2), encoding="utf-8")
    print(r)


def verify():
    m = json.loads((EVIDENCE / "manifest.json").read_text())
    bad = []
    for name, expected in m.get("files", {}).items():
        p = EVIDENCE / name
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            bad.append(name)
    print("VERIFIED" if not bad else "FAILED: " + ", ".join(bad))
    raise SystemExit(0 if not bad else 1)


parser = argparse.ArgumentParser(description="SAMURAI Incident Zero")
parser.add_argument("command", choices=["init", "collect", "timeline", "analyze", "report", "verify"])
args = parser.parse_args()
{"init": init, "collect": collect, "timeline": timeline, "analyze": analyze,
 "report": report, "verify": verify}[args.command]()
