#!/usr/bin/env python3
import argparse, hashlib, json, os, platform, socket, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"


def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return {"returncode": p.returncode, "stdout": p.stdout[-20000:], "stderr": p.stderr[-4000:]}
    except Exception as e:
        return {"error": str(e)}


def write_json(name, data):
    EVIDENCE.mkdir(exist_ok=True)
    p = EVIDENCE / name
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return p


def init():
    EVIDENCE.mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)
    write_json("case.json", {"created_at": time.time(), "hostname": socket.gethostname(), "platform": platform.platform()})
    print("initialized", EVIDENCE)


def collect():
    EVIDENCE.mkdir(exist_ok=True)
    data = {
        "collected_at": time.time(),
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "system": {"uname": run(["uname", "-a"])},
        "processes": run(["ps", "-ef"]),
        "network": run(["ss", "-tunap"]),
        "auth": run(["last", "-n", "30"]),
        "filesystem": run(["find", "/tmp", "-xdev", "-type", "f", "-printf", "%TY-%Tm-%TdT%TH:%TM:%TS %p\\n"]),
    }
    write_json("collection.json", data)
    manifest = {}
    for p in sorted(EVIDENCE.glob("*.json")):
        manifest[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    write_json("manifest.json", manifest)
    print("collected", len(data), "datasets")


def timeline():
    p = EVIDENCE / "collection.json"
    if not p.exists():
        raise SystemExit("run collect first")
    d = json.loads(p.read_text())
    events = [{"time": d["collected_at"], "type": "collection", "detail": "evidence collection completed"}]
    out = {"generated_at": time.time(), "events": events}
    write_json("timeline.json", out)
    print("timeline: 1 event")


def analyze():
    c = json.loads((EVIDENCE / "collection.json").read_text())
    findings = []
    if c["processes"].get("returncode") != 0:
        findings.append({"severity": "medium", "signal": "process_collection_failed"})
    if c["network"].get("returncode") != 0:
        findings.append({"severity": "medium", "signal": "network_collection_failed"})
    report = {"generated_at": time.time(), "risk": "low" if not findings else "medium", "findings": findings}
    write_json("analysis.json", report)
    print("risk:", report["risk"])


def report():
    a = json.loads((EVIDENCE / "analysis.json").read_text())
    r = ROOT / "reports" / "incident-report.json"
    r.write_text(json.dumps({"product": "SAMURAI Incident Zero", "version": "0.1", "analysis": a}, indent=2), encoding="utf-8")
    print(r)


def verify():
    m = json.loads((EVIDENCE / "manifest.json").read_text())
    bad = []
    for name, expected in m.items():
        p = EVIDENCE / name
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            bad.append(name)
    print("VERIFIED" if not bad else "FAILED: " + ", ".join(bad))
    raise SystemExit(0 if not bad else 1)


parser = argparse.ArgumentParser(description="SAMURAI Incident Zero")
parser.add_argument("command", choices=["init", "collect", "timeline", "analyze", "report", "verify"])
args = parser.parse_args()
{"init": init, "collect": collect, "timeline": timeline, "analyze": analyze, "report": report, "verify": verify}[args.command]()
