import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SZI = ROOT / "szi.py"


def run(*args):
    return subprocess.run([sys.executable, str(SZI), *args], cwd=ROOT, capture_output=True, text=True)


def test_cli_pipeline(tmp_path):
    # Run in repository because v0.1 stores evidence relative to szi.py.
    for p in (ROOT / "evidence").glob("*.json"):
        p.unlink()
    result = run("init")
    assert result.returncode == 0
    result = run("collect")
    assert result.returncode == 0
    assert (ROOT / "evidence/collection.json").exists()
    assert (ROOT / "evidence/manifest.json").exists()
    result = run("timeline")
    assert result.returncode == 0
    result = run("analyze")
    assert result.returncode == 0
    result = run("report")
    assert result.returncode == 0
    result = run("verify")
    assert result.returncode == 0


def test_manifest_detects_tampering():
    manifest = ROOT / "evidence/manifest.json"
    collection = ROOT / "evidence/collection.json"
    data = json.loads(manifest.read_text())
    original = collection.read_text()
    collection.write_text(original + "\nTAMPERED\n")
    try:
        result = run("verify")
        assert result.returncode != 0
    finally:
        collection.write_text(original)

    # Confirm the expected digest differs after tampering.
    assert hashlib.sha256(collection.read_bytes()).hexdigest() == data["collection.json"]
