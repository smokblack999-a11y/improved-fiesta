# SAMURAI Incident Zero

Defensive incident-response evidence collector for Linux and Termux.

## v0.1 goals

- Read-only collection
- SHA-256 evidence manifest
- Process/network/auth/filesystem metadata collection
- Deterministic JSON artifacts
- Timeline and basic risk scoring
- No exploit, persistence, deletion, or automatic remediation

## Quick start

```bash
python3 szi.py init
python3 szi.py collect
python3 szi.py timeline
python3 szi.py analyze
python3 szi.py report
python3 szi.py verify
```

Use only on systems you own or are authorized to investigate.
