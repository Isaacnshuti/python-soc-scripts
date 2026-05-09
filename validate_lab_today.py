#!/usr/bin/env python3
"""
Run and verify all cybersecurity scripts in a safe lab setup.

Produces:
  - lab_test_results_2026-05-08.json
  - lab_test_logs_2026-05-08/*.log

This validator is intended for authorized virtual lab environments only.
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).parent
DATE_TAG = "2026-05-08"
LOG_DIR = BASE / f"lab_test_logs_{DATE_TAG}"
RESULT_JSON = BASE / f"lab_test_results_{DATE_TAG}.json"


def run_cmd(name: str, cmd: list[str], log_path: Path) -> dict:
    start = time.time()
    proc = subprocess.run(
        cmd,
        cwd=BASE,
        text=True,
        capture_output=True,
        check=False,
    )
    elapsed = round(time.time() - start, 3)
    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    log_path.write_text(output)
    return {
        "name": name,
        "command": " ".join(cmd),
        "return_code": proc.returncode,
        "duration_sec": elapsed,
        "log_file": str(log_path.name),
        "status": "PASS" if proc.returncode == 0 else "FAIL",
    }


def read_json_summary(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    try:
        data = json.loads(path.read_text())
    except Exception as exc:  # pragma: no cover
        return {"exists": True, "json_ok": False, "error": str(exc)}

    summary = {"exists": True, "json_ok": True}
    if isinstance(data, dict):
        summary["top_level_keys"] = list(data.keys())[:10]
        if "alerts" in data and isinstance(data["alerts"], list):
            summary["alerts"] = len(data["alerts"])
        if "findings" in data and isinstance(data["findings"], list):
            summary["findings"] = len(data["findings"])
        if "events" in data and isinstance(data["events"], list):
            summary["events"] = len(data["events"])
        if "total_alerts" in data:
            summary["total_alerts"] = data["total_alerts"]
        if "count" in data:
            summary["count"] = data["count"]
    elif isinstance(data, list):
        summary["type"] = "list"
        summary["items"] = len(data)
    else:
        summary["type"] = type(data).__name__
    return summary


def main() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()

    outputs = {
        "out_01": BASE / f"lab_out_01_breach_report_{DATE_TAG}.json",
        "out_02": BASE / f"lab_out_02_win_findings_{DATE_TAG}.json",
        "out_03": BASE / f"lab_out_03_net_alerts_{DATE_TAG}.json",
        "out_04_html": BASE / f"lab_out_04_triage_{DATE_TAG}.html",
        "out_04_json": BASE / f"lab_out_04_incidents_{DATE_TAG}.json",
        "out_05": BASE / f"lab_out_05_phish_report_{DATE_TAG}.json",
        "out_06_db": BASE / f"lab_out_06_siem_{DATE_TAG}.db",
        "out_06_json": BASE / f"lab_out_06_siem_alerts_{DATE_TAG}.json",
    }

    # Clean prior run artifacts for deterministic results.
    for p in outputs.values():
        if p.exists():
            if p.is_file():
                p.unlink()

    tests = [
        (
            "script_01_breach_detector",
            [
                "python3",
                "01_log_breach_detector.py",
                "--log",
                "sample_auth.log",
                "--threshold",
                "5",
                "--output",
                str(outputs["out_01"].name),
            ],
        ),
        (
            "script_02_windows_event_analyzer",
            [
                "python3",
                "02_win_event_analyzer.py",
                "--demo",
                "--severity",
                "LOW",
                "--output",
                str(outputs["out_02"].name),
            ],
        ),
        (
            "script_03_network_analyzer",
            [
                "python3",
                "03_net_analyzer.py",
                "--demo",
                "--output",
                str(outputs["out_03"].name),
            ],
        ),
        (
            "script_04_alert_triage",
            [
                "python3",
                "04_alert_triage.py",
                "--alerts",
                "sample_alerts.json",
                "--top",
                "5",
                "--html",
                str(outputs["out_04_html"].name),
                "--json-out",
                str(outputs["out_04_json"].name),
            ],
        ),
        (
            "script_05_phish_detector",
            [
                "python3",
                "05_phish_detector.py",
                "--dir",
                ".",
                "--output",
                str(outputs["out_05"].name),
            ],
        ),
        (
            "script_06_siem_ingest_syslog",
            [
                "python3",
                "06_siem.py",
                "--log",
                "sample_auth.log",
                "--source",
                "syslog",
                "--db",
                str(outputs["out_06_db"].name),
            ],
        ),
        (
            "script_06_siem_ingest_apache",
            [
                "python3",
                "06_siem.py",
                "--log",
                "sample_apache.log",
                "--source",
                "apache",
                "--db",
                str(outputs["out_06_db"].name),
            ],
        ),
        (
            "script_06_siem_dashboard_export",
            [
                "python3",
                "06_siem.py",
                "--dashboard",
                "--export",
                str(outputs["out_06_json"].name),
                "--db",
                str(outputs["out_06_db"].name),
            ],
        ),
    ]

    run_results = []
    for name, cmd in tests:
        log_path = LOG_DIR / f"{name}.log"
        run_results.append(run_cmd(name=name, cmd=cmd, log_path=log_path))

    pass_count = sum(1 for r in run_results if r["status"] == "PASS")
    fail_count = len(run_results) - pass_count

    output_checks = {
        key: read_json_summary(path)
        for key, path in outputs.items()
        if path.suffix == ".json"
    }
    output_checks["out_04_html"] = {
        "exists": outputs["out_04_html"].exists(),
        "bytes": outputs["out_04_html"].stat().st_size if outputs["out_04_html"].exists() else 0,
    }
    output_checks["out_06_db"] = {
        "exists": outputs["out_06_db"].exists(),
        "bytes": outputs["out_06_db"].stat().st_size if outputs["out_06_db"].exists() else 0,
    }

    report = {
        "generated_at_utc": stamp,
        "environment": {
            "base_dir": str(BASE),
            "authorized_lab_only": True,
        },
        "summary": {
            "tests_total": len(run_results),
            "pass": pass_count,
            "fail": fail_count,
        },
        "runs": run_results,
        "artifacts": {k: str(v.name) for k, v in outputs.items()},
        "artifact_checks": output_checks,
        "notes": [
            "Tool 02 and Tool 03 were tested in demo mode for safe/offline lab validation.",
            "Tool 06 was validated through two ingestion steps plus dashboard/export.",
            "All commands were executed locally in a controlled learning environment.",
        ],
    }

    RESULT_JSON.write_text(json.dumps(report, indent=2))
    print(f"[+] Validation report written: {RESULT_JSON.name}")
    print(f"[+] Logs directory: {LOG_DIR.name}")
    print(f"[+] Pass/Fail: {pass_count}/{len(run_results)}")


if __name__ == "__main__":
    main()
