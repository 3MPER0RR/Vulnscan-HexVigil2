#!/usr/bin/env python3
"""
nvd_lookup.py — Arricchisce i findings con CVE reali da NVD
Uso: python nvd_lookup.py --target <path> [--severity LEVEL]
"""

import argparse
import json
import time
import urllib.request
import urllib.parse
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from scanner.engine import scan
from scanner.rules import Severity

# ── Colori ─────────────────────────────────────────────────────────────────────
RED    = "\033[91m"
ORANGE = "\033[38;5;214m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH,
    Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


def fetch_cves(cwe_id: str, max_results: int = 5) -> list[dict]:
    """Interroga NVD e restituisce i CVE più recenti per un CWE."""
    params = urllib.parse.urlencode({
        "cweId":        cwe_id,
        "resultsPerPage": max_results,
        "startIndex":   0,
    })
    url = f"{NVD_API}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vulnscan/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data.get("vulnerabilities", [])
    except Exception as e:
        return []


def cvss_color(score: float) -> str:
    if score >= 9.0:  return RED
    if score >= 7.0:  return ORANGE
    if score >= 4.0:  return YELLOW
    return GREEN


def format_cve(vuln: dict) -> str:
    cve  = vuln.get("cve", {})
    cve_id = cve.get("id", "N/A")
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")[:120]
            break

    # CVSS score
    score = None
    severity_label = ""
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            score = m.get("cvssData", {}).get("baseScore")
            severity_label = m.get("cvssData", {}).get("baseSeverity", "")
            break

    score_str = ""
    if score is not None:
        color = cvss_color(float(score))
        score_str = f"{color}{BOLD}CVSS {score} ({severity_label}){RESET}"

    return (
        f"    {CYAN}{BOLD}{cve_id}{RESET}  {score_str}\n"
        f"    {GRAY}{desc}...{RESET}"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",   required=True)
    parser.add_argument("--severity", default=None)
    args = parser.parse_args()

    print(f"\n{WHITE}{BOLD}  NVD CVE/CWE Lookup{RESET}")
    print(f"{GRAY}  {'─' * 60}{RESET}\n")

    findings = scan(args.target)

    # Filtra per severità
    if args.severity:
        min_sev = Severity[args.severity]
        min_idx = SEVERITY_ORDER.index(min_sev)
        findings = [f for f in findings if SEVERITY_ORDER.index(f.severity) <= min_idx]

    if not findings:
        print(f"  {GREEN}Nessun finding da arricchire.{RESET}\n")
        return

    # Raggruppa per CWE per evitare chiamate duplicate
    cwe_map: dict[str, list] = {}
    for f in findings:
        if f.cwe:
            cwe_map.setdefault(f.cwe, []).append(f)

    seen_cves: set[str] = set()

    for cwe_id, related_findings in cwe_map.items():
        print(f"  {YELLOW}{BOLD}■ {cwe_id}{RESET}  —  {len(related_findings)} finding(s)")

        # Mostra i finding associati
        for f in related_findings[:3]:
            print(f"    {GRAY}→ [{f.rule_id}] {f.title}  (line {f.line}, {f.file}){RESET}")

        print(f"\n  {GRAY}CVE reali associati (NVD):{RESET}")

        cves = fetch_cves(cwe_id, max_results=5)
        if not cves:
            print(f"    {GRAY}Nessun CVE trovato o errore di rete.{RESET}")
        else:
            for vuln in cves:
                cve_id_str = vuln.get("cve", {}).get("id", "")
                if cve_id_str in seen_cves:
                    continue
                seen_cves.add(cve_id_str)
                print(format_cve(vuln))
                print()

        print(f"{GRAY}  {'─' * 60}{RESET}\n")

        # Rispetta il rate limit NVD (max 5 req/s senza API key)
        time.sleep(0.7)

    print(f"  {GREEN}{BOLD}Lookup completato.{RESET}  "
          f"{WHITE}{len(seen_cves)} CVE unici trovati.{RESET}\n")


if __name__ == "__main__":
    main()
