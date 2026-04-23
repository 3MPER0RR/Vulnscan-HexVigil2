#!/usr/bin/env python3
"""
ai_analysis.py — Analisi contestuale AI dei findings
Supporta: Claude (Anthropic), Groq, OpenRouter

Inserisci la tua API key direttamente in API_KEYS qui sotto.
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

# ── Colori ─────────────────────────────────────────────────────────────────────
RED     = "\033[91m"
ORANGE  = "\033[38;5;214m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
MAGENTA = "\033[95m"
GRAY    = "\033[90m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# ==============================================================================
# ██  INSERISCI LE TUE API KEY QUI  ██
# Lascia vuota ("") i backend che non usi.
# ==============================================================================
API_KEYS = {
    "claude":      "",   # es. sk-ant-...
    "groq":        "",   # es. gsk_...
    "openrouter":  "",   # es. sk-or-...
}
# ==============================================================================

BACKENDS = {
    "claude": {
        "name":    "Claude (Anthropic)",
        "url":     "https://api.anthropic.com/v1/messages",
        "model":   "claude-sonnet-4-5",
        "env_key": "ANTHROPIC_API_KEY",
        "free":    False,
    },
    "groq": {
        "name":    "Groq (LLaMA 3.3 70B) — FREE",
        "url":     "https://api.groq.com/openai/v1/chat/completions",
        "model":   "llama-3.3-70b-versatile",
        "env_key": "GROQ_API_KEY",
        "free":    True,
    },
    "openrouter": {
        "name":    "OpenRouter (Mistral 7B) — FREE",
        "url":     "https://openrouter.ai/api/v1/chat/completions",
        "model":   "openai/gpt-oss-120b:free",
        "env_key": "OPENROUTER_API_KEY",
        "free":    True,
    },
}

SYSTEM_PROMPT = """Sei un esperto di sicurezza informatica specializzato in analisi
di vulnerabilità del codice sorgente. Il tuo compito è analizzare i findings
di uno scanner SAST e determinare:

1. Se il finding è un FALSO POSITIVO o una VULNERABILITÀ REALE
2. La severità reale nel contesto specifico del codice
3. Un fix concreto e specifico per quel codice

Rispondi SOLO in formato JSON valido, senza testo aggiuntivo, con questa struttura:
{
  "findings": [
    {
      "rule_id": "C002",
      "title": "Use of strcpy()",
      "file": "example.c",
      "line": 42,
      "false_positive": false,
      "original_severity": "HIGH",
      "real_severity": "CRITICAL",
      "confidence": "HIGH",
      "reasoning": "Il buffer di destinazione è fisso a 64 byte ma l input arriva da rete senza validazione",
      "fix": "Sostituire strcpy(dst, src) con strncpy(dst, src, sizeof(dst) - 1);"
    }
  ],
  "summary": {
    "total_analyzed": 5,
    "false_positives": 2,
    "confirmed_vulnerabilities": 3,
    "critical_confirmed": 1
  }
}"""


# =============================================================================
# Chiamate API
# =============================================================================

def call_claude(prompt, api_key, model):
    payload = json.dumps({
        "model":      model,
        "max_tokens": 4096,
        "system":     SYSTEM_PROMPT,
        "messages":   [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        BACKENDS["claude"]["url"],
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
        return data["content"][0]["text"]


def call_openai_compatible(prompt, api_key, url, model, extra_headers={}):
    payload = json.dumps({
        "model":       model,
        "messages":    [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "max_tokens":  4096,
        "temperature": 0.1,
    }).encode()

    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "vulnscan/1.0",
    }
    headers.update(extra_headers)

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]


def call_backend(backend_id, prompt, api_key):
    cfg = BACKENDS[backend_id]
    if backend_id == "claude":
        return call_claude(prompt, api_key, cfg["model"])
    elif backend_id == "groq":
        return call_openai_compatible(prompt, api_key, cfg["url"], cfg["model"])
    elif backend_id == "openrouter":
        return call_openai_compatible(
            prompt, api_key, cfg["url"], cfg["model"],
            extra_headers={"HTTP-Referer": "vulnscan", "X-Title": "VulnScan"}
        )
    raise ValueError(f"Backend sconosciuto: {backend_id}")


# =============================================================================
# Selezione automatica backend
# =============================================================================

def detect_backend(forced=None):
    """
    Priorità:
    1. Chiave hardcoded in API_KEYS (questo file)
    2. Variabile d'ambiente
    """
    order = [forced] if forced else ["claude", "groq", "openrouter"]
    for bid in order:
        if bid not in BACKENDS:
            continue
        # 1. chiave nel file
        key = API_KEYS.get(bid, "").strip()
        # 2. variabile d'ambiente come fallback
        if not key:
            key = os.environ.get(BACKENDS[bid]["env_key"], "").strip()
        if key:
            return bid, key
    return None, None


# =============================================================================
# Prompt builder
# =============================================================================

def build_prompt(scan_report, nvd_report):
    scan_truncated = scan_report[:12000]
    nvd_truncated  = nvd_report[:6000]
    return f"""Analizza i seguenti findings di uno scanner SAST e il lookup CVE/NVD associato.
Determina per ogni finding se è un falso positivo e la severità reale nel contesto del codice.

=== SCAN REPORT ===
{scan_truncated}

=== CVE/NVD REPORT ===
{nvd_truncated}

Rispondi SOLO con il JSON strutturato. Nessun testo aggiuntivo."""


# =============================================================================
# Rendering risultato
# =============================================================================

def render_result(result_json):
    findings = result_json.get("findings", [])
    summary  = result_json.get("summary", {})

    SEV_COLOR = {
        "CRITICAL": RED,
        "HIGH":     ORANGE,
        "MEDIUM":   YELLOW,
        "LOW":      CYAN,
        "INFO":     GREEN,
    }

    print(f"\n{WHITE}{BOLD}  ── ANALISI AI ──────────────────────────────────────{RESET}\n")

    for f in findings:
        is_fp    = f.get("false_positive", False)
        rule_id  = f.get("rule_id", "")
        title    = f.get("title", "")
        fpath    = f.get("file", "")
        line     = f.get("line", "")
        orig_sev = f.get("original_severity", "")
        real_sev = f.get("real_severity", orig_sev)
        reason   = f.get("reasoning", "")
        fix      = f.get("fix", "")
        conf     = f.get("confidence", "")

        if is_fp:
            status = f"{GREEN}{BOLD}✅ FALSO POSITIVO{RESET}"
        else:
            color  = SEV_COLOR.get(real_sev, WHITE)
            status = f"{color}{BOLD}⚠  CONFERMATO — {real_sev}{RESET}"

        print(f"  {status}  {BOLD}{title}{RESET}  {GRAY}[{rule_id}]{RESET}")
        print(f"  {GRAY}{fpath}  line {line}{RESET}")

        if orig_sev != real_sev and not is_fp:
            print(f"  {GRAY}Severità: {orig_sev} → {SEV_COLOR.get(real_sev,'')}{real_sev}{RESET}  "
                  f"{GRAY}(confidenza: {conf}){RESET}")

        print(f"  {CYAN}Ragionamento:{RESET} {reason}")

        if fix and not is_fp:
            print(f"  {GREEN}Fix:{RESET} {fix}")

        print()

    total     = summary.get("total_analyzed", len(findings))
    fp_count  = summary.get("false_positives", 0)
    real_vuln = summary.get("confirmed_vulnerabilities", 0)
    critical  = summary.get("critical_confirmed", 0)

    print(f"{GRAY}  {'═' * 60}{RESET}")
    print(f"  {BOLD}RIEPILOGO AI{RESET}")
    print(f"{GRAY}  {'─' * 60}{RESET}")
    print(f"  Findings analizzati  : {WHITE}{BOLD}{total}{RESET}")
    print(f"  Falsi positivi       : {GREEN}{BOLD}{fp_count}{RESET}")
    print(f"  Vulnerabilità reali  : {ORANGE}{BOLD}{real_vuln}{RESET}")
    print(f"  CRITICAL confermati  : {RED}{BOLD}{critical}{RESET}")

    if total > 0:
        reduction = round((fp_count / total) * 100)
        print(f"\n  {GREEN}Riduzione falsi positivi: {BOLD}{reduction}%{RESET}")

    print(f"{GRAY}  {'═' * 60}{RESET}\n")


# =============================================================================
# Stub — nessuna chiave trovata
# =============================================================================

def print_stub():
    print(f"\n  {YELLOW}{BOLD}⚠  Nessuna API key configurata.{RESET}\n")
    print(f"  {WHITE}Apri {CYAN}ai_analysis.py{WHITE} e inserisci la tua chiave in:{RESET}\n")
    print(f"  {CYAN}API_KEYS = {{{RESET}")
    print(f'  {CYAN}    "claude":     "",{RESET}  {GRAY}# sk-ant-...{RESET}')
    print(f'  {CYAN}    "groq":       "",{RESET}  {GRAY}# gsk_...{RESET}')
    print(f'  {CYAN}    "openrouter": "",{RESET}  {GRAY}# sk-or-...{RESET}')
    print(f"  {CYAN}}}{RESET}\n")
    print(f"  {WHITE}{BOLD}Dove ottenere le chiavi gratuite:{RESET}")
    print(f"  {CYAN}Groq      :{RESET} https://console.groq.com   {GREEN}(gratuito, veloce){RESET}")
    print(f"  {CYAN}OpenRouter:{RESET} https://openrouter.ai      {GREEN}(gratuito con alcuni modelli){RESET}")
    print(f"  {CYAN}Claude    :{RESET} https://console.anthropic.com\n")


# =============================================================================
# Main
# =============================================================================

def load_report(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        print(f"  {RED}File non trovato: {path}{RESET}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-report", required=True)
    parser.add_argument("--nvd-report",  required=True)
    parser.add_argument("--backend",
                        choices=["claude", "groq", "openrouter"],
                        default=None,
                        help="Forza un backend specifico (default: auto)")
    args = parser.parse_args()

    print(f"\n{MAGENTA}{BOLD}  AI Analysis Layer — VulnScan{RESET}")
    print(f"{GRAY}  {'─' * 60}{RESET}\n")

    backend_id, api_key = detect_backend(args.backend)

    if not backend_id:
        print_stub()
        return

    cfg = BACKENDS[backend_id]
    print(f"  {GREEN}Backend:{RESET} {WHITE}{BOLD}{cfg['name']}{RESET}")
    print(f"  {GREEN}Modello:{RESET} {WHITE}{cfg['model']}{RESET}\n")

    scan_report = load_report(args.scan_report)
    nvd_report  = load_report(args.nvd_report)
    prompt      = build_prompt(scan_report, nvd_report)

    print(f"  {GRAY}Invio findings all'AI in corso...{RESET}\n")

    try:
        raw = call_backend(backend_id, prompt, api_key)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  {RED}Errore HTTP {e.code}: {body}{RESET}")
        return
    except Exception as e:
        print(f"  {RED}Errore di connessione: {e}{RESET}")
        return

    clean = raw.strip()
    if clean.startswith("```"):
        clean = "\n".join(clean.split("\n")[1:])
    if clean.endswith("```"):
        clean = "\n".join(clean.split("\n")[:-1])

    try:
        result = json.loads(clean)
    except json.JSONDecodeError:
        print(f"  {YELLOW}Risposta non in JSON valido. Output grezzo:{RESET}\n")
        print(raw)
        return

    render_result(result)


if __name__ == "__main__":
    main()