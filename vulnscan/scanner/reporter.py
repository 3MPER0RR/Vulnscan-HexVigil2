from .rules import Finding, Severity
from collections import Counter

# ANSI color codes
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

RED     = "\033[91m"
ORANGE  = "\033[38;5;214m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"
MAGENTA = "\033[95m"

SEVERITY_COLOR = {
    Severity.CRITICAL: RED,
    Severity.HIGH:     ORANGE,
    Severity.MEDIUM:   YELLOW,
    Severity.LOW:      CYAN,
    Severity.INFO:     GREEN,
}

SEVERITY_ICON = {
    Severity.CRITICAL: "💀",
    Severity.HIGH:     "🔴",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "ℹ️ ",
}


def _sev(s: Severity) -> str:
    color = SEVERITY_COLOR[s]
    icon  = SEVERITY_ICON[s]
    return f"{color}{BOLD}{icon} {s.value:<8}{RESET}"


def print_banner():
    print(f"""
{MAGENTA}{BOLD}
          ⧗▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂⧗
          ⧗◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌⧗
          ⧗◌◌◌◌◌◌◌◌HexVigil◌◌◌◌◌◌◌◌⧗
          ⧗◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌◌⧗
          ⧗▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂▸◂⧗
{RESET}{GRAY}Static Vulnerability Scanner — v1.0{RESET}
""")


def print_findings(findings: list[Finding], verbose: bool = False):
    if not findings:
        print(f"\n{GREEN}{BOLD}✅  No vulnerabilities found.{RESET}\n")
        return

    current_file = None
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            print(f"\n{WHITE}{BOLD}📄  {f.file}{RESET}")
            print(f"{GRAY}{'─' * 70}{RESET}")

        sev_str = _sev(f.severity)
        print(f"  {sev_str}  {BOLD}{f.title}{RESET}  {GRAY}[{f.rule_id}]{RESET}")
        print(f"  {GRAY}Line {f.line}:{RESET}  {DIM}{f.snippet[:100]}{RESET}")

        if f.cwe:
            print(f"  {GRAY}CWE: {f.cwe}{RESET}", end="  ")
        if f.tags:
            tags_str = "  ".join(f"#{t}" for t in f.tags)
            print(f"{GRAY}{tags_str}{RESET}", end="")
        print()

        if verbose:
            print(f"  {CYAN}Description:{RESET} {f.description}")
            if f.fix:
                print(f"  {GREEN}Fix:{RESET} {f.fix}")
        print()


def print_summary(findings: list[Finding], files_scanned: int, elapsed: float):
    counts = Counter(f.severity for f in findings)

    total = len(findings)
    critical = counts.get(Severity.CRITICAL, 0)
    high     = counts.get(Severity.HIGH,     0)
    medium   = counts.get(Severity.MEDIUM,   0)
    low      = counts.get(Severity.LOW,      0)

    print(f"{GRAY}{'═' * 70}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{GRAY}{'─' * 70}{RESET}")
    print(f"  Files scanned : {WHITE}{BOLD}{files_scanned}{RESET}")
    print(f"  Total findings: {WHITE}{BOLD}{total}{RESET}")
    print(f"  {_sev(Severity.CRITICAL)}  {RED}{BOLD}{critical}{RESET}")
    print(f"  {_sev(Severity.HIGH)}  {ORANGE}{BOLD}{high}{RESET}")
    print(f"  {_sev(Severity.MEDIUM)}  {YELLOW}{BOLD}{medium}{RESET}")
    print(f"  {_sev(Severity.LOW)}  {CYAN}{BOLD}{low}{RESET}")
    print(f"\n  {GRAY}Scan completed in {elapsed:.2f}s{RESET}")

    if critical > 0:
        print(f"\n  {RED}{BOLD}⚠️  {critical} CRITICAL issue(s) require immediate attention!{RESET}")
    elif high > 0:
        print(f"\n  {ORANGE}{BOLD}⚠️  {high} HIGH severity issue(s) found.{RESET}")
    else:
        print(f"\n  {GREEN}Risk level: acceptable — review remaining findings.{RESET}")

    print(f"{GRAY}{'═' * 70}{RESET}\n")
