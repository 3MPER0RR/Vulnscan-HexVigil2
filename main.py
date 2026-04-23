#!/usr/bin/env python3
"""
VulnScan — Static Vulnerability Scanner
Usage:
    python main.py <path> [--verbose] [--severity LEVEL] [--lang LANG]
"""
 
import argparse
import sys
import time
import os
from pathlib import Path
 
from scanner import scan, print_banner, print_findings, print_summary
from scanner.rules import Severity
 
 
SUPPORTED_EXTENSIONS = {
    ".c", ".cpp", ".h", ".hpp",
    ".py",
    ".js", ".ts", ".mjs", ".cjs",
    ".rs",
    ".java", ".kt",
}
 
IGNORED_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__",
    "venv", ".venv", "dist", "build", "target",
    ".idea", ".vscode",
}
 
 
def count_files(path: str) -> int:
    root = Path(path)
    if root.is_file():
        return 1 if root.suffix in SUPPORTED_EXTENSIONS else 0
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            if Path(fname).suffix in SUPPORTED_EXTENSIONS:
                count += 1
    return count
 
 
def parse_args():
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Static vulnerability scanner for C/C++, Python, JS/TS, Rust, Java/Kotlin",
    )
    parser.add_argument(
        "target",
        help="File or directory to scan",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show full description and fix for each finding",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Show only findings at or above this severity",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "python", "js", "rust", "java"],
        default=None,
        help="Restrict scan to a specific language",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the banner",
    )
    return parser.parse_args()
 
 
LANG_EXTENSIONS = {
    "c":      {".c", ".cpp", ".h", ".hpp"},
    "python": {".py"},
    "js":     {".js", ".ts", ".mjs", ".cjs"},
    "rust":   {".rs"},
    "java":   {".java", ".kt"},
}
 
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]
 
 
def main():
    args = parse_args()
 
    if not args.no_banner:
        print_banner()
 
    print(f"  🔍  Scanning: \033[97m{args.target}\033[0m\n")
 
    start = time.perf_counter()
    findings = scan(args.target)
    elapsed = time.perf_counter() - start
 
    # Filter by language
    if args.lang:
        allowed_exts = LANG_EXTENSIONS[args.lang]
        findings = [f for f in findings if os.path.splitext(f.file)[1] in allowed_exts]
 
    # Filter by minimum severity
    if args.severity:
        min_sev = Severity[args.severity]
        min_score = SEVERITY_ORDER.index(min_sev)
        findings = [f for f in findings if SEVERITY_ORDER.index(f.severity) <= min_score]
 
    files_scanned = count_files(args.target)
 
    print_findings(findings, verbose=args.verbose)
    print_summary(findings, files_scanned, elapsed)
 
    # Exit code: 1 se trova CRITICAL o HIGH
    has_critical = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    sys.exit(1 if has_critical else 0)
 
 
if __name__ == "__main__":
    main()