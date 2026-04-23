from pathlib import Path
from .file_walker import walk_files
from .rules import EXT_TO_RULES, Finding
from .rules.c_cpp import run_c_analysis

C_EXTENSIONS = {".c", ".cpp", ".h", ".hpp"}


def scan(target: str) -> list[Finding]:
    files = walk_files(target)
    all_findings: list[Finding] = []

    for fpath in files:
        ext = fpath.suffix
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if ext in C_EXTENSIONS:
            # Usa l'analizzatore C avanzato (regole + UAF + double free)
            findings = run_c_analysis(source, str(fpath))
        else:
            rules = EXT_TO_RULES.get(ext, [])
            findings = []
            for rule in rules:
                findings.extend(rule.match(source, str(fpath)))

        all_findings.extend(findings)

    # Sort: critical first, then by file+line
    all_findings.sort(key=lambda f: (-f.score, f.file, f.line))
    return all_findings