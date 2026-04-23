from .base import Rule, Severity, Finding
import re

# ── Regole base (pattern singola riga) ────────────────────────────────────────
C_CPP_RULES: list[Rule] = [
    Rule(
        id="C001", severity=Severity.CRITICAL,
        title="Use of gets()",
        description="gets() has no bounds checking and always leads to buffer overflow.",
        pattern=r"\bgets\s*\(",
        fix="Use fgets(buf, sizeof(buf), stdin) instead.",
        cwe="CWE-121",
        tags=["buffer-overflow", "memory"],
        extensions=[".c", ".cpp", ".h", ".hpp"],
    ),
    Rule(
        id="C002", severity=Severity.HIGH,
        title="Use of strcpy() with variable source",
        description="strcpy() with a variable (non-literal) source risks buffer overflow.",
        pattern=r'\bstrcpy\s*\(\s*\w+\s*,\s*(?!")\w+\s*\)',
        fix="Use strncpy() or strlcpy() with explicit size.",
        cwe="CWE-120",
        tags=["buffer-overflow", "memory"],
        extensions=[".c", ".cpp", ".h", ".hpp"],
    ),
    Rule(
        id="C003", severity=Severity.HIGH,
        title="Use of strcat()",
        description="strcat() does not perform bounds checking.",
        pattern=r"\bstrcat\s*\(",
        fix="Use strncat() with explicit size.",
        cwe="CWE-120",
        tags=["buffer-overflow", "memory"],
        extensions=[".c", ".cpp", ".h", ".hpp"],
    ),
    Rule(
        id="C004", severity=Severity.MEDIUM,
        title="Use of sprintf()",
        description="sprintf() can overflow if format string is not controlled.",
        pattern=r"\bsprintf\s*\(",
        fix="Use snprintf() with explicit size limit.",
        cwe="CWE-134",
        tags=["format-string", "memory"],
        extensions=[".c", ".cpp", ".h", ".hpp"],
    ),
    Rule(
        id="C005", severity=Severity.CRITICAL,
        title="Use of system()",
        description="system() executes shell commands and is vulnerable to injection.",
        pattern=r"\bsystem\s*\(",
        fix="Use execve() with explicit arguments instead.",
        cwe="CWE-78",
        tags=["command-injection", "os"],
        extensions=[".c", ".cpp"],
    ),
    Rule(
        id="C006", severity=Severity.HIGH,
        title="Use of scanf() without width limit",
        description="scanf(\"%s\") without width specifier allows buffer overflow.",
        pattern=r'scanf\s*\(\s*"[^"]*%s[^"]*"',
        fix='Use scanf("%255s", buf) with a width limit.',
        cwe="CWE-121",
        tags=["buffer-overflow", "input"],
        extensions=[".c", ".cpp"],
    ),
    Rule(
        id="C007", severity=Severity.LOW,
        title="Use of rand()",
        description="rand() is not cryptographically secure — low risk in non-security contexts.",
        pattern=r"\brand\s*\(\s*\)",
        fix="Use /dev/urandom or a CSPRNG for security-sensitive randomness.",
        cwe="CWE-338",
        tags=["crypto", "randomness"],
        extensions=[".c", ".cpp"],
    ),
    Rule(
        id="C008", severity=Severity.HIGH,
        title="Integer overflow in malloc",
        description="Multiplication inside malloc() without overflow check.",
        pattern=r"malloc\s*\([^)]*\*[^)]*\)",
        fix="Use checked arithmetic or calloc().",
        cwe="CWE-190",
        tags=["integer-overflow", "memory"],
        extensions=[".c", ".cpp"],
    ),
    Rule(
        id="C009", severity=Severity.LOW,
        title="Returning pointer to local variable",
        description="Returning address of a local variable causes undefined behavior.",
        pattern=r"return\s+&\s*\w+\s*;",
        fix="Allocate on heap or use static storage.",
        cwe="CWE-562",
        tags=["memory", "ub"],
        extensions=[".c", ".cpp"],
    ),
    Rule(
        id="C010", severity=Severity.MEDIUM,
        title="Use of printf with variable as format string",
        description="Passing a variable directly to printf() is a format string vulnerability.",
        pattern=r"\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)",
        fix='Use printf("%s", userdata) instead.',
        cwe="CWE-134",
        tags=["format-string"],
        extensions=[".c", ".cpp"],
    ),
    Rule(
        id="C014", severity=Severity.HIGH,
        title="memcpy with user-controlled size",
        description="memcpy() with size from external input can overflow destination buffer.",
        pattern=r"\bmemcpy\s*\([^,]+,[^,]+,\s*(?:argc|argv|input|len|size|count|n)\b",
        fix="Validate size before memcpy: ensure size <= sizeof(destination).",
        cwe="CWE-122",
        tags=["buffer-overflow", "memory"],
        extensions=[".c", ".cpp"],
    ),
    Rule(
        id="C015", severity=Severity.MEDIUM,
        title="Unsafe use of strtok()",
        description="strtok() is not thread-safe and modifies the original string.",
        pattern=r"\bstrtok\s*\(",
        fix="Use strtok_r() for thread-safe tokenization.",
        cwe="CWE-362",
        tags=["thread-safety", "memory"],
        extensions=[".c", ".cpp"],
    ),
]


# ── Analizzatore multi-riga: UAF e Double Free ────────────────────────────────

def _find_uaf_and_double_free(source: str, filepath: str) -> list[Finding]:
    """
    Analizza il codice riga per riga tenendo traccia delle variabili
    liberate con free(). Segnala:
    - Use After Free (C011): uso di ptr dopo free(ptr)
    - Double Free   (C012): free(ptr) dopo un altro free(ptr)
    """
    findings = []
    lines = source.splitlines()

    free_re  = re.compile(r'\bfree\s*\(\s*(\w+)\s*\)')
    use_re   = re.compile(r'\b(\w+)\s*(?:\[|\->|\.|\b)')
    print_re = re.compile(
        r'\b(?:printf|fprintf|puts|fputs|strcpy|strcat|memcpy|strlen|strcmp|strncmp)\s*\([^)]*\b(\w+)\b'
    )

    # Stato per funzione corrente
    freed: dict[str, int] = {}   # var_name → line number of free()
    in_func = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Rileva inizio/fine funzione (euristica semplice)
        if re.search(r'\w+\s+\w+\s*\([^)]*\)\s*\{', line) and not stripped.startswith('//'):
            freed = {}
            in_func = True

        if stripped == '}' and in_func:
            freed = {}

        if not in_func:
            continue

        # Trova free(var)
        for m in free_re.finditer(line):
            var = m.group(1)
            if var in freed:
                # Double free
                findings.append(Finding(
                    rule_id     = "C012",
                    severity    = Severity.CRITICAL,
                    title       = "Double Free",
                    description = f"free({var}) called twice — heap corruption.",
                    file        = filepath,
                    line        = i,
                    snippet     = stripped,
                    fix         = f"Set {var} = NULL after first free(). Never free twice.",
                    cwe         = "CWE-415",
                    tags        = ["double-free", "memory"],
                ))
            else:
                freed[var] = i

        # Trova uso di variabile liberata (UAF)
        if 'free(' not in line:
            for m in print_re.finditer(line):
                var = m.group(1)
                if var in freed:
                    findings.append(Finding(
                        rule_id     = "C011",
                        severity    = Severity.CRITICAL,
                        title       = "Use After Free (UAF)",
                        description = f"Variable '{var}' used after free() on line {freed[var]}.",
                        file        = filepath,
                        line        = i,
                        snippet     = stripped,
                        fix         = f"Set {var} = NULL after free(). Check for NULL before use.",
                        cwe         = "CWE-416",
                        tags        = ["use-after-free", "memory", "uaf"],
                    ))

    return findings


def run_c_analysis(source: str, filepath: str) -> list[Finding]:
    """Entry point chiamato dall'engine per analisi C avanzata."""
    findings = []
    # Regole standard
    for rule in C_CPP_RULES:
        findings.extend(rule.match(source, filepath))
    # Analisi multi-riga
    findings.extend(_find_uaf_and_double_free(source, filepath))
    return findings