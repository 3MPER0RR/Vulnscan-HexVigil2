from .base import Rule, Finding, Severity
from .c_cpp import C_CPP_RULES
from .python import PYTHON_RULES
from .javascript import JS_RULES
from .rust import RUST_RULES
from .java import JAVA_RULES

ALL_RULES: list[Rule] = (
    C_CPP_RULES + PYTHON_RULES + JS_RULES + RUST_RULES + JAVA_RULES
)

EXT_TO_RULES: dict[str, list[Rule]] = {}
for rule in ALL_RULES:
    for ext in rule.extensions:
        EXT_TO_RULES.setdefault(ext, []).append(rule)

__all__ = ["Rule", "Finding", "Severity", "ALL_RULES", "EXT_TO_RULES"]