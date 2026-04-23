from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_SCORE = {
    Severity.CRITICAL: 5,
    Severity.HIGH:     4,
    Severity.MEDIUM:   3,
    Severity.LOW:      2,
    Severity.INFO:     1,
}


@dataclass
class Finding:
    rule_id:     str
    severity:    Severity
    title:       str
    description: str
    file:        str
    line:        int
    snippet:     str
    fix:         Optional[str] = None
    cwe:         Optional[str] = None
    tags:        list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return SEVERITY_SCORE[self.severity]


@dataclass
class Rule:
    id:          str
    severity:    Severity
    title:       str
    description: str
    pattern:     str
    fix:         Optional[str] = None
    cwe:         Optional[str] = None
    tags:        list[str] = field(default_factory=list)
    extensions:  list[str] = field(default_factory=list)

    def _compiled(self):
        if not hasattr(self, "_re"):
            self._re = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        return self._re

    def match(self, source: str, filepath: str) -> list[Finding]:
        findings = []
        lines = source.splitlines()
        for i, line in enumerate(lines, start=1):
            if self._compiled().search(line):
                findings.append(Finding(
                    rule_id     = self.id,
                    severity    = self.severity,
                    title       = self.title,
                    description = self.description,
                    file        = filepath,
                    line        = i,
                    snippet     = line.strip(),
                    fix         = self.fix,
                    cwe         = self.cwe,
                    tags        = self.tags,
                ))
        return findings