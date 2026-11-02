"""CWE identifiers, in one form.

Scanners disagree on the form. Opengrep's SARIF tags read `CWE-22: Improper Limitation
of a Pathname...`, Bandit's issue_cwe is a bare number, OSV carries `CWE-79`. Every
comparison in Quarry is against `CWE-<n>`, so a long-form tag never matched and no
Opengrep finding was ever selected for Layer 3 (IMPROVEMENT-PLAN item 10).

`probe_class` folds a CWE onto the class a probe or report table is written for. The
stored CWE stays what the scanner said, so an advisory still names CWE-78.
"""
from __future__ import annotations

import re

_CWE = re.compile(r"^\s*CWE[-_ ]?(\d+)\b", re.I)

#: A narrower CWE that the same probe decides. CWE-78 (OS command injection) is what
#: Bandit and Semgrep emit for subprocess with a shell; the command-injection probe is
#: written for CWE-77. CWE-1333 (inefficient regex) is a resource-consumption bug.
EQUIVALENT = {"CWE-78": "CWE-77", "CWE-1333": "CWE-400"}


def normalise(value: object) -> str | None:
    """`CWE-<n>` from any scanner's form, or None if there is no CWE number in it."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value > 0 else None
    m = _CWE.match(str(value))
    return f"CWE-{int(m[1])}" if m else None


def probe_class(value: object) -> str | None:
    cwe = normalise(value)
    return EQUIVALENT.get(cwe, cwe) if cwe else None
