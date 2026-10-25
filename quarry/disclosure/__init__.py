"""Disclosure: turn a confirmed verdict into a report a human can send.

Quarry finds vulnerabilities in other people's projects, so its output is a reporter's
advisory, not a CVE record. A CVE record is what the project's CNA (or GitHub, as a CNA,
from a GHSA) produces downstream. What a reporter sends is a clear write-up: what, where,
the impact, a reproduction, and a suggested fix. This package renders that as Markdown,
structured to match GitHub's "Report a vulnerability" (GHSA) form so the same text works
whether it is emailed to a maintainer's security contact or pasted into a GHSA draft.
"""
from .report import (  # noqa: F401
    DisclosureContext, Draft, render_report, build_reports, draft_reports,
    SecurityContact, extract_security_contacts, guess_ecosystem,
)
