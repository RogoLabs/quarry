"""The dashboard's routes, one router per area.

`runs` is the run list, one run's page, its evidence, the egress ledger and Setup;
`triage` is the console and the two operator dispositions; `research` is deep review;
`reports` is validation, advisory drafts and the Layer 2 digest. Each reads through
queries.py, writes through writes.py, and gets the app's state from context.web().
The CSRF guard, Host allowlist and security headers are installed app-wide by
app.create_app, so no router opts into them and none can opt out.
"""
from . import reports, research, runs, triage  # noqa: F401

ROUTERS = (runs.router, triage.router, research.router, reports.router)
