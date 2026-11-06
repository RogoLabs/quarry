"""The default deep-review model set, shared by the CLI and the dashboard.

gpt-oss:20b left the default on 2026-11-06 (docs/IMPROVEMENT-PLAN.md, item 27): on
run 7's first night it failed 20 of its 42 units with done_reason=length and used 18,590
of the night's 34,306 s doing it. granite4.2:30b replaced it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry.cli import DEFAULT_DEEP_MODELS                # noqa: E402
from quarry.research.ensemble import family               # noqa: E402
from quarry.web.routes.research import DEEP_DEFAULT, DEEP_MODELS  # noqa: E402
from test_web import seeded                                # noqa: E402,F401


def test_cli_and_dashboard_share_one_default():
    assert DEFAULT_DEEP_MODELS.split(",") == DEEP_DEFAULT
    assert set(DEEP_DEFAULT) <= set(DEEP_MODELS)


def test_the_default_spans_three_families_and_drops_gpt_oss():
    assert "gpt-oss:20b" not in DEEP_DEFAULT
    assert len({family(m) for m in DEEP_DEFAULT}) == 3


def test_gpt_oss_stays_selectable():
    assert "gpt-oss:20b" in DEEP_MODELS


def test_the_research_page_checks_exactly_the_default(seeded):
    client, _ = seeded
    page = client.get("/research").text
    checked = re.findall(r'name="models" value="([^"]+)"[^>]*\bchecked\b', page)
    assert checked == DEEP_DEFAULT
