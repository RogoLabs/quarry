"""Thinking-capable models put their answer in the wrong field.

MEASURED against a live ollama on a ten-token prompt: `qwen3.6:27b` returned
`response: ""`, `done_reason: "stop"`, and `thinking: '{"ok": true}'` — the correct
answer, in a field nothing read.

`ollama show` reports the capability. Of the six models offered in the UI,
`gpt-oss:20b` and `qwen3.6:27b` have `thinking`; `qwen3-coder:30b`, `devstral:24b`,
`codestral:22b` and `deepseek-coder-v2:16b` do not. The correlation with outcomes was
exact: research run 2 had qwen3-coder:30b at 7/7 and gpt-oss:20b at 3/7 with
"empty response with and without grammar"; run 3 paired two thinking models and went
0/6 before this was found.

Two traps worth keeping named, because both cost hours:

1. `done_reason` is `"stop"`, so the truncation guard cannot see it. The failure looks
   like success to every check except "is the string empty".
2. The two-family rule *selects for* this pairing. gpt-oss + qwen3.6 satisfies "two
   families" while qwen3-coder — the one model with a clean record — is also family
   qwen, so pairing it with qwen3.6 would be refused.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.research.ensemble import _recover        # noqa: E402


def test_a_normal_response_passes_through_untouched():
    d = {"response": '{"findings": []}'}
    assert _recover(d) == '{"findings": []}'
    assert "recovered_from_thinking" not in d


def test_the_answer_is_recovered_from_thinking():
    """The exact shape observed from qwen3.6:27b."""
    d = {"response": "", "done_reason": "stop", "thinking": '{\n  "ok": true\n}'}
    assert _recover(d) == '{\n  "ok": true\n}'
    assert d["recovered_from_thinking"] is True, \
        "the recovery must be recorded, not silent — it changes what the run measured"


def test_a_whitespace_only_response_still_recovers():
    """`if not resp.strip()` was already the existing emptiness test; match it."""
    assert _recover({"response": "  \n ", "thinking": '{"ok":1}'}) == '{"ok":1}'


def test_genuinely_empty_stays_empty_so_the_grammar_fallback_still_fires():
    """The fallback is not removed — only stopped from firing on a false positive."""
    assert _recover({"response": ""}) == ""
    assert _recover({"response": "", "thinking": ""}) == ""
    assert _recover({"response": "", "thinking": None}) == ""


def test_missing_fields_do_not_raise():
    """ollama's payload shape varies by version; this runs on every call."""
    assert _recover({}) == ""
    assert _recover({"response": None}) == ""


def test_non_thinking_models_are_unaffected():
    """qwen3-coder:30b and devstral:24b omit the field entirely."""
    d = {"response": "prose then {\"a\":1}", "done_reason": "stop"}
    assert _recover(d) == "prose then {\"a\":1}"
    assert "recovered_from_thinking" not in d


@pytest.mark.parametrize("payload", [
    {"response": "", "thinking": '{"findings":[]}'},
    {"response": None, "thinking": '{"findings":[]}'},
])
def test_recovered_output_is_parseable_by_the_existing_parser(payload):
    """The recovered string must survive parse_findings, or recovery buys nothing."""
    from quarry.research.ensemble import parse_findings
    assert parse_findings(_recover(dict(payload)), "injection", "qwen3.6:27b") == []
