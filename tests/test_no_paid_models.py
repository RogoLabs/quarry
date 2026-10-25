"""Guard: Quarry spends no money.

P0 through P1a are entirely local and free. The LLM layers are gated behind the
calibration run (PLAN D3/D12), and until that gate is passed there must be no code
path that can reach a paid model — not an import, not a dependency, not a stray
endpoint. This test is the durable version of that claim.

When the adjudicator is eventually built, this test should FAIL loudly and be amended
in the same commit — deliberately, with the cost accounting and budget ceiling landing
alongside it. It is a tripwire, not a prohibition.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "quarry"
sys.path.insert(0, str(ROOT))

SOURCE = sorted(PKG.rglob("*.py"))

PROVIDER_SDKS = ("anthropic", "openai", "cohere", "mistralai", "litellm",
                 "google.generativeai", "google.genai", "vertexai", "boto3")

MODEL_ENDPOINTS = (
    "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "api.mistral.ai", "bedrock-runtime", "openai.azure.com",
    "/v1/chat/completions", "/v1/messages", "/v1/complete",
)

# Locally-served inference is free. Deep mode (quarry/research/) now uses it
# deliberately, so the tripwire that forbade any local endpoint has been amended here
# rather than deleted — which is the behaviour the original comment specified. What is
# still asserted: local inference is loopback-only, and it is the ONLY model endpoint.
LOCAL_INFERENCE_ALLOWED = {"http://127.0.0.1:11434/api/generate"}

CREDENTIAL_READS = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY",
    "find-generic-password", "GITHUB_TOKEN", "GH_TOKEN",
)


def _sources_containing(needles) -> list[str]:
    hits = []
    for path in SOURCE:
        text = path.read_text(errors="replace")
        for needle in needles:
            if needle in text:
                hits.append(f"{path.relative_to(ROOT)}: {needle!r}")
    return hits


def test_no_model_provider_sdk_is_imported():
    pattern = re.compile(
        r"^\s*(?:import|from)\s+(" + "|".join(re.escape(s) for s in PROVIDER_SDKS) + r")\b",
        re.M)
    offenders = [str(p.relative_to(ROOT)) for p in SOURCE
                 if pattern.search(p.read_text(errors="replace"))]
    assert not offenders, f"model-provider SDK imported in: {offenders}"


def test_no_model_provider_sdk_is_declared_as_a_dependency():
    """Not even as an optional extra. An unused extra is an invitation to write the
    code path before the calibration run has justified it."""
    proj = tomllib.load((ROOT / "pyproject.toml").open("rb"))["project"]
    declared = list(proj.get("dependencies", []))
    for extra in (proj.get("optional-dependencies") or {}).values():
        declared += list(extra)
    offenders = [d for d in declared
                 if any(d.lower().startswith(s.split(".")[0]) for s in PROVIDER_SDKS)]
    assert not offenders, f"model-provider SDK declared in pyproject: {offenders}"


def test_no_paid_model_endpoint_appears_in_source():
    hits = _sources_containing(MODEL_ENDPOINTS)
    assert not hits, f"paid-model endpoint referenced: {hits}"


def test_local_inference_is_loopback_only():
    """Deep mode calls a local model. Assert it can only ever be a loopback address —
    an inference URL pointing anywhere else is source code leaving the machine."""
    found = set()
    for path in SOURCE:
        found |= set(re.findall(r"https?://[^\s\"\']+/api/(?:generate|chat)",
                                path.read_text(errors="replace")))
    assert found <= LOCAL_INFERENCE_ALLOWED, f"non-loopback inference endpoint: {found - LOCAL_INFERENCE_ALLOWED}"
    for url in found:
        assert url.startswith(("http://127.0.0.1", "http://localhost")), url


def test_model_names_in_source_are_all_local_weights():
    """Deep mode names models in a family map. Assert every one is open-weight and
    locally served — a hosted model id appearing here is a paid call waiting to happen."""
    from quarry.research.ensemble import FAMILY
    forbidden = ("claude", "gpt-4", "gpt-5", "o1-", "o3-", "gemini", "sonnet", "opus")
    for name in FAMILY:
        low = name.lower()
        assert not any(f in low for f in forbidden), f"hosted model id in FAMILY map: {name}"


def test_refutation_is_cross_family_by_construction():
    """Belt (2026): self-refinement without external feedback degrades findings by
    37.6%. The ban is only real if `family()` actually separates the models we ship."""
    from quarry.research.ensemble import FAMILY, family
    fams = {family(m) for m in FAMILY}
    assert len(fams) >= 4, f"ensemble needs >=4 distinct families, got {fams}"
    assert family("qwen3-coder:30b") != family("gpt-oss:20b")
    assert family("qwen3-coder:30b") == family("qwen3.6:27b"), \
        "two Qwen variants must NOT count as independent refuters"


def test_no_credential_is_read_anywhere():
    """Seat 5's invariant: no process that reads target bytes holds a credential, and
    at P1 no process holds one at all — ingest clones anonymously (D17)."""
    hits = _sources_containing(CREDENTIAL_READS)
    assert not hits, f"credential read found: {hits}"


def test_outbound_hosts_are_a_known_free_allowlist():
    """Every literal URL in the source, checked against what the design actually needs:
    a clone host and two free metadata APIs. No inference host, no billing."""
    allowed = {
        "https://github.com",                    # anonymous clone
        "https://repos.ecosyste.ms",             # dependents, commit stats (free, no key)
        "https://api.securityscorecards.dev",    # OpenSSF Scorecard covariate (free, no key)
        "http://127.0.0.1",                      # local inference (deep mode), loopback only
    }
    found = set()
    for path in SOURCE:
        found |= set(re.findall(r"https?://[a-zA-Z0-9._-]+",
                                path.read_text(errors="replace")))
    unexpected = found - allowed
    assert not unexpected, f"unexpected outbound host(s): {sorted(unexpected)}"


def test_recorded_spend_schema_exists_and_defaults_to_zero(tmp_path):
    """The cost column exists so the first paid call cannot be untracked."""
    from quarry import db
    con = db.init(tmp_path / "t.db")
    cols = {r[1] for r in con.execute("PRAGMA table_info(verdicts)")}
    assert {"cost_usd", "cache_read_tokens", "cache_write_tokens", "model"} <= cols
    assert con.execute("SELECT COALESCE(SUM(cost_usd),0) FROM verdicts").fetchone()[0] == 0


def test_a_verified_quote_outranks_a_refuter_denying_its_existence():
    """REGRESSION, measured on cve-validation-library. The refuter killed two findings
    with "the quoted code is not found in the provided source" — for quotes at
    validate.ts:327 and :376, both of which verify against the file. A kill mandate
    makes a refuter eager, and an eager refuter invents grounds.

    A false positive is visible and costs triage time. A false negative is invisible
    and costs the finding. So the deterministic check outranks the model."""
    from quarry.research.ensemble import Finding
    f = Finding(lens="x", model="m", title="t", file="src/core/validate.ts",
                quote="private static validateTimelineHelper(value: Date): boolean {",
                severity="medium", reasoning="r", attacker_control="a",
                why_it_might_be_wrong="w", quote_verified=True)
    f.refutations = [
        {"model": "refuter-a", "verdict": "refuted",
         "reason": "The quoted code is not found in the provided source."},
        {"model": "refuter-b", "verdict": "refuted",
         "reason": "The version check is applied by the caller, so this is unreachable."},
    ]
    assert f.refuter_errors == 1, "the false-existence refutation must be discarded"
    assert f.refuted == 1, "the substantive refutation must still count"

    # ...and when the quote did NOT verify, a nonexistence refutation is legitimate.
    f.quote_verified = False
    assert f.refuter_errors == 0 and f.refuted == 2
