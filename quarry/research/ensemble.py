"""Multi-model deep review of a single repository.

The gated design (LAYER2-PLAN.md) optimises precision across many repos: a
deterministic detector emits an anomaly cohort and one model answers one bounded
question. That is the right architecture for breadth — and it is the wrong one here,
which the target proved immediately. `cve-validation-library` has no routes, no ORM
and no auth, so all four detectors emit zero candidates and no model ever reads it.

Deep mode is the other product. One repo, the whole source in context, several model
*families* reading it independently, then refuting each other. It trades throughput
for coverage, which is the correct trade when the repo is small and the question is
"is there anything here at all".

Two design rules carried over from the panel, because they survive the change:

* **Cross-family, never self-critique.** Refutation comes from a different
  architecture. Belt (2026) measures self-refinement without external feedback at
  -37.6%; families here are `qwen3moe`, `gptoss`, `deepseek2`, `llama`, `glm`.
* **Agreement is weighted by independence, and it may only ever boost.** Two Qwen
  variants agreeing is one model agreeing with itself. And the finding that justifies
  the whole exercise — the one nobody else sees — is N=1 by construction.
"""
from __future__ import annotations

import functools
import glob
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..scanners.base import rel_or_none

OLLAMA = "http://127.0.0.1:11434/api/generate"

# curl for the loopback ollama call. `-q` must come first: it skips ~/.curlrc, which
# can add a proxy, extra headers or `--data @file`. `--noproxy '*'` ignores
# http_proxy/ALL_PROXY from the environment, so a prompt full of target source never
# takes a detour through a proxy on its way to 127.0.0.1.
CURL_LOOPBACK = ["curl", "-q", "--noproxy", "*", "-sS"]


class CloudModelRefused(ValueError):
    """A model name that ollama would forward off the machine."""


def check_local_model(model: str) -> str:
    """Refuse any model ollama serves remotely.

    Ollama's cloud models (names ending in `-cloud`, or tagged `:cloud`) look exactly
    like local ones to this API: the request goes to 127.0.0.1, and ollama forwards
    the whole prompt, i.e. the target's source, to ollama.com. No egress row is
    written because Quarry never opened that connection. "Completely local" has to
    hold for the model layer too, so any name containing "cloud" is refused outright.
    Too broad on purpose: a false refusal costs a rename, a false pass ships a
    repository off the machine.
    """
    if "cloud" in model.lower():
        raise CloudModelRefused(
            f"refusing model {model!r}: ollama forwards cloud models to ollama.com, "
            f"which would send the target's source off this machine unrecorded")
    return model

# Appended when a model cannot honour ollama's `format` schema and has to be asked in
# prose instead. Measured necessary for gpt-oss:20b.
JSON_ONLY_SUFFIX = """

Respond with a single JSON object and nothing else — no prose before or after it, no markdown fences. Every element of `findings` must be an OBJECT with exactly these keys, never a bare string:

{"findings": [{"title": "...", "file": "path/to/file.ts", "line": 42,
  "quote": "the exact line copied from the source",
  "severity": "critical|high|medium|low|info",
  "reasoning": "...", "attacker_control": "...", "why_it_might_be_wrong": "..."}]}

If you have no findings, respond exactly: {"findings": []}"""

# Architecture family per model, so "cross-family" is checkable rather than asserted.
FAMILY = {
    "qwen3-coder:30b": "qwen",
    "qwen3.6:27b": "qwen",
    "gpt-oss:20b": "gptoss",
    "deepseek-coder-v2:16b": "deepseek",
    "codestral:22b": "mistral",
    "devstral:24b": "mistral",
    "glm-5.2:9b": "glm",
    "llama3.2:3b": "llama",
}


def family(model: str) -> str:
    return FAMILY.get(model, model.split(":")[0])


# ---------------------------------------------------------------- lenses
#
# A lens is a question plus the evidence that makes it worth asking. Hardcoding a
# fixed list is how a reviewer finds nothing: `cve-validation-library` has no routes,
# no ORM and no auth, so an authz-shaped lens set emits zero candidates on a package
# whose whole job is security-relevant. Selection is driven by the deterministic
# profile, so every lens that runs can name the fact that selected it, and every lens
# that did not run can say why.

@dataclass(frozen=True)
class Lens:
    key: str
    question: str
    guidance: str
    requires: tuple[str, ...] = ()          # any-of these capabilities
    min_hits: int = 1
    kinds: tuple[str, ...] = ()             # artifact kinds, empty = any
    frameworks: tuple[str, ...] = ()        # empty = any

    def applies(self, prof) -> tuple[bool, str]:
        if self.kinds and prof.artifact_kind not in self.kinds:
            return False, f"artifact is {prof.artifact_kind}, lens wants {'/'.join(self.kinds)}"
        if self.frameworks and not any(f in prof.frameworks for f in self.frameworks):
            return False, f"no {'/'.join(self.frameworks)} detected"
        if not self.requires:
            return True, "applies to any repository"
        for cap in self.requires:
            n = prof.capabilities.get(cap, 0)
            if n >= self.min_hits:
                ev = prof.evidence.get(cap, "?")
                return True, f"{cap}={n} (e.g. {ev})"
        want = "/".join(self.requires)
        return False, f"no {want} at >={self.min_hits} hits"


CATALOGUE: tuple[Lens, ...] = (
    Lens("validation-bypass",
         "Can a malicious input be crafted that this code reports as VALID but that a "
         "downstream consumer should have rejected?",
         "A validation gap is the worst possible bug in something whose purpose is to "
         "validate. Look for: constraints absent where the field name or prose implies "
         "one; `additionalProperties` left open; `oneOf`/`anyOf` branches admitting more "
         "than intended; validation applied to one container but not a sibling; checks "
         "before rather than after normalisation; early returns that skip later checks; "
         "and any caught exception that yields a passing result.",
         requires=("schema_validation",), min_hits=5),

    Lens("untrusted-input-handling",
         "What happens when this code is given hostile input rather than merely invalid "
         "input?",
         "Consider prototype pollution via `__proto__`/`constructor` keys through parsing "
         "and any object spread or merge; deeply nested structures and recursion limits; "
         "very large arrays or strings; unicode normalisation tricks; and whether error "
         "paths echo the input back to the caller.",
         requires=("deserialization", "schema_validation", "http_routes")),

    Lens("broken-authz-idor",
         "Is there a route or action reachable by a user who should not reach it, or one "
         "that operates on an object without checking the caller owns it?",
         "Compare siblings: a route whose neighbours carry an authorization check and "
         "which carries none is the highest-value finding available. Then look for object "
         "lookups keyed directly on a caller-supplied id with no ownership predicate. Name "
         "the two principals: who is authenticated, and whose data is reached.",
         requires=("http_routes",), min_hits=5),

    Lens("multi-tenancy-isolation",
         "Can one tenant, organisation or account reach another's data?",
         "Find the discriminator column and then find every query that omits it. Scoping "
         "applied in a base class or default scope but bypassed by one raw query, one "
         "`unscoped`, or one admin path is the classic shape. This is authorization at row "
         "granularity, so treat a missing scope exactly as seriously as a missing auth check.",
         requires=("multi_tenant",), min_hits=20),

    Lens("injection",
         "Can attacker-controlled data reach an interpreter — SQL, shell, template, or "
         "the host language itself?",
         "Trace from a named entry point to the sink and quote both. String interpolation "
         "into a query, a command, or a template is the shape. Parameterised queries and "
         "escaped template output are not findings; say so rather than reporting them.",
         requires=("raw_sql", "subprocess", "template_render")),

    Lens("mass-assignment",
         "Can a caller set a model attribute the developer did not intend to expose?",
         "Look for parameter filtering that is absent, over-broad, or applied "
         "inconsistently across actions — and specifically for privilege-bearing "
         "attributes (role, admin, owner, tenant, verified, price) reachable through it.",
         requires=("orm_models",), min_hits=5, kinds=("service",)),

    Lens("redos-and-resource",
         "Is there a regular expression or parsing construct an attacker can make "
         "expensive?",
         "Quote the exact pattern. Nested quantifiers, overlapping alternation, and "
         "unbounded `.*` before an anchor are the shapes that matter. Validation and "
         "parsing run before anything trusts the input, which makes them the natural "
         "denial-of-service target. Consider unbounded input size as well as pattern shape.",
         requires=("schema_validation", "deserialization")),

    Lens("filesystem-and-path",
         "Can a caller-supplied path reach a file the author did not intend?",
         "Examine how each path is constructed, joined and resolved, and whether a "
         "relative path, an absolute path, a symlink or a `..` sequence changes the "
         "outcome. Say explicitly who supplies the path — if it is only ever a developer, "
         "say so and do not report it.",
         requires=("filesystem", "file_upload")),

    Lens("secrets-and-crypto",
         "Is key material, a token, or a credential handled in a way that exposes it, or "
         "is a cryptographic primitive used incorrectly?",
         "Committed secrets, secrets in logs or error messages, tokens without expiry or "
         "audience checks, non-CSPRNG randomness used for anything security-bearing, "
         "hand-rolled comparison of secrets, and weak or absent signature verification.",
         requires=("crypto", "authn")),

    Lens("api-contract-footgun",
         "What is the most likely way a competent consumer of this package will use it "
         "incorrectly, in a way that silently disables a security control?",
         "The users are other programs that will trust the verdict. A footgun producing a "
         "false pass is a defect in the ecosystem even when the library is internally "
         "correct. Consider defaults, optional parameters that skip checks, async "
         "functions usable without await, and result shapes that make failure easy to ignore.",
         kinds=("library",)),

    Lens("supply-chain-and-build",
         "Is there anything about this package's dependencies, build, or publication that "
         "lets an attacker influence what consumers execute?",
         "Consider each dependency and whether it belongs at all; version ranges and "
         "overrides, since an override usually means a CVE was hit before; lifecycle "
         "scripts; what the publish manifest actually ships; and CI workflows that run "
         "attacker-influenced content with elevated tokens.",
         requires=()),

    Lens("error-and-disclosure",
         "Does a failure path reveal something the caller should not learn?",
         "Stack traces, internal paths, query fragments, upstream error bodies, and the "
         "difference in timing or message between 'no such user' and 'wrong password'.",
         requires=("http_routes",)),

    Lens("background-job-trust",
         "Does work deferred to a queue re-check what the request path checked?",
         "Jobs frequently run with elevated privilege and deserialise their arguments. "
         "Look for authorization performed at enqueue time but not at execution time, and "
         "for job arguments that carry objects rather than ids.",
         requires=("background_jobs",)),
)


def select_lenses(prof) -> tuple[list[Lens], list[tuple[str, str]]]:
    """-> (selected, [(lens_key, why_not)]). Both halves are reported: a lens that did
    not run is information, not silence."""
    chosen, rejected = [], []
    for lens in CATALOGUE:
        ok, why = lens.applies(prof)
        (chosen if ok else rejected).append(lens if ok else (lens.key, why))
    return chosen, rejected


# ---------------------------------------------------------------- schema

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array", "maxItems": 6,
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "maxLength": 120},
                    "file": {"type": "string", "maxLength": 200},
                    "line": {"type": "integer"},
                    "quote": {"type": "string", "maxLength": 300},
                    "severity": {"type": "string",
                                 "enum": ["critical", "high", "medium", "low", "info"]},
                    "reasoning": {"type": "string", "maxLength": 900},
                    "attacker_control": {"type": "string", "maxLength": 400},
                    "why_it_might_be_wrong": {"type": "string", "maxLength": 400},
                },
                "required": ["title", "file", "quote", "severity", "reasoning",
                             "attacker_control", "why_it_might_be_wrong"],
            },
        }
    },
    "required": ["findings"],
}

REFUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["refuted", "survives", "uncertain"]},
        "reason": {"type": "string", "maxLength": 600},
        "counter_quote": {"type": "string", "maxLength": 300},
    },
    "required": ["verdict", "reason"],
}


# ---------------------------------------------------------------- runtime

@dataclass
class Finding:
    lens: str
    model: str
    title: str
    file: str
    quote: str
    severity: str
    reasoning: str
    attacker_control: str
    why_it_might_be_wrong: str
    line: int | None = None
    quote_verified: bool = False
    refutations: list[dict[str, Any]] = field(default_factory=list)
    agreement: list[str] = field(default_factory=list)   # other FAMILIES that saw it

    @property
    def survived(self) -> int:
        return sum(1 for r in self.valid_refutations if r.get("verdict") == "survives")

    @property
    def refuted(self) -> int:
        return sum(1 for r in self.valid_refutations if r.get("verdict") == "refuted")

    @property
    def valid_refutations(self) -> list[dict[str, Any]]:
        """Refutations that are not themselves false.

        MEASURED, and the reason this exists: on `cve-validation-library` the refuter
        killed two findings with "the quoted code is not found in the provided source"
        — for quotes at `validate.ts:327` and `validate.ts:376`, both of which verify
        against the file. A kill mandate makes a refuter eager, and an eager refuter
        invents grounds.

        This asymmetry matters more than it looks. A false positive is visible and
        costs triage time; a false *negative* is invisible and costs the finding. So
        the deterministic check outranks the model in both directions: if the quote
        verified against the source, any refutation resting on "that code does not
        exist" is discarded and recorded as a refuter error.
        """
        out = []
        for r in self.refutations:
            reason = (r.get("reason") or "").lower()
            denies_existence = any(k in reason for k in (
                "not found in", "does not exist", "no such code", "cannot find",
                "is not present", "not in the provided"))
            if self.quote_verified and denies_existence:
                r = {**r, "discarded": "quote verified against source; refuter denied "
                                       "its existence"}
                out.append(r) if False else None
                continue
            out.append(r)
        return out

    @property
    def refuter_errors(self) -> int:
        return len(self.refutations) - len(self.valid_refutations)


def _recover(d: dict) -> str:
    """The model's answer, from wherever ollama put it.

    MEASURED, both families, on a ten-token prompt: a thinking-capable model returns
    `response: ""` with `done_reason: "stop"` and its actual output — correctly
    formatted JSON — in `thinking`. `ollama show` reports the capability:
    gpt-oss:20b and qwen3.6:27b have it, qwen3-coder:30b and devstral:24b do not.

    That single field is the whole difference between a working ensemble and a run
    that burns hours producing nothing. On research run 2, qwen3-coder:30b went 7/7
    while gpt-oss:20b went 3/7 with `empty response with and without grammar`; on run
    3, gpt-oss:20b and qwen3.6:27b were 0/5 between them. Every failure was a thinking
    model, every success was not.

    The comment below attributes the empty response to a silent grammar failure. That
    reading is wrong and the retry it justifies cannot help: dropping `format` does not
    stop a model reasoning, so the second call comes back empty too. Reading the field
    ollama actually filled is the fix; the grammar fallback stays for the case where
    there is genuinely nothing anywhere.

    Safe for non-thinking models: they leave `thinking` absent, so this returns
    `response` unchanged.
    """
    resp = d.get("response") or ""
    if resp.strip():
        return resp
    thinking = d.get("thinking") or ""
    if thinking.strip():
        d["recovered_from_thinking"] = True
        return thinking
    return resp


@functools.lru_cache(maxsize=None)
def supports_thinking(model: str) -> bool:
    """True when ollama reports the `thinking` capability for this model.

    MEASURED (qwen3.6:27b, api/generate, num_ctx 65536, num_predict 2200, the findings
    phase's own budget): the model spent all 2200 output tokens on an 8847-character
    reasoning trace and returned `response: ""` with `done_reason: "length"` — the JSON
    answer never started, so the unit produced nothing but an error. The same call with
    `think: false` returned valid findings in 404 tokens with `done_reason: "stop"`. A
    thinking model counts its reasoning against the same output budget as the answer, so
    a bounded num_predict truncates it before the schema is satisfied; `_recover`'s read
    of the `thinking` field cannot help once that field is itself cut off mid-token.

    This gate is load-bearing, not an optimisation: ollama rejects the `think` option
    for a model that does not advertise the capability (devstral:24b, qwen3-coder:30b),
    so `think: false` may only be sent to a model this returns True for.
    """
    try:
        p = subprocess.run(["ollama", "show", model],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    out = p.stdout.lower()
    if "capabilities" not in out:
        return False
    tail = out.split("capabilities", 1)[1]
    return re.search(r"(?:^|\s)thinking(?:\s|$)", tail) is not None


def call(model: str, prompt: str, schema: dict | None, *, num_ctx: int = 65536,
         num_predict: int = 2048, timeout: int = 1800) -> tuple[str, dict]:
    """One ollama call. Grammar-constrained when a schema is given, and
    `done_reason` is checked — a truncated JSON prefix parses as nothing and cost the
    predecessor 25% of its files."""
    check_local_model(model)
    body: dict[str, Any] = {
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0, "top_k": 1, "seed": 42,
                    "num_ctx": num_ctx, "num_predict": num_predict},
    }
    # Thinking models burn num_predict on a reasoning trace and truncate before the JSON
    # answer (done_reason=length). Ask them for the structured answer directly; the gate
    # matters because ollama 400s if `think` is sent to a non-thinking model.
    if supports_thinking(model):
        body["think"] = False
    if schema:
        body["format"] = schema
    p = subprocess.run([*CURL_LOOPBACK, "--max-time", str(timeout), OLLAMA,
                        "-H", "Content-Type: application/json", "-d", json.dumps(body)],
                       capture_output=True, text=True, timeout=timeout + 60)
    if p.returncode != 0:
        raise RuntimeError(f"{model}: curl failed: {p.stderr[:200]}")
    d = json.loads(p.stdout)
    if d.get("done_reason") not in (None, "stop"):
        raise RuntimeError(f"{model}: done_reason={d.get('done_reason')} — output truncated")
    resp = _recover(d)
    # MEASURED: gpt-oss:20b returns an EMPTY response with done_reason="stop" when a
    # `format` schema is supplied — it fails the grammar silently and reports success.
    # Left as an error it costs a third of the ensemble on every run, so retry once
    # without the constraint and recover the JSON from prose. Grammar is an
    # optimisation, not a requirement; the parser already tolerates prose around JSON.
    if schema and not resp.strip():
        body.pop("format", None)
        body["prompt"] = prompt + JSON_ONLY_SUFFIX
        p = subprocess.run([*CURL_LOOPBACK, "--max-time", str(timeout), OLLAMA,
                            "-H", "Content-Type: application/json",
                            "-d", json.dumps(body)],
                           capture_output=True, text=True, timeout=timeout + 60)
        d = json.loads(p.stdout)
        resp = _recover(d)
        d["grammar_fallback"] = True
        if not resp.strip():
            raise RuntimeError(f"{model}: empty response with and without grammar")
    return resp, d


def parse_findings(raw: str, lens: str, model: str) -> list[Finding]:
    try:
        doc = json.loads(raw)
    except ValueError:
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return []
        try:
            doc = json.loads(m.group(0))
        except ValueError:
            return []
    out = []
    for f in (doc.get("findings") or [])[:6]:
        if not isinstance(f, dict) or not f.get("title"):
            continue
        out.append(Finding(
            lens=lens, model=model,
            title=str(f.get("title", ""))[:120], file=str(f.get("file", ""))[:200],
            quote=str(f.get("quote", ""))[:300], severity=str(f.get("severity", "info")),
            reasoning=str(f.get("reasoning", ""))[:900],
            attacker_control=str(f.get("attacker_control", ""))[:400],
            why_it_might_be_wrong=str(f.get("why_it_might_be_wrong", ""))[:400],
            line=f.get("line") if isinstance(f.get("line"), int) else None))
    return out


def verify_quote(f: Finding, root: Path) -> bool:
    """The single cheapest false-premise killer: does the quoted line exist verbatim?
    27% of the predecessor's rejections were hallucinated code."""
    if not f.quote.strip():
        return False
    needle = " ".join(f.quote.split())
    cand: list[Path] = []
    if f.file:
        # `file` is model output. Unchecked, "/etc/hosts" made `root / f.file` the
        # host file itself and this a yes/no oracle on any file the operator can read.
        # Same taint boundary as a scanner path; outside the clone, nothing verifies.
        rel = rel_or_none(f.file, root)
        if rel is None:
            return False
        cand.append(root / rel)
        name = Path(rel).name
        if name:
            # glob.escape: a model-supplied "*" must not turn into a tree walk.
            cand += list(root.rglob(glob.escape(name)))
    base = root.resolve()
    for p in cand[:5]:
        try:
            # A sandboxed scanner can plant a symlink after the scrub; never read
            # through one, and never read anything that resolves outside the clone.
            if p.is_symlink() or not p.resolve().is_relative_to(base):
                continue
            if p.is_file() and needle in " ".join(p.read_text(errors="replace").split()):
                return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------- prompts

HUNT_SYSTEM = """You are a senior application security engineer performing a deep review \
of a small library. You have been given its ENTIRE source. There is nothing you cannot see, \
so an answer of "I could not determine X" is a choice, not a limitation.

Rules that decide whether your output is worth anything:

1. QUOTE REAL CODE. Every finding must include `quote`: a span copied character-for-character \
from the source above. If you cannot copy it, you are imagining it, and the finding will be \
discarded automatically.
2. NAME THE ATTACKER'S CONTROL. Say exactly what an attacker supplies and how it reaches the \
code you quoted. "An attacker could" without a named input is not a finding.
3. ARGUE AGAINST YOURSELF. `why_it_might_be_wrong` is required and must be substantive — the \
strongest reason a reviewer would reject your finding. Writing "none" there makes the finding \
less credible, not more.
4. REPORT NOTHING RATHER THAN SOMETHING. An empty findings array is a valid, respectable \
answer and is much better than a plausible guess. Most reviews of most files find nothing.
5. This library's own test fixtures contain deliberately invalid records. Malformed data in \
`test-data/` is the test suite working, not a vulnerability.

Severity reflects impact on a consumer of this library, not how interesting the code is."""

REFUTE_SYSTEM = """You are refuting a security finding written by a different model. Your \
mandate is to KILL it. You have the complete source it was written about.

You are not being asked whether the finding is interesting or whether the code could be \
improved. You are being asked one question: is the specific claim TRUE as stated?

Return `refuted` if: the quoted code does not exist or does not say what is claimed; the \
attacker cannot actually supply the input; a check elsewhere already prevents it; the \
construct is real but confers no attacker benefit; or the claim is about test/fixture code.

Return `survives` ONLY if you tried to kill it and could not. Return `uncertain` only when a \
specific named fact would settle it and it is genuinely not in the source.

Default to `refuted`. Most findings are wrong."""


def hunt_prompt(pack_text: str, lens: Lens, manifest: str) -> str:
    return (f"{HUNT_SYSTEM}\n\n"
            f"===== REPOSITORY ({manifest.count(chr(10)) + 1} files) =====\n"
            f"{pack_text}\n\n"
            f"===== YOUR LENS: {lens.key} =====\n"
            f"{lens.question}\n\n{lens.guidance}\n\n"
            f"Review the whole repository through this lens only. Other reviewers are "
            f"covering other angles; do not dilute yours. Return JSON.")


def refute_prompt(pack_text: str, f: Finding) -> str:
    return (f"{REFUTE_SYSTEM}\n\n"
            f"===== REPOSITORY =====\n{pack_text}\n\n"
            f"===== THE CLAIM =====\n"
            f"Title: {f.title}\nFile: {f.file}\nSeverity claimed: {f.severity}\n"
            f"Quoted code: {f.quote}\n"
            f"Attacker control claimed: {f.attacker_control}\n\n"
            f"Is this true as stated? Return JSON.")
