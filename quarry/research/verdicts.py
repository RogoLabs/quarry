"""Human verdicts on Layer 2 findings, and carrying them into the next deep run.

Run 1's two survivors both read as deliberate behaviour (work/survivors-run1-review.md),
but that was a reading in a Markdown file, not a record. Nothing stopped run 2 from
finding the same two things and presenting them as new. Here a verdict is a row
(migration v9, `deep_verdicts`): `intended`, `real` or `unclear`, with the human's note and
a timestamp. Rows are appended, never updated or deleted (D8); the newest row for a
research finding is its current verdict.

The next deep run on the same target reads them. A new finding that matches a prior
finding (same target, lens and file, and a matching quote or enclosing symbol) records
which prior finding and verdict it matched. When that verdict is `intended`, the refuter is
shown the human's note, and a survivor is listed as previously judged intended rather
than as new. Nothing is dropped: the finding is stored, refuted and funnelled exactly as
before, and the hunt prompt is deliberately NOT told about prior verdicts, because a
hunter told "a human said this is fine" can simply stop reporting it, which is a silent
drop by another name.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Iterable

from .. import taint
from .ensemble import MIN_QUOTE_CHARS

VERDICTS = ("intended", "real", "unclear")


class VerdictError(ValueError):
    """A verdict that cannot be recorded as asked."""


def record(con: sqlite3.Connection, research_finding_id: int, verdict: str, note: str,
           *, actor: str = "operator") -> int:
    """Append one human verdict. The vocabulary is checked here rather than by a CHECK
    constraint, for the reason migration v1 gives: a CHECK has to be rebuilt to grow."""
    verdict = (verdict or "").strip().lower()
    if verdict not in VERDICTS:
        raise VerdictError(f"verdict must be one of {', '.join(VERDICTS)}, not {verdict!r}")
    note = (note or "").strip()
    if not note:
        raise VerdictError("a verdict needs a note saying why; the next run shows it to "
                           "the refuter")
    if con.execute("SELECT 1 FROM research_findings WHERE id=?",
                   (research_finding_id,)).fetchone() is None:
        raise VerdictError(f"no research finding {research_finding_id}")
    cur = con.execute(
        "INSERT INTO deep_verdicts (research_finding_id, verdict, note, actor) "
        "VALUES (?,?,?,?)",
        (research_finding_id, verdict, taint.scrub_text(note, 2000),
         taint.scrub_text(actor or "operator", 80)))
    return int(cur.lastrowid)


def latest(con: sqlite3.Connection, research_finding_id: int) -> dict[str, Any] | None:
    r = con.execute(
        "SELECT * FROM deep_verdicts WHERE research_finding_id=? ORDER BY id DESC LIMIT 1",
        (research_finding_id,)).fetchone()
    return dict(r) if r else None


def _ws(s: str | None) -> str:
    return " ".join((s or "").split())


def quotes_overlap(a: str | None, b: str | None) -> bool:
    """One quote is inside the other, whitespace ignored, and the shorter one is long
    enough to mean something (the same floor quote verification uses). Models re-quote
    the same lines with a line more or less from one run to the next."""
    x, y = _ws(a), _ws(b)
    short, long_ = (x, y) if len(x) <= len(y) else (y, x)
    return len(short.replace(" ", "")) >= MIN_QUOTE_CHARS and short in long_


def candidates(con: sqlite3.Connection, target: str, lens: str, file: str,
               exclude_research_id: int | None = None) -> list[dict[str, Any]]:
    """Earlier research findings on this target, lens and file that carry a human
    verdict, each with its newest verdict, newest first."""
    rows = con.execute(
        """SELECT dv.id AS verdict_id, dv.verdict, dv.note, dv.actor, dv.created_at,
                  rf.id AS rf_id, rf.research_id, rf.title, rf.file, rf.quote, rf.symbol,
                  rr.run_id
             FROM deep_verdicts dv
             JOIN research_findings rf ON rf.id = dv.research_finding_id
             JOIN research_runs rr     ON rr.id = rf.research_id
             JOIN runs r               ON r.id = rr.run_id
            WHERE r.target = ? AND rf.lens = ? AND rf.file = ?
              AND rf.research_id IS NOT ?
              AND dv.id = (SELECT MAX(d2.id) FROM deep_verdicts d2
                           WHERE d2.research_finding_id = dv.research_finding_id)
            ORDER BY dv.id DESC""",
        (target, lens, file, exclude_research_id)).fetchall()
    return [dict(r) for r in rows]


def match(prior: Iterable[dict[str, Any]], *, quote: str, symbol: str | None
          ) -> tuple[dict[str, Any], str] | None:
    """The newest prior verdict this finding matches, and on what basis.

    Callers have already held lens, file and target equal. Then: the same enclosing
    symbol matches; so does an overlapping quote, unless both findings have a known
    symbol and the symbols differ. That exception is the cve-services shape: the line
    `mw.optionallyValidateUser,` sits in several routes of one index.js, and a verdict on
    `GET /cve-id/:id` says nothing about the route below it."""
    for p in prior:                                    # newest first
        same_symbol = bool(symbol) and symbol == p.get("symbol")
        if same_symbol:
            return p, f"same enclosing symbol `{symbol}`"
        if quotes_overlap(quote, p.get("quote")):
            if symbol and p.get("symbol") and symbol != p.get("symbol"):
                continue
            return p, "overlapping quote"
    return None


def detail(con: sqlite3.Connection, verdict_id: int) -> dict[str, Any] | None:
    """One verdict with the finding it was given on, in the shape `prior_context`
    reads. Used by the refute pass, which has only the matched verdict's id."""
    r = con.execute(
        """SELECT dv.id AS verdict_id, dv.verdict, dv.note, dv.actor, dv.created_at,
                  rf.id AS rf_id, rf.title, rf.file, rf.quote, rf.symbol, rr.run_id
             FROM deep_verdicts dv
             JOIN research_findings rf ON rf.id = dv.research_finding_id
             JOIN research_runs rr     ON rr.id = rf.research_id
            WHERE dv.id = ?""", (verdict_id,)).fetchone()
    return dict(r) if r else None


def prior_context(p: dict[str, Any], basis: str) -> str:
    """The block a refuter sees when the claim matches a prior `intended` verdict.
    Context, not an instruction to kill: the code may have changed, and a matching quote
    can carry a different claim."""
    return (
        f"A human reviewer has already judged a matching finding on this target.\n"
        f"- Verdict: INTENDED (deliberate behaviour, not a vulnerability), recorded "
        f"{taint.scrub_text(p['created_at'], 40)} UTC by "
        f"{taint.scrub_text(p['actor'], 40)}.\n"
        f"- Their note: {_ws(taint.scrub_text(p['note'], 800))}\n"
        f"- The finding they judged: research finding #{int(p['rf_id'])} (run "
        f"{int(p['run_id'])}): {_ws(taint.scrub_text(p['title'], 200))}; file "
        f"{taint.scrub_text(p['file'], 200)}; quoted code: "
        f"{_ws(taint.scrub_text(p['quote'], 300))}\n"
        f"- Why it matches this claim: {basis}.\n"
        f"Treat this as context, not proof. The code may have changed since, and a "
        f"matching quote can carry a different claim. If this claim describes the same "
        f"behaviour the reviewer judged intended, it is not a vulnerability unless you can "
        f"name what the reviewer missed. If it is a different claim, judge it on its own.")


def survivors(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """A run's Layer 2 survivors on the digest's bar (quote verified, defended by at
    least one cross-family model), each with its own newest human verdict and the prior
    verdict it was matched to, if any."""
    rows = con.execute(
        """SELECT rf.id, rf.research_id, rf.lens, rf.file, rf.title, rf.model, rf.family,
                  rf.n_survived, rf.n_refuted, rf.symbol, rf.prior_match,
                  own.verdict AS verdict, own.note AS note, own.created_at AS verdict_at,
                  own.actor AS verdict_by,
                  pv.verdict AS prior_verdict, pv.note AS prior_note,
                  pv.created_at AS prior_at, pv.research_finding_id AS prior_rf
             FROM research_findings rf
             JOIN research_runs rr ON rr.id = rf.research_id
             LEFT JOIN deep_verdicts own ON own.id = (
                  SELECT MAX(d.id) FROM deep_verdicts d WHERE d.research_finding_id = rf.id)
             LEFT JOIN deep_verdicts pv ON pv.id = rf.prior_verdict_id
            WHERE rr.run_id = ? AND rf.quote_verified = 1 AND rf.n_survived > 0
            ORDER BY rf.n_survived DESC, rf.n_refuted ASC, rf.subsystem, rf.id""",
        (run_id,)).fetchall()
    return [dict(r) for r in rows]
