"""Schema migrations.

Small and explicit: each migration is a function that takes a connection. The
`schema_version` pragma is the ledger. SQLite cannot alter a CHECK constraint, so
where one needs to change the table is rebuilt.
"""
from __future__ import annotations

import sqlite3


def _v1_funnel_actions(con: sqlite3.Connection) -> None:
    """Seat 1's canonical stage list needs `pass` and `merge` alongside kill/defer,
    and a `score_delta` so every point of a finding's rank traces to the stage that
    granted it. The action set is validated in Python (db.funnel) rather than by a
    CHECK, so the constraint does not have to be rebuilt again next time a stage is
    added."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(funnel_events)")}
    if "score_delta" in cols:
        return
    con.executescript("""
        ALTER TABLE funnel_events RENAME TO funnel_events_old;
        CREATE TABLE funnel_events (
            id              INTEGER PRIMARY KEY,
            run_id          INTEGER NOT NULL REFERENCES runs(id),
            occurrence_id   INTEGER REFERENCES occurrences(id),
            producer_id     TEXT    REFERENCES producers(id),
            stage           TEXT    NOT NULL,
            action          TEXT    NOT NULL,
            deterministic   INTEGER NOT NULL,
            reason          TEXT    NOT NULL,
            score_delta     REAL    NOT NULL DEFAULT 0,
            merged_into     INTEGER REFERENCES occurrences(id),
            actor           TEXT    NOT NULL DEFAULT 'system',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        INSERT INTO funnel_events
            (id,run_id,occurrence_id,producer_id,stage,action,deterministic,reason,actor,created_at)
        SELECT id,run_id,occurrence_id,producer_id,stage,action,deterministic,reason,actor,created_at
        FROM funnel_events_old;
        DROP TABLE funnel_events_old;
        CREATE INDEX IF NOT EXISTS idx_funnel_run ON funnel_events(run_id, stage);
        CREATE INDEX IF NOT EXISTS idx_funnel_occ ON funnel_events(occurrence_id);
    """)


def _v2_rank_view(con: sqlite3.Connection) -> None:
    """Rank is derived, never stored: the sum of every score_delta a finding was
    granted. That makes the ranker auditable by construction — you can always ask
    which stage gave a finding its position."""
    con.executescript("""
        DROP VIEW IF EXISTS occurrence_rank;
        CREATE VIEW occurrence_rank AS
        SELECT o.id AS occurrence_id,
               o.run_id,
               COALESCE(SUM(f.score_delta), 0) AS score
        FROM occurrences o
        LEFT JOIN funnel_events f ON f.occurrence_id = o.id
        GROUP BY o.id;
    """)


def _v3_issue_membership(con: sqlite3.Connection) -> None:
    """Cross-tool equivalence is a membership table, never a merge-and-delete (D8)."""
    con.executescript("""
        CREATE TABLE IF NOT EXISTS issue_members (
            issue_id    TEXT    NOT NULL REFERENCES issues(id),
            finding_id  TEXT    NOT NULL REFERENCES findings(id),
            run_id      INTEGER NOT NULL REFERENCES runs(id),
            PRIMARY KEY (issue_id, finding_id)
        );
        CREATE INDEX IF NOT EXISTS idx_member_finding ON issue_members(finding_id);
    """)


def _v4_repair_views(con: sqlite3.Connection) -> None:
    """`ALTER TABLE ... RENAME` rewrites references inside views, so v1's rebuild
    silently repointed `live_occurrences` at `funnel_events_old` — which v1 then
    dropped. The view kept parsing and failed only at query time. Recreate both views
    from their canonical definitions after any table rebuild."""
    con.executescript("""
        DROP VIEW IF EXISTS live_occurrences;
        CREATE VIEW live_occurrences AS
        SELECT o.*
        FROM occurrences o
        WHERE NOT EXISTS (
            SELECT 1 FROM funnel_events f
            WHERE f.occurrence_id = o.id
              AND f.action IN ('kill','defer','merge')
              AND f.id > COALESCE((SELECT MAX(r.id) FROM funnel_events r
                                   WHERE r.occurrence_id = o.id
                                     AND r.action = 'resurrect'), 0)
        );
        DROP VIEW IF EXISTS occurrence_rank;
        CREATE VIEW occurrence_rank AS
        SELECT o.id AS occurrence_id, o.run_id,
               COALESCE(SUM(f.score_delta), 0) AS score
        FROM occurrences o
        LEFT JOIN funnel_events f ON f.occurrence_id = o.id
        GROUP BY o.id;
    """)


def _v5_targets(con: sqlite3.Connection) -> None:
    """Target selection (D2/P1a). Scored components are stored separately from the
    total so a weighting change can be re-derived without re-fetching, and
    `covariates` holds audit-maturity signals that are deliberately NOT scored —
    selecting on "no SECURITY.md" begs the question the calibration run exists to
    answer (Seat 6)."""
    con.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            slug            TEXT PRIMARY KEY,
            score           REAL NOT NULL DEFAULT 0,
            surface         REAL NOT NULL DEFAULT 0,
            blast_radius    REAL NOT NULL DEFAULT 0,
            responsiveness  REAL NOT NULL DEFAULT 0,
            language        TEXT,
            stars           INTEGER,
            pushed_at       TEXT,
            archived        INTEGER NOT NULL DEFAULT 0,
            license_spdx    TEXT,
            covariates      TEXT NOT NULL DEFAULT '{}',
            reasons         TEXT NOT NULL DEFAULT '[]',
            stratum         TEXT,
            scored_at       TEXT NOT NULL DEFAULT (datetime('now')),
            scanned_run     INTEGER REFERENCES runs(id)
        );
        CREATE INDEX IF NOT EXISTS idx_targets_score ON targets(score DESC);
    """)


def _v6_research(con: sqlite3.Connection) -> None:
    """Deep-mode bookkeeping.

    One row per (subsystem x lens x model) unit of work, so a long run is resumable at
    the granularity it actually fails at, and the UI can show progress without the
    worker reporting to it. Findings themselves go into `occurrences` as ordinary
    producers keyed `deep:{lens}` — one row per lens, never one row for the whole
    layer, or it self-suppresses into the collapsed known-bad band by the second repo
    (Seats 2 and 4)."""
    con.executescript("""
        CREATE TABLE IF NOT EXISTS research_runs (
            id           INTEGER PRIMARY KEY,
            run_id       INTEGER NOT NULL REFERENCES runs(id),
            status       TEXT NOT NULL DEFAULT 'queued',
            models       TEXT NOT NULL DEFAULT '[]',
            lenses       TEXT NOT NULL DEFAULT '[]',
            profile      TEXT NOT NULL DEFAULT '{}',
            deadline     TEXT,
            started_at   TEXT NOT NULL DEFAULT (datetime('now')),
            finished_at  TEXT,
            note         TEXT
        );
        CREATE TABLE IF NOT EXISTS research_units (
            id            INTEGER PRIMARY KEY,
            research_id   INTEGER NOT NULL REFERENCES research_runs(id),
            subsystem     TEXT NOT NULL,
            weight        REAL NOT NULL DEFAULT 1,
            lens          TEXT NOT NULL,
            model         TEXT NOT NULL,
            phase         TEXT NOT NULL DEFAULT 'hunt',
            status        TEXT NOT NULL DEFAULT 'pending',
            tokens_in     INTEGER NOT NULL DEFAULT 0,
            seconds       REAL NOT NULL DEFAULT 0,
            n_findings    INTEGER NOT NULL DEFAULT 0,
            error         TEXT,
            updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE (research_id, subsystem, lens, model, phase)
        );
        CREATE INDEX IF NOT EXISTS idx_runits ON research_units(research_id, status);
        CREATE TABLE IF NOT EXISTS research_findings (
            id            INTEGER PRIMARY KEY,
            research_id   INTEGER NOT NULL REFERENCES research_runs(id),
            occurrence_id INTEGER REFERENCES occurrences(id),
            subsystem     TEXT NOT NULL,
            lens          TEXT NOT NULL,
            model         TEXT NOT NULL,
            family        TEXT NOT NULL,
            title         TEXT NOT NULL,
            file          TEXT,
            quote         TEXT,
            quote_verified INTEGER NOT NULL DEFAULT 0,
            severity      TEXT,
            reasoning     TEXT,
            attacker_control TEXT,
            self_critique TEXT,
            refutations   TEXT NOT NULL DEFAULT '[]',
            n_refuted     INTEGER NOT NULL DEFAULT 0,
            n_survived    INTEGER NOT NULL DEFAULT 0,
            refuter_errors INTEGER NOT NULL DEFAULT 0,
            agreement     TEXT NOT NULL DEFAULT '[]',
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_rfind ON research_findings(research_id);
    """)


def _v7_research_liveness(con: sqlite3.Connection) -> None:
    """A status column that is only ever written by the worker cannot report the
    worker dying. The first deep run showed `running` indefinitely after its process
    was killed — the UI stated something untrue and had no way to know better.

    `pid` and `host` make liveness checkable by the reader instead of reported by the
    writer, which is the only arrangement that survives the writer disappearing."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(research_runs)")}
    if "pid" not in cols:
        con.execute("ALTER TABLE research_runs ADD COLUMN pid INTEGER")
    if "host" not in cols:
        con.execute("ALTER TABLE research_runs ADD COLUMN host TEXT")
    if "heartbeat" not in cols:
        con.execute("ALTER TABLE research_runs ADD COLUMN heartbeat TEXT")


def _v8_advisories(con: sqlite3.Connection) -> None:
    """One row per advisory draft `quarry report` writes.

    The Markdown file stays the artifact; this row is how the dashboard finds it and
    how anyone can tell the file changed after it was written. `sha256` is of the
    content as written, so a hand edit (or a later run overwriting the same path)
    shows as a mismatch instead of passing as the original draft. `verdict_id` ties
    the draft to the exact dynamic verdict it was drafted from."""
    con.executescript("""
        CREATE TABLE IF NOT EXISTS advisories (
            id          INTEGER PRIMARY KEY,
            run_id      INTEGER NOT NULL REFERENCES runs(id),
            finding_id  TEXT    NOT NULL REFERENCES findings(id),
            verdict_id  INTEGER REFERENCES verdicts(id),
            path        TEXT    NOT NULL,
            sha256      TEXT    NOT NULL,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_advisories_run ON advisories(run_id);
    """)


MIGRATIONS = (_v1_funnel_actions, _v2_rank_view, _v3_issue_membership,
              _v4_repair_views, _v5_targets, _v6_research, _v7_research_liveness,
              _v8_advisories)


def migrate(con: sqlite3.Connection) -> int:
    version = con.execute("PRAGMA user_version").fetchone()[0]
    applied = 0
    for i, fn in enumerate(MIGRATIONS, start=1):
        if i <= version:
            continue
        fn(con)
        con.execute(f"PRAGMA user_version = {i}")
        applied += 1
    return applied
