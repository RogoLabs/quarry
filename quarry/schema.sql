-- Quarry schema. Ratified design points, from docs/PLAN.md:
--   D8  three identities; funnel_events ledger; defer != kill; NOTHING IS EVER DELETED
--   D9  SARIF is an export projection; each tool's native output kept verbatim
--   D15 evidence blobs at ingest, for killed occurrences too
--   D16 secrets stored as prefix+hash, never plaintext
--
-- Suppression is a row in funnel_events, never a DELETE and never a flag mutation.
-- Every query that shows "live" findings joins against the ledger. This is the
-- difference between a funnel you can audit and a funnel that is a lie (Seat 1, Seat 4).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

-- ---------------------------------------------------------------- runs

CREATE TABLE IF NOT EXISTS runs (
    id              INTEGER PRIMARY KEY,
    target          TEXT    NOT NULL,          -- owner/repo
    clone_url       TEXT    NOT NULL,
    git_sha         TEXT,                      -- pinned; evidence re-hydrates from this
    license_spdx    TEXT,                      -- drives the CodeQL gate
    license_osi     INTEGER,                   -- 1 = OSI-approved, 0 = not, NULL = unknown
    started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    status          TEXT    NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running','done','failed','cancelled')),
    volume_path     TEXT,                      -- sparse image mount; NULL once released
    manifest        TEXT    NOT NULL DEFAULT '{}'   -- tool versions, rule hashes, model ids, config hash
);

-- ---------------------------------------------------------------- producers
-- A producer is (tool, rule). The cross-repo precision ledger lives here; it is the
-- mechanism by which the deterministic layer improves, and the reason /triage is
-- more than a SARIF viewer (Seat 4, round 2).

CREATE TABLE IF NOT EXISTS producers (
    id              TEXT    PRIMARY KEY,       -- "opengrep:python.lang.security.audit.eval-detected"
    tool            TEXT    NOT NULL,
    rule_id         TEXT    NOT NULL,
    name            TEXT,
    cwe             TEXT,
    default_severity TEXT,
    help_uri        TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,   -- D8: dismissal sets 0, never deletes
    -- precision ledger, accumulated across every run ever
    n_occurrences   INTEGER NOT NULL DEFAULT 0,
    n_adjudicated   INTEGER NOT NULL DEFAULT 0,
    n_confirmed     INTEGER NOT NULL DEFAULT 0,
    dismissed_at    TEXT,
    dismissed_note  TEXT,
    UNIQUE (tool, rule_id)
);

-- ---------------------------------------------------------------- findings & issues
-- finding_id is LINE-NUMBER-FREE, hashed over (repo, path, enclosing symbol content,
-- producer). Verdicts key on this so a re-scan does not re-pay to re-reject the same
-- findings, and a reformat does not create 158 new ones (Seat 1).

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT    PRIMARY KEY,       -- finding_id
    target          TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    symbol          TEXT,                      -- enclosing function/class, if resolvable
    symbol_sha      TEXT,                      -- sha256 of the enclosing symbol's source
    producer_id     TEXT    NOT NULL REFERENCES producers(id),
    issue_id        TEXT,                      -- cross-tool equivalence class, assigned by clustering
    first_seen_run  INTEGER NOT NULL REFERENCES runs(id),
    last_seen_run   INTEGER NOT NULL REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_producer ON findings(producer_id);
CREATE INDEX IF NOT EXISTS idx_findings_issue    ON findings(issue_id);

-- Cross-tool equivalence classes. A membership table, never a merge-and-delete.
CREATE TABLE IF NOT EXISTS issues (
    id              TEXT    PRIMARY KEY,
    target          TEXT    NOT NULL,
    title           TEXT,
    cwe             TEXT,
    created_run     INTEGER NOT NULL REFERENCES runs(id)
);

-- ---------------------------------------------------------------- occurrences
-- One physical result, one run, one line. This is what a tool emitted.

CREATE TABLE IF NOT EXISTS occurrences (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    finding_id      TEXT    NOT NULL REFERENCES findings(id),
    producer_id     TEXT    NOT NULL REFERENCES producers(id),
    path            TEXT    NOT NULL,          -- validated at the taint boundary
    start_line      INTEGER,
    end_line        INTEGER,
    message         TEXT,
    severity        TEXT,                      -- the tool's claim. NEVER a sort key (§2.3).
    security_severity REAL,                    -- SARIF numeric, for export only
    fingerprint     TEXT,                      -- SARIF partialFingerprints/primaryLocationLineHash
    blob_sha        TEXT REFERENCES evidence_blobs(sha),
    redacted        INTEGER NOT NULL DEFAULT 0,   -- D16: secret material replaced by prefix+hash
    secret_prefix   TEXT,                      -- first 4 chars only
    secret_sha      TEXT,                      -- sha256 of the full match
    raw_result      TEXT    NOT NULL DEFAULT '{}'  -- D9: the tool's native JSON, verbatim
);
CREATE INDEX IF NOT EXISTS idx_occ_run     ON occurrences(run_id);
CREATE INDEX IF NOT EXISTS idx_occ_finding ON occurrences(finding_id);

-- ---------------------------------------------------------------- the funnel ledger
-- D8. Every suppression is a reversible, attributed event. `defer` is not `kill`.
-- Recall accounting is impossible without this table, and a funnel whose per-stage
-- recall cost you cannot measure is indistinguishable from a bug (Seat 1).

CREATE TABLE IF NOT EXISTS funnel_events (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    occurrence_id   INTEGER REFERENCES occurrences(id),
    producer_id     TEXT    REFERENCES producers(id),   -- set for producer-wide dismissals
    stage           TEXT    NOT NULL,   -- quote-verify | test-path | local-dev-fixture | dedup
                                        -- | corroboration | severity-floor | per-file-cap
                                        -- | budget-ceiling | operator | rule-disabled
    action          TEXT    NOT NULL CHECK (action IN ('kill','defer','boost','resurrect')),
    deterministic   INTEGER NOT NULL,   -- 0 => UI flags it as a RECALL RISK (Seat 4)
    reason          TEXT    NOT NULL,
    actor           TEXT    NOT NULL DEFAULT 'system',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_funnel_run   ON funnel_events(run_id, stage);
CREATE INDEX IF NOT EXISTS idx_funnel_occ   ON funnel_events(occurrence_id);

-- ---------------------------------------------------------------- evidence
-- D15. Content-addressed source windows captured at the taint boundary, for every
-- occurrence including killed ones. The code pane must never depend on the clone
-- surviving: ~8k unique windows per 18k occurrences, ~32 MB raw / ~9 MB gzipped,
-- and that figure scales with finding count, not repo size (Seats 4 + 5).

CREATE TABLE IF NOT EXISTS evidence_blobs (
    sha             TEXT    PRIMARY KEY,       -- sha256 of the window text
    path            TEXT    NOT NULL,
    file_sha256     TEXT    NOT NULL,          -- of the whole file, for re-hydration checks
    git_sha         TEXT,
    start_line      INTEGER NOT NULL,
    end_line        INTEGER NOT NULL,
    body            BLOB    NOT NULL,          -- zstd/gzip, redacted at this same boundary
    encoding        TEXT    NOT NULL DEFAULT 'gzip',
    bytes           INTEGER NOT NULL
);

-- ---------------------------------------------------------------- adjudication

CREATE TABLE IF NOT EXISTS verdicts (
    id              INTEGER PRIMARY KEY,
    finding_id      TEXT    NOT NULL REFERENCES findings(id),   -- carries forward across runs
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    seat            TEXT    NOT NULL DEFAULT 'chair',
    model           TEXT    NOT NULL,
    effort          TEXT,
    verdict         TEXT    NOT NULL CHECK (verdict IN ('confirmed','needs-review','rejected')),
    reason          TEXT,                      -- the six-class taxonomy + local-dev-fixture
    adjusted_severity TEXT,
    cvss_vector     TEXT,
    cwe             TEXT,
    evidence_score  INTEGER NOT NULL DEFAULT 0,   -- executed evidence outranks argued (Seat 4)
    executed_score  INTEGER NOT NULL DEFAULT 0,
    rationale       TEXT,
    cost_usd        REAL    NOT NULL DEFAULT 0,
    cache_read_tokens    INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_verdict_finding ON verdicts(finding_id);

-- ---------------------------------------------------------------- egress ledger
-- Seat 5, P0 step 8. One row per outbound call, rendered on /runs/:id.
-- "Completely local" is a claim that has to be auditable to mean anything.

CREATE TABLE IF NOT EXISTS egress (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER REFERENCES runs(id),
    stage           TEXT    NOT NULL,
    destination     TEXT    NOT NULL,
    bytes_out       INTEGER NOT NULL DEFAULT 0,
    bytes_in        INTEGER NOT NULL DEFAULT 0,
    note            TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_egress_run ON egress(run_id);

-- ---------------------------------------------------------------- quarantine
-- D14. Target-supplied scanner config is moved aside, never loaded, never deleted —
-- it is evidence. Suppression reason strings must never reach a model (Seat 1).

CREATE TABLE IF NOT EXISTS quarantined (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    original_path   TEXT    NOT NULL,
    kind            TEXT    NOT NULL,   -- loader-config | suppression | symlink
    detail          TEXT,
    sha256          TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_quarantine_run ON quarantined(run_id);

-- ---------------------------------------------------------------- live view
-- The one place the ledger semantics are encoded. Everything that shows findings
-- goes through this, so "killed" can never drift between call sites.

CREATE VIEW IF NOT EXISTS live_occurrences AS
SELECT o.*
FROM occurrences o
WHERE NOT EXISTS (
    SELECT 1 FROM funnel_events f
    WHERE f.occurrence_id = o.id
      AND f.action = 'kill'
      AND f.id > COALESCE((SELECT MAX(r.id) FROM funnel_events r
                           WHERE r.occurrence_id = o.id AND r.action = 'resurrect'), 0)
);
