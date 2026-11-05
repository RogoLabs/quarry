"""quarry: command line entry point."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import config, db, funnel as funnel_mod, orchestrator, targets as targets_mod, vulndb

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Local-first repository security audit. Nothing leaves this machine "
                       "without an explicit, separate action.")
con_out = Console()


def _open() -> tuple[config.Paths, object]:
    paths = config.paths()
    first = not paths.db.exists()
    connection = db.init(paths.db) if first else db.connect(paths.db)
    if first:
        con_out.print(f"[dim]initialised {escape(str(paths.db))}[/]")
    return paths, connection


def _e(value) -> str:
    """Untrusted text for a rich markup string or table cell.

    Paths, messages, git stderr, finding ids and profile evidence come from scanned
    repositories, and rich parses `[...]` in them as markup: a file named `a[/b].py`
    crashed `quarry killed` with a MarkupError. None renders as an empty string.
    """
    return "" if value is None else escape(str(value))


db_app = typer.Typer(help="Vulnerability-database provisioning: the one deliberate "
                          "network step. Scanners never fetch their own databases.")
app.add_typer(db_app, name="db")


@db_app.command("sync")
def db_sync(timeout: int = typer.Option(900)) -> None:
    """Fetch Trivy/Grype/OSV databases into the sandbox-readable DB directory."""
    _, connection = _open()
    con_out.print(f"[dim]{_e(vulndb.db_dir())}[/]")
    for r in vulndb.sync_all(connection, timeout=timeout):
        mark = "[green]ok[/]" if r.ok else "[red]fail[/]"
        con_out.print(f"  {_e(f'{r.name:14s}')} {mark} {r.seconds:5.1f}s  {_e(r.detail)}")
    con_out.print(_db_table())


@db_app.command("status")
def db_status() -> None:
    """Show which vulnerability databases are present, and how old each one is."""
    con_out.print(_db_table())


def _db_table() -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("database"); t.add_column("size"); t.add_column("built")
    t.add_column("age"); t.add_column("read from")
    ages = vulndb.ages()
    for k, v in vulndb.status().items():
        a = ages.get(k, {})
        days = a.get("age_days")
        age = ("[dim]?[/]" if days is None else
               f"[red]{days:.1f} d[/]" if days > vulndb.STALE_DAYS else f"{days:.1f} d")
        t.add_row(_e(k), _e(v), _e((a.get("built") or "")[:19]), age,
                  f"[dim]{_e(a.get('basis', ''))}[/]")
    return t


#: The only binds `serve` accepts. The dashboard has no authentication and its routes
#: spawn processes and send signals, so it must not be reachable from another host;
#: these are also exactly the Host values the app's own allowlist accepts.
LOOPBACK_BINDS = ("127.0.0.1", "localhost", "::1")


@app.command()
def serve(host: str = typer.Option("127.0.0.1", help="loopback only: 127.0.0.1, localhost or ::1"),
          port: int = typer.Option(8099),
          reload: bool = typer.Option(False)) -> None:
    """Start the triage dashboard. Binds to loopback only; it has no authentication."""
    import uvicorn
    bind = host.strip("[]")
    if bind.lower() not in LOOPBACK_BINDS:
        con_out.print(f"[red]refusing:[/] --host {escape(host)} is not a loopback "
                      "address. The dashboard has no authentication and can start and "
                      "stop processes, so it binds only to "
                      f"{', '.join(LOOPBACK_BINDS)}. To reach it from elsewhere, use an "
                      "SSH tunnel (ssh -L 8099:127.0.0.1:8099 host).")
        raise typer.Exit(2)
    _open()   # ensure the schema and migrations are current before the server starts
    shown = f"[{bind}]" if ":" in bind else bind
    con_out.print(f"[bold]quarry[/] at {escape(f'http://{shown}:{port}/triage')}")
    uvicorn.run("quarry.web.app:app", host=bind, port=port, reload=reload,
                log_level="warning")


targets_app = typer.Typer(help="Target selection (PLAN D2 / P1a). Scored on attack "
                               "surface, blast radius and maintainer responsiveness. "
                               "Audit maturity is recorded as a covariate, never scored.")
app.add_typer(targets_app, name="targets")


@targets_app.command("score")
def targets_score(slugs: list[str] = typer.Argument(..., help="owner/repo ..."),
                  stratum: str = typer.Option("", help="label this batch, e.g. popular | unaudited")) -> None:
    """Score one or more candidate targets."""
    _, connection = _open()
    rows = []
    with con_out.status("scoring…"):
        for slug in slugs:
            ts = targets_mod.score_target(slug)
            with db.tx(connection):
                # The ledger is written whether or not the score succeeded: the
                # requests left the machine either way, and `doctor` reads this table
                # to answer "which hosts has this tool contacted".
                targets_mod.log_egress(connection, ts)
                if ts.ok:
                    targets_mod.save(connection, ts, stratum or None)
            rows.append(ts)
    t = Table(show_header=True, header_style="bold")
    for c, j in (("target", "left"), ("score", "right"), ("surface", "right"),
                 ("blast", "right"), ("resp", "right"), ("lang", "left"),
                 ("scorecard", "right"), ("note", "left")):
        t.add_column(c, justify=j)
    for ts in sorted(rows, key=lambda x: -x.score):
        sc = ts.covariates.get("openssf_scorecard")
        t.add_row(_e(ts.slug), f"{ts.score:.0f}", f"{ts.surface:.0f}",
                  f"{ts.blast_radius:.0f}", f"{ts.responsiveness:.0f}",
                  _e(ts.language or "-"), f"{sc:.1f}" if sc else "-",
                  f"[red]{_e(ts.error)}[/]" if ts.error else
                  ("[dim]archived[/]" if ts.archived else ""))
    con_out.print(t)
    con_out.print("[dim]Covariates (Scorecard, SECURITY.md, CodeQL) are recorded but never "
                  "scored: selecting on them would beg the calibration run's question.[/]")


@targets_app.command("why")
def targets_why(slug: str) -> None:
    """Show every component of one target's score."""
    _, connection = _open()
    r = connection.execute("SELECT * FROM targets WHERE slug=?", (slug,)).fetchone()
    if not r:
        con_out.print(f"[yellow]{_e(slug)} has not been scored.[/]")
        raise typer.Exit(1)
    con_out.print(f"[bold]{_e(slug)}[/]  score [bold]{r['score']:.0f}[/] = "
                  f"surface {r['surface']:.0f} + blast {r['blast_radius']:.0f} + "
                  f"responsiveness {r['responsiveness']:.0f}")
    for reason in json.loads(r["reasons"]):
        con_out.print(f"   · {_e(reason)}")
    con_out.print("[dim]covariates (not scored):[/] "
                  + _e(json.dumps(json.loads(r["covariates"]))))


@targets_app.command("list")
def targets_list(limit: int = typer.Option(25), stratum: str = typer.Option("")) -> None:
    """Ranked candidates."""
    _, connection = _open()
    t = Table(show_header=True, header_style="bold")
    for c in ("target", "score", "surface", "blast", "resp", "lang", "stratum", "scanned"):
        t.add_column(c)
    for r in targets_mod.ranked(connection, limit, stratum or None):
        t.add_row(_e(r["slug"]), f"{r['score']:.0f}", f"{r['surface']:.0f}",
                  f"{r['blast_radius']:.0f}", f"{r['responsiveness']:.0f}",
                  _e(r["language"] or "-"), _e(r["stratum"] or "-"),
                  str(r["scanned_run"] or "-"))
    con_out.print(t)


DEFAULT_DEEP_MODELS = "qwen3-coder:30b,gpt-oss:20b,devstral:24b"


@app.command()
def deep(run_id: int = typer.Argument(..., help="an ingested run"),
         models: str = typer.Option(DEFAULT_DEEP_MODELS,
                                    help="comma-separated; must span >=2 families"),
         until: str = typer.Option("", help="stop at HH:MM (e.g. 07:00)"),
         hours: float = typer.Option(0.0, help="stop after N hours"),
         no_refute: bool = typer.Option(False, help="skip cross-family refutation"),
         resume: int = typer.Option(0, help="resume an existing research id")) -> None:
    """Deep multi-model review: several model families read the repo independently.

    Interruptible by design: work is committed per (subsystem x lens x model) unit, so
    stopping costs one unit, and `--resume` picks up where it left off.
    """
    from datetime import datetime, timedelta
    from .ingest import RunVolume
    from .research import runner

    paths, connection = _open()
    src = RunVolume.attach_existing(run_id, paths.runs).src
    mods = [m.strip() for m in models.split(",") if m.strip()]
    fams = {__import__("quarry.research.ensemble", fromlist=["family"]).family(m)
            for m in mods}
    if len(fams) < 2:
        con_out.print(f"[red]refusing:[/] all models are family {_e(fams)}, so "
                      f"cross-family refutation is impossible, and same-family review "
                      f"is the configuration measured at -37.6%.")
        raise typer.Exit(1)

    deadline = None
    if hours > 0:
        deadline = datetime.now() + timedelta(hours=hours)
    elif until:
        hh, mm = (int(x) for x in until.split(":"))
        d = datetime.now().replace(hour=hh, minute=mm, second=0, microsecond=0)
        deadline = d + timedelta(days=1) if d <= datetime.now() else d

    if resume:
        rid = resume
        con_out.print(f"resuming research run {rid}")
    else:
        rid, subs, lenses = runner.plan(connection, run_id, src, models=mods)
        con_out.print(f"[bold]research {rid}[/] · {len(subs)} subsystem(s) × "
                      f"{len(lenses)} lens(es) × {len(mods)} model(s) = "
                      f"[bold]{len(subs) * len(lenses) * len(mods)}[/] units")
        con_out.print(f"  lenses: {_e(', '.join(l.key for l in lenses))}")
        con_out.print(f"  families: {_e(', '.join(sorted(fams)))}")
    if deadline:
        con_out.print(f"  deadline: {deadline:%H:%M} "
                      f"({(deadline - datetime.now()).total_seconds()/3600:.1f}h)")

    stats = runner.execute(connection, rid, src, deadline=deadline,
                           progress=lambda m: con_out.print(_e(m)), refute=not no_refute)
    t = Table(show_header=False, box=None)
    for k, v in stats.items():
        t.add_row(_e(k.replace("_", " ")), _e(v))
    con_out.print(t)
    # Candidates face the Layer 2 gate now rather than sitting in triage unfunnelled.
    # Ones still awaiting refutation are deferred, and a later pass revives them.
    con_out.print("[bold]funnel pass[/] over the new candidates")
    _print_funnel(funnel_mod.run(connection, run_id, src=src))
    con_out.print(f"[dim]watch it at http://127.0.0.1:8099/research/{rid}[/]")


@app.command("deep-verdict")
def deep_verdict(research_finding_id: int = typer.Argument(
                     ..., help="a research finding id (quarry deep-survivors lists them)"),
                 verdict: str = typer.Argument(..., help="intended | real | unclear"),
                 note: str = typer.Option(..., "--note",
                                          help="why; a later run shows it to the refuter"),
                 by: str = typer.Option("operator", "--by", help="who judged it")) -> None:
    """Record a human verdict on a Layer 2 deep-review finding.

    Appended, never overwritten: the newest verdict on a finding is its current one. The
    next deep run on the same target matches its findings against this one (same lens and
    file, and a matching quote or enclosing symbol). An `intended` match is shown to the
    refuter, and if it survives it is listed as previously judged intended, not as new.
    """
    from .research import verdicts
    _, connection = _open()
    try:
        vid = verdicts.record(connection, research_finding_id, verdict, note, actor=by)
    except verdicts.VerdictError as e:
        con_out.print(f"[red]refusing:[/] {_e(e)}")
        raise typer.Exit(1)
    rf = connection.execute("SELECT lens, file, quote_verified, n_survived "
                            "FROM research_findings WHERE id=?",
                            (research_finding_id,)).fetchone()
    con_out.print(f"verdict {vid}: research finding {research_finding_id} "
                  f"({_e(rf['lens'])}, {_e(rf['file'])}) is "
                  f"[bold]{_e(verdict.strip().lower())}[/]")
    if not (rf["quote_verified"] and rf["n_survived"]):
        con_out.print("[yellow]note:[/] this finding is not a Layer 2 survivor (quote not "
                      "verified, or no cross-family model defended it); recorded anyway")


@app.command("deep-survivors")
def deep_survivors(run_id: int = typer.Argument(..., help="a run with a deep review")) -> None:
    """List a run's Layer 2 survivors with their human verdicts.

    A survivor clears the bar the report digest uses: the quote verified, and a model of
    another family defended it. Survivors that matched an earlier human verdict are
    listed apart from new ones, so a finding already judged intended is not presented as
    new."""
    from .research import verdicts
    _, connection = _open()
    rows = verdicts.survivors(connection, run_id)
    if not rows:
        con_out.print(f"[dim]no deep-review survivors for run {run_id}[/]")
        return
    groups = (("new", [r for r in rows if not r["prior_verdict"]]),
              ("previously judged intended",
               [r for r in rows if r["prior_verdict"] == "intended"]),
              ("previously judged real or unclear",
               [r for r in rows if r["prior_verdict"] in ("real", "unclear")]))
    for label, group in groups:
        if not group:
            continue
        t = Table(title=f"{len(group)} {label}", show_header=True, header_style="bold")
        for c in ("id", "lens", "file", "title", "vote", "verdict", "prior"):
            t.add_column(c)
        for r in group:
            prior = f"{r['prior_verdict']} (#{r['prior_rf']})" if r["prior_verdict"] else "-"
            t.add_row(str(r["id"]), _e(r["lens"]), _e(r["file"]), _e(r["title"]),
                      f"{r['n_survived']} defended / {r['n_refuted']} refuted",
                      _e(r["verdict"] or "-"), _e(prior))
        con_out.print(t)
    for r in rows:
        if r["verdict"]:
            con_out.print(f"  #{r['id']} {_e(r['verdict'])} ({_e(r['verdict_at'])} UTC, "
                          f"{_e(r['verdict_by'])}): {_e(r['note'])}")
        if r["prior_verdict"]:
            con_out.print(f"  #{r['id']} matched #{r['prior_rf']} ({_e(r['prior_match'])}), "
                          f"judged {_e(r['prior_verdict'])} {_e(r['prior_at'])} UTC: "
                          f"{_e(r['prior_note'])}")
    con_out.print(f"[dim]{len(rows)} survivor(s): {len(groups[0][1])} new, "
                  f"{len(groups[1][1])} previously judged intended, "
                  f"{sum(1 for r in rows if not r['verdict'])} without a verdict of their "
                  f"own. Record one with: quarry deep-verdict <id> intended|real|unclear "
                  f"--note \"...\"[/]")


def _print_replay(result: dict) -> None:
    s = result["score"]
    t = Table(show_header=True, header_style="bold")
    for c in ("repo", "lenses", "units", "claims", "unsupported", "survivors",
              "plants found (hunt)", "plants found (after refute)", "wall s"):
        t.add_column(c)
    for repo, r in result["repos"].items():
        p = s["per_repo"][repo]
        t.add_row(_e(repo), _e(", ".join(r["lenses"])), str(r["units"]), str(p["claims"]),
                  str(p["unsupported"]), str(p["survivors"]),
                  f"{p['found_at_hunt']}/{p['plants']}",
                  f"{p['found_after_refute']}/{p['plants']}", f"{r['wall_seconds']:.0f}")
    con_out.print(t)
    m, u = s["missed_after_refute"], s["unsupported_claims"]
    con_out.print(f"missed at the hunt: {s['missed_at_hunt']['n']}/{s['plants']} "
                  f"{_e(s['missed_at_hunt']['ids'])}; missed after refutation: "
                  f"{m['n']}/{s['plants']} {_e(m['ids'])}; unsupported claims: "
                  f"{u['n']}/{u['of']}; wall {result['wall_seconds']:.0f} s"
                  + ("" if result["complete"] else " [red](incomplete: cut by the cap)[/]"))


@app.command("deep-replay")
def deep_replay(models: str = typer.Option("qwen3-coder:30b,devstral:24b",
                                           help="comma-separated; must span >=2 families"),
                corpus: str = typer.Option("", help="corpus dir (default: the committed "
                                                    "tests/fixtures/replay)"),
                out: str = typer.Option("", help="result JSON (default: "
                                                 "<data>/replay/<stamp>.json)"),
                no_route_intent: bool = typer.Option(False, help="prompts as before item "
                                                                 "20, to measure it"),
                max_minutes: float = typer.Option(0.0, help="safety cap; a cut replay is "
                                                            "marked incomplete")) -> None:
    """Replay the fixed planted-bug set through Layer 2 and score it.

    Scores missed plants (at the hunt and after cross-family refutation), unsupported
    claims (quote not in the source) and wall time, with the models, their digests, the
    budget and the lens set recorded. Uses a scratch database, never the operator's.
    Compare two results with `quarry deep-replay-compare`."""
    from datetime import datetime
    from .research import replay
    paths = config.paths()
    c = replay.load(Path(corpus) if corpus else replay.DEFAULT_CORPUS)
    problems = replay.preflight(c)
    if problems:
        for p in problems:
            con_out.print(f"[red]preflight:[/] {_e(p)}")
        raise typer.Exit(1)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    workdir = paths.root / "replay" / stamp
    mods = [m.strip() for m in models.split(",") if m.strip()]
    con_out.print(f"replaying {_e(c.name)}: {len(c.plants)} plants in "
                  f"{len(c.repos)} repositories, models {_e(', '.join(mods))}, "
                  f"route intent {'off' if no_route_intent else 'on'}")
    try:
        result = replay.run(c, mods, workdir=workdir, route_intent=not no_route_intent,
                            max_minutes=max_minutes,
                            progress=lambda m: con_out.print(_e(m)))
    except ValueError as e:
        con_out.print(f"[red]refusing:[/] {_e(e)}")
        raise typer.Exit(1)
    dest = Path(out) if out else paths.root / "replay" / f"{stamp}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2, default=str))
    _print_replay(result)
    con_out.print(f"[dim]result: {_e(dest)}[/]")


@app.command("deep-replay-compare")
def deep_replay_compare(before: str = typer.Argument(..., help="earlier result JSON"),
                        after: str = typer.Argument(..., help="later result JSON"),
                        rescore: bool = typer.Option(False, help="score both again with "
                                                                 "the current scorer"),
                        corpus: str = typer.Option("", help="corpus dir for --rescore")
                        ) -> None:
    """Compare two replay results. A tie is a valid result; differing models, digests,
    budget, lens set or corpus make the pair not comparable, and it says which."""
    from .research import replay
    a, b = (json.loads(Path(p).read_text()) for p in (before, after))
    if rescore:
        c = replay.load(Path(corpus) if corpus else replay.DEFAULT_CORPUS)
        try:
            a, b = replay.rescore(a, c), replay.rescore(b, c)
        except ValueError as e:
            con_out.print(f"[red]refusing:[/] {_e(e)}")
            raise typer.Exit(1)
        con_out.print("[dim]both rescored with the current scorer[/]")
    d = replay.compare(a, b)
    colour = {"better": "green", "worse": "red", "tie": "bold",
              "mixed": "yellow"}.get(d["verdict"], "red")
    con_out.print(f"[{colour}]{_e(d['verdict'])}[/]")
    for k, v in d["deltas"].items():
        con_out.print(f"  {_e(k)}: {v:+}")
    con_out.print(f"  claims: {d['claims'][0]} -> {d['claims'][1]}; unsupported: "
                  f"{_e(d['unsupported_claims'][0])} -> {_e(d['unsupported_claims'][1])}")
    con_out.print(f"  missed after refutation: {_e(d['missed_after_refute_ids'][0])} -> "
                  f"{_e(d['missed_after_refute_ids'][1])}")
    con_out.print(f"  wall seconds: {d['wall_seconds'][0]} -> {d['wall_seconds'][1]} "
                  f"(reported, not scored)")
    for k, v in d["what_changed"].items():
        con_out.print(f"  changed {_e(k)}: {_e(v[0])} -> {_e(v[1])}")
    for k, v in d["fixed_differs"].items():
        con_out.print(f"  [red]fixed but differs[/] {_e(k)}: {_e(v[0])} -> {_e(v[1])}")


@app.command()
def doctor() -> None:
    """Check the environment: data root, containment, and which tools are present."""
    paths, _ = _open()
    t = Table(title="quarry doctor", show_header=True, header_style="bold")
    t.add_column("check"); t.add_column("result")
    t.add_row("data root", _e(paths.root))
    t.add_row("filesystem", _e(config._filesystem(paths.root) or "?"))
    t.add_row("sync xattrs", _e(", ".join(config._xattrs(paths.root)) or "none"))
    from .sandbox import CLONE_PROFILE, PROFILE
    t.add_row("tier1 profile", "present" if PROFILE.exists() else "[red]MISSING[/]")
    t.add_row("clone profile", "present" if CLONE_PROFILE.exists() else "[red]MISSING[/]")
    con_out.print(t)

    # Cost posture, stated plainly. P0-P1a are entirely local; the LLM layers are
    # gated behind the calibration run (PLAN D3/D12) and no model code path exists yet.
    _, connection = _open()
    spend = connection.execute(
        "SELECT COUNT(*) n, COALESCE(SUM(cost_usd),0) c FROM verdicts").fetchone()
    hosts = connection.execute(
        "SELECT DISTINCT destination FROM egress ORDER BY destination").fetchall()
    c = Table(title="cost posture", show_header=True, header_style="bold")
    c.add_column("check"); c.add_column("result")
    # Detect without importing: `import anthropic` here would itself be a
    # model-provider import, which is exactly what tests/test_no_paid_models.py
    # forbids — and it correctly caught this the first time it was written that way.
    import importlib.util
    present = [n for n in ("anthropic", "openai", "cohere", "mistralai", "litellm")
               if importlib.util.find_spec(n) is not None]
    c.add_row("model provider",
              f"[red]{', '.join(present)} installed[/]" if present
              else "[green]no model-provider SDK installed[/]")
    c.add_row("adjudicator", "[green]not built: gated on the calibration run (D3/D12)[/]")
    c.add_row("paid calls made", f"{spend['n']}")
    c.add_row("total spend", f"[green]${spend['c']:.4f}[/]")
    c.add_row("hosts contacted", _e(", ".join(h["destination"] for h in hosts) or "none"))
    con_out.print(c)

    dbs = _db_table()
    dbs.title = f"vulnerability databases (stale past {vulndb.STALE_DAYS} days)"
    con_out.print(dbs)

    m = orchestrator.tool_manifest()
    t2 = Table(title="tools", show_header=True, header_style="bold")
    t2.add_column("tool"); t2.add_column("version")
    for k, v in m.items():
        t2.add_row(_e(k), _e(v) if v else "[dim]absent[/]")
    con_out.print(t2)


@app.command()
def ingest(target: str = typer.Argument(..., help="owner/repo"),
           size_gb: int = typer.Option(20, help="run volume quota"),
           keep: bool = typer.Option(True, help="keep the run volume mounted")) -> None:
    """Clone a target into a contained run volume and record it."""
    paths, connection = _open()
    try:
        with con_out.status(f"ingesting {_e(target)}…"):
            res = orchestrator.ingest(paths, connection, target, size_gb=size_gb, keep_volume=keep)
    except RuntimeError as e:
        con_out.print(f"[red]ingest failed[/] {_e(e)}")
        if "Authentication failed" in str(e) or "not found" in str(e).lower():
            con_out.print("[dim]Ingest clones anonymously and holds no credential by design "
                          "(PLAN D6), so private repositories are not reachable from this path.[/]")
        raise typer.Exit(1)

    t = Table(show_header=False, box=None)
    t.add_row("run", str(res.run_id))
    t.add_row("target", _e(res.target))
    t.add_row("sha", _e(res.git_sha or "?"))
    t.add_row("license", _e(f"{res.license_spdx or 'none'}  "
                            f"({'OSI' if res.license_osi else 'not OSI'})"))
    t.add_row("files", str(res.files))
    t.add_row("symlinks removed", str(res.symlinks_removed))
    t.add_row("configs quarantined", str(res.configs_quarantined))
    if res.volume:
        t.add_row("volume", _e(res.volume.mount))
    con_out.print(t)
    for n in res.notes:
        con_out.print(f"[yellow]note[/] {_e(n)}")


@app.command()
def scan(run_id: int = typer.Argument(..., help="an ingested run"),
         only: str = typer.Option("", help="comma-separated tool names"),
         timeout: int = typer.Option(1800)) -> None:
    """Run the deterministic layer (Layer 1) over an ingested run. No model calls."""
    paths, connection = _open()
    tools = [t.strip() for t in only.split(",") if t.strip()] or None
    try:
        with con_out.status(f"scanning run {run_id}…"):
            s = orchestrator.scan(paths, connection, run_id, only=tools, timeout=timeout)
    except orchestrator.AlreadyScanned as e:
        con_out.print(f"[red]refused[/]: {_e(e)}")
        raise typer.Exit(2)

    t = Table(show_header=True, header_style="bold")
    for c in ("tool", "rc", "secs", "records", "note"):
        t.add_column(c)
    for name, info in s.per_tool.items():
        note = _e(info["skipped"] or info["error"] or info.get("note") or "")
        style = "dim" if info["skipped"] or info.get("note") else ("red" if info["error"] else "")
        t.add_row(_e(name), str(info["rc"]), str(info["seconds"]), str(info["records"]),
                  f"[{style}]{note}[/{style}]" if style else note)
    con_out.print(t)
    con_out.print(f"[bold]{s.occurrences}[/] occurrences · [bold]{s.findings}[/] distinct findings · "
                  f"{s.evidence_blobs} evidence blobs ({s.evidence_bytes/1024:.0f} KB gzipped)")
    _print_health(s.health)


def _print_health(by_tool: dict) -> None:
    for tool, msgs in by_tool.items():
        for m in msgs:
            con_out.print(f"[red bold]health[/] {_e(tool)}: {_e(m)}")


@app.command()
def funnel(run_id: int = typer.Argument(..., help="a scanned run"),
           top_k: int = typer.Option(0, help="budget cut; 0 = no cut")) -> None:
    """Run the deterministic funnel over a scanned run's new occurrences. Free, and
    nothing is deleted. Safe to repeat: each occurrence goes through once."""
    paths, connection = _open()
    from .ingest import RunVolume
    try:
        src = RunVolume.attach_existing(run_id, paths.runs).src
    except Exception:
        src = None
    res = funnel_mod.run(connection, run_id, src=src,
                         budget_top_k=top_k if top_k > 0 else None)
    _print_funnel(res)


def _print_funnel(res) -> None:
    if not res.started_with:
        con_out.print(f"[dim]run {res.run_id}: nothing new to funnel; every occurrence "
                      f"has already been through it[/]")
        return
    t = Table(show_header=True, header_style="bold")
    for c in ("#", "stage", "killed", "deferred", "merged", "boosted", "remaining"):
        t.add_column(c, justify="right" if c not in ("stage",) else "left")
    for i, s in enumerate(res.stages, 1):
        name = f"[yellow]⚠ {_e(s.stage)}[/]" if s.heuristic else _e(s.stage)
        t.add_row(str(i), name,
                  str(s.killed) if s.killed else "[dim]·[/]",
                  str(s.deferred) if s.deferred else "[dim]·[/]",
                  str(s.merged) if s.merged else "[dim]·[/]",
                  str(s.boosted) if s.boosted else "[dim]·[/]",
                  str(s.remaining))
    con_out.print(t)
    pct = 100 * res.survivors / res.started_with if res.started_with else 0
    con_out.print(f"[bold]{res.started_with}[/] → [bold]{res.survivors}[/] survive "
                  f"({pct:.0f}%). [yellow]⚠[/] = heuristic stage, carries recall risk. "
                  f"Nothing deleted; every suppression is reversible.")
    _print_health(res.health)


@app.command()
def killed(run_id: int, stage: str = typer.Option("", help="filter to one stage"),
           limit: int = typer.Option(15)) -> None:
    """Audit what the funnel suppressed, and why. Every number links to its set."""
    _, connection = _open()
    sql = """SELECT f.stage, f.action, f.reason, f.deterministic, o.path, o.start_line,
                    p.id AS producer
             FROM funnel_events f
             JOIN occurrences o ON o.id = f.occurrence_id
             JOIN producers p ON p.id = o.producer_id
             WHERE f.run_id = ? AND f.action IN ('kill','defer','merge')"""
    args: list = [run_id]
    if stage:
        sql += " AND f.stage = ?"
        args.append(stage)
    sql += " ORDER BY f.id DESC LIMIT ?"
    args.append(limit)
    t = Table(show_header=True, header_style="bold")
    for c in ("stage", "action", "producer", "location", "reason"):
        t.add_column(c, overflow="fold")
    for r in connection.execute(sql, args):
        mark = "" if r["deterministic"] else "[yellow]⚠[/] "
        # Truncate first, then escape: escaping adds backslashes that a later slice
        # could cut in half.
        t.add_row(f"{mark}{_e(r['stage'])}", _e(r["action"]), _e(r["producer"][:34]),
                  _e(f"{r['path']}:{r['start_line'] or ''}"), _e((r["reason"] or "")[:70]))
    con_out.print(t)


@app.command()
def validate(run_id: int = typer.Argument(..., help="a scanned + funnelled run"),
             limit: int = typer.Option(50, help="max candidates to probe"),
             dry_run: bool = typer.Option(False, help="profile and plan only; probe nothing"),
             build_network: bool = typer.Option(
                 False, "--build-network",
                 help="let Dockerfile RUN steps reach the network while the target is "
                      "built; they still get none of your environment or credentials, "
                      "and the running target stays offline"),
             env: list[str] = typer.Option(
                 [], "--env",
                 help="KEY=VALUE for one of the target's own variables, such as a "
                      "placeholder its sample .env ships; repeatable"),
             memory: str = typer.Option(
                 "2g", help="memory cap for each of the target's services, like 6g"),
             seed: str = typer.Option(
                 "", help="run a named seed recipe's setup commands (the target's own) "
                          "in the contained instance before probing, e.g. vulnlookup")
             ) -> None:
    """Layer 3: stand the target up and probe surviving findings into
    confirmed-or-killed verdicts. Which probes run is chosen from what the codebase is.
    The target runs from a compose document Quarry rebuilds: builds get no network
    unless you pass --build-network, and nothing from your shell environment is
    interpolated."""
    from .ingest import RunVolume
    from .dynamic import runtime_docker, plan_validation, run_validation

    paths, connection = _open()
    vol = RunVolume.attach_existing(run_id, paths.runs)

    if dry_run:
        runtime_docker.register()
        plan = plan_validation(connection, run_id, vol.src)
        con_out.print(f"[bold]{_e(plan.artifact_kind)}[/] · {len(plan.candidates)} candidate(s)"
                      f" · {plan.routed}/{len(plan.candidates)} routed · {plan.routes_found} routes"
                      f" · runtime: {_e(plan.runtime_reason)}")
        for key, n, why in plan.selected:
            con_out.print(f"  [green]probe[/] {_e(key)} ×{n}  ({_e(why)})")
        for key, why in plan.skipped:
            con_out.print(f"  [dim]skip  {_e(key)}: {_e(why)}[/]")
        return

    overrides = {}
    for item in env:
        key, sep, value = item.partition("=")
        if not sep:
            con_out.print(f"[red]--env {_e(item)}[/]: expected KEY=VALUE")
            raise typer.Exit(2)
        overrides[key] = value
    try:
        runtime = runtime_docker.DockerRuntime(
            build_network="default" if build_network else "none",
            env_overrides=overrides, mem_limit=memory)
    except ValueError as e:
        con_out.print(f"[red]{_e(str(e))}[/]")
        raise typer.Exit(2)
    if build_network:
        con_out.print("[yellow]--build-network[/]: RUN steps can reach the internet, the "
                      "LAN and this Mac while the target builds")
    recipe = None
    if seed:
        from .dynamic import seed as seed_mod
        recipe = seed_mod.get(seed)
        if recipe is None:
            con_out.print(f"[red]no seed recipe {_e(seed)}[/]; known: "
                          f"{_e(', '.join(seed_mod.names()) or 'none')}")
            raise typer.Exit(2)
        con_out.print(f"[yellow]--seed {_e(seed)}[/]: runs the target's own setup "
                      f"commands in the contained instance ({_e(recipe.description)})")
    try:
        with con_out.status("standing the target up and probing…"):
            res = run_validation(connection, run_id, vol.mount, runtime, limit=limit,
                                 seed=recipe)
    except runtime_docker.DockerError as e:
        # run_validation has already put this on the run page as a health warning.
        kind = ("refused" if isinstance(e, runtime_docker.ComposeRefused)
                else "provisioning gap")
        con_out.print(f"[red]{kind}[/]: {_e(str(e)[:1200])}")
        raise typer.Exit(1)
    con_out.print(f"[bold]validation of run {run_id}[/]: "
                  f"[green]{res.confirmed} confirmed[/], {res.rejected} rejected, "
                  f"{res.needs_review} needs-review")
    for finding, lens, verdict in res.verdicts:
        colour = {"confirmed": "green", "rejected": "dim", "needs-review": "yellow"}[verdict]
        con_out.print(f"  [{colour}]{verdict:12}[/] {_e(f'{lens:20}')} {_e(finding)}")
    if res.confirmed:
        con_out.print(f"[dim]write advisories with: quarry report {run_id}[/]")


@app.command()
def report(run_id: int = typer.Argument(..., help="a validated run"),
           out: str = typer.Option("", help="output directory (default: <data>/reports/<run>)")) -> None:
    """Write a Markdown disclosure advisory for every confirmed verdict: send it to the
    project's security contact, or paste it into GitHub's Report a vulnerability (GHSA) form."""
    from pathlib import Path
    from .ingest import RunVolume
    from .disclosure import draft_reports, draft_research_digest

    paths, connection = _open()
    vol = RunVolume.attach_existing(run_id, paths.runs)
    out_dir = Path(out) if out else Path(paths.runs).parent / "reports" / str(run_id)
    drafts = draft_reports(connection, run_id, vol.src, out_dir=out_dir)
    # Layer 2 survivors reach the report too, even when Layer 3 confirmed nothing. They are
    # candidates for triage, clearly separated from the confirmed-dynamic advisories above.
    digest = draft_research_digest(connection, run_id, out_dir=out_dir)

    if not drafts and digest is None:
        con_out.print("[yellow]no confirmed verdicts and no deep-review survivors to "
                      "report for this run[/]")
        return
    # One row per confirmed-verdict file, so the dashboard can list the drafts and tell
    # when a file on disk no longer matches what was written.
    with db.tx(connection):
        for d in drafts:
            db.advisory(connection, run_id, d.finding_id, str(d.path.resolve()),
                        d.sha256, verdict_id=d.verdict_id)
    if drafts:
        con_out.print(f"[bold]{len(drafts)} confirmed-dynamic advisory draft(s)[/] in "
                      f"{_e(out_dir)}:")
        for d in drafts:
            con_out.print(f"  {_e(d.path.name)}")
    else:
        con_out.print(f"[dim]no confirmed-dynamic verdicts[/] in {_e(out_dir)}")
    if digest is not None:
        con_out.print(f"[bold]{digest.n_findings} deep-review candidate(s)[/] (Layer 2, "
                      f"not dynamically confirmed): {_e(digest.path.name)}")
    con_out.print("[dim]review before sending (review-before-send); these are drafts.[/]")


@app.command()
def runs() -> None:
    """List runs."""
    _, connection = _open()
    t = Table(show_header=True, header_style="bold")
    for c in ("id", "target", "sha", "license", "status", "started"):
        t.add_column(c)
    for r in connection.execute(
            "SELECT id,target,git_sha,license_spdx,license_osi,status,started_at "
            "FROM runs ORDER BY id DESC LIMIT 50"):
        lic = f"{r['license_spdx'] or '-'}{'' if r['license_osi'] else ' (not OSI)'}"
        t.add_row(str(r["id"]), _e(r["target"]), _e((r["git_sha"] or "")[:10]), _e(lic),
                  _e(r["status"]), _e(r["started_at"]))
    con_out.print(t)


@app.command()
def quarantine(run_id: int) -> None:
    """Show what ingest moved aside for a run: symlinks destroyed, configs quarantined."""
    _, connection = _open()
    t = Table(show_header=True, header_style="bold")
    for c in ("kind", "path", "detail"):
        t.add_column(c)
    for r in connection.execute(
            "SELECT kind, original_path, detail FROM quarantined WHERE run_id=? ORDER BY kind",
            (run_id,)):
        t.add_row(_e(r["kind"]), _e(r["original_path"]), _e(r["detail"]))
    con_out.print(t)


@app.command()
def release(run_id: int) -> None:
    """Detach and delete a run's volume. Evidence lives in blobs, not clones."""
    paths, connection = _open()
    from .ingest import RunVolume
    vol = RunVolume.attach_existing(run_id, paths.runs)
    vol.release()
    connection.execute("UPDATE runs SET volume_path=NULL WHERE id=?", (run_id,))
    con_out.print(f"released run {run_id}")


if __name__ == "__main__":
    app()
