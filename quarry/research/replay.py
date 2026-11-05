"""A fixed planted-bug replay for measuring Layer 2 changes (IMPROVEMENT-PLAN item 21).

Since run 1, Layer 2 changed its thinking setting, quote minimum, family table and refute
batching, and nothing measured any of it against a fixed set. `docs/LEGA-CORPUS.md`
defines a planted-bug corpus of ten cloned OSS apps, and nothing runs it. This is the
small version that can run on every change: two synthetic services under
`tests/fixtures/replay/`, built on Leg A's idea (guard deletion first, ground truth by
construction), with the answer key in `plants.json` beside them so no model reads it.

A replay runs the real Layer 2 (`runner.plan` and `runner.execute`, so the real prompts,
parsing, quote verification, persistence and cross-family refutation) against a scratch
database, never the operator's, and scores three things:

  * missed plants, at the hunt and after refutation, out of the plants in the set;
  * unsupported claims: findings whose quote does not verify, out of all findings;
  * wall time.

It records what was held fixed (models and their digests, the Ollama version, the
budget and sampling constants, the lens set, a hash of the corpus) and what may differ
between two replays (the Quarry commit, a hash of the Layer 2 source, and whether route
intent was on). `compare` refuses to call two replays comparable when a fixed thing
differs, and calls equal scores a tie, which is a valid result.

Never report bare recall (LEGA-CORPUS.md): every result carries claims per repository
alongside the plants found, because a lens that flags everything finds every plant.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from .. import db
from . import ensemble as E
from . import intent as intent_mod
from . import runner
from .profile import profile_repo

DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "replay"
DEFAULT_MODELS = ("qwen3-coder:30b", "devstral:24b")


@dataclass(frozen=True)
class Location:
    file: str
    symbol: str
    anchors: tuple[str, ...]


@dataclass(frozen=True)
class Plant:
    id: str
    repo: str
    lens: str
    kind: str
    describe: str
    locations: tuple[Location, ...]
    mentions: tuple[str, ...] = ()
    guard: str | None = None
    route: dict | None = None


@dataclass
class Corpus:
    root: Path
    name: str
    lenses: tuple[str, ...]
    plants: list[Plant] = field(default_factory=list)

    @property
    def repos(self) -> list[str]:
        return sorted({p.repo for p in self.plants})


def load(root: Path = DEFAULT_CORPUS) -> Corpus:
    root = Path(root)
    doc = json.loads((root / "plants.json").read_text())
    plants = [Plant(id=p["id"], repo=p["repo"], lens=p["lens"], kind=p["kind"],
                    describe=p["describe"],
                    locations=tuple(Location(l["file"], l["symbol"], tuple(l["anchors"]))
                                    for l in p["locations"]),
                    mentions=tuple(p.get("mentions", ())), guard=p.get("guard"),
                    route=p.get("route"))
              for p in doc["plants"]]
    return Corpus(root, doc["corpus"], tuple(doc["lenses"]), plants)


def _files(repo_dir: Path) -> list[Path]:
    return sorted(p for p in repo_dir.rglob("*") if p.is_file()
                  and "__pycache__" not in p.parts)


def corpus_sha(c: Corpus) -> str:
    """Of every file a replay reads: the answer key and each repository, path and bytes.
    Two replays on different corpora are not comparable, and this says so."""
    h = hashlib.sha256()
    for p in [c.root / "plants.json"] + [f for r in c.repos for f in _files(c.root / r)]:
        h.update(str(p.relative_to(c.root)).encode())
        h.update(b"\0")
        h.update(p.read_bytes())
    return h.hexdigest()


def layer2_sha() -> str:
    """Of Layer 2's own source (quarry/research/*.py): the thing a replay measures."""
    h = hashlib.sha256()
    for p in sorted(Path(__file__).parent.glob("*.py")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def _ws(s: str | None) -> str:
    return " ".join((s or "").split())


# ------------------------------------------------------------------ preflight


def preflight(c: Corpus) -> list[str]:
    """Every plant checked by program before anything runs (LEGA-CORPUS.md: "Pre-flight
    every plant by program"). An empty list means the set is sound:

      * each location's file exists and each anchor is in it verbatim, and an anchor
        resolves to the planted symbol, so scoring can find the plant;
      * the plant's lens is one the profile selects for its repository, so the hunt
        can reach it at all;
      * a guard deletion has a sibling population: at least two routes in the same file
        declare the guard, and the planted route does not;
      * the answer key is outside every repository, and no repository file says
        "plant", so nothing in the prompt gives the answer away."""
    problems: list[str] = []
    for repo in c.repos:
        d = c.root / repo
        if not d.is_dir():
            problems.append(f"{repo}: repository directory missing")
            continue
        for f in _files(d):
            if f.name == "plants.json":
                problems.append(f"{repo}: an answer key is inside the repository")
            elif "plant" in f.read_text(errors="replace").lower():
                problems.append(f"{repo}/{f.relative_to(d)}: mentions 'plant'")
    selected: dict[str, set[str]] = {}
    for repo in c.repos:
        if (c.root / repo).is_dir():
            chosen, _ = E.select_lenses(profile_repo(c.root / repo))
            selected[repo] = {l.key for l in chosen}
    for p in c.plants:
        d = c.root / p.repo
        if p.lens not in c.lenses:
            problems.append(f"{p.id}: lens {p.lens} is not in the corpus lens set")
        if p.repo in selected and p.lens not in selected[p.repo]:
            problems.append(f"{p.id}: the profile does not select {p.lens} for {p.repo}")
        for loc in p.locations:
            path = d / loc.file
            if not path.is_file():
                problems.append(f"{p.id}: {loc.file} does not exist")
                continue
            text = _ws(path.read_text(errors="replace"))
            for a in loc.anchors:
                if _ws(a) not in text:
                    problems.append(f"{p.id}: anchor not in {loc.file}: {a!r}")
            got = intent_mod.locate(d, loc.file, loc.anchors[0])
            if got != loc.symbol:
                problems.append(f"{p.id}: {loc.file} anchor resolves to {got!r}, "
                                f"not {loc.symbol!r}")
        if p.kind == "guard-deletion" and p.route and p.guard:
            rf = d / p.route["file"]
            decls = intent_mod.declarations(rf.read_text(errors="replace"),
                                            p.route["file"]) if rf.is_file() else []
            planted = [x for x in decls if x.method == p.route["method"]
                       and x.path == p.route["path"]]
            siblings = [x for x in decls if x not in planted and p.guard in x.guards]
            if len(planted) != 1:
                problems.append(f"{p.id}: planted route not declared exactly once")
            elif p.guard in planted[0].guards:
                problems.append(f"{p.id}: the planted route still declares {p.guard}")
            if len(siblings) < 2:
                problems.append(f"{p.id}: {len(siblings)} sibling(s) declare {p.guard}; "
                                f"a guard deletion needs at least 2")
    return problems


# ------------------------------------------------------------------ scoring


def resolve_file(file: str, repo_files: set[str]) -> str | None:
    """The repository file a finding names, by the stand-in rule quote verification
    uses: the path itself, or the one file with that name."""
    f = (file or "").strip().lstrip("./")
    if f in repo_files:
        return f
    same = [x for x in repo_files if Path(x).name == Path(f).name]
    return same[0] if len(same) == 1 else None


def match(plant: Plant, finding: dict[str, Any], repo_files: set[str]) -> str | None:
    """How a verified finding hits a plant, or None. An unverified quote never counts:
    a claim about code that is not there has not found anything."""
    if finding.get("repo") != plant.repo or not finding.get("quote_verified"):
        return None
    f = resolve_file(finding.get("file", ""), repo_files)
    locs = [l for l in plant.locations if l.file == f]
    if not locs:
        return None
    quote = _ws(finding.get("quote"))
    for loc in locs:
        if finding.get("symbol") and finding["symbol"] == loc.symbol:
            return "symbol"
        if any(_ws(a) in quote for a in loc.anchors):
            return "anchor"
    # A mention in the title counts. One in the reasoning counts only when the quote's own
    # definition is unknown: MEASURED on the first replay, a claim about `remove` reasoned
    # "similar to the download function" and matched the download plant by mention.
    title = (finding.get("title") or "").lower()
    reasoning = (finding.get("reasoning") or "").lower()
    for m in (x.lower() for x in plant.mentions):
        if m in title or (not finding.get("symbol") and m in reasoning):
            return "mention"
    return None


def _frac(n: int, of: int) -> dict:
    return {"n": n, "of": of}


def score(c: Corpus, findings: list[dict[str, Any]],
          repo_files: dict[str, set[str]]) -> dict[str, Any]:
    """Score one replay's findings against the plants. Pure: no model, no database.

    `findings` are research_findings rows with `repo` added. A plant is found at the
    hunt when any verified finding matches it, and after refutation when a matching
    finding also survived (a cross-family model defended it), the bar the digest uses."""
    per_plant: dict[str, dict] = {}
    on_plant: set[int] = set()
    for p in c.plants:
        hits = []
        for i, f in enumerate(findings):
            how = match(p, f, repo_files.get(p.repo, set()))
            if how:
                on_plant.add(i)
                hits.append({"finding": f.get("id"), "model": f.get("model"),
                             "lens": f.get("lens"), "via": how,
                             "survived": bool(f.get("n_survived"))})
        per_plant[p.id] = {"repo": p.repo, "lens": p.lens, "kind": p.kind,
                           "found_at_hunt": bool(hits),
                           "found_after_refute": any(h["survived"] for h in hits),
                           "hits": hits}
    verified = [i for i, f in enumerate(findings) if f.get("quote_verified")]
    survivors = [i for i in verified if findings[i].get("n_survived")]
    missed_hunt = sorted(k for k, v in per_plant.items() if not v["found_at_hunt"])
    missed_ref = sorted(k for k, v in per_plant.items() if not v["found_after_refute"])
    n = len(c.plants)
    per_repo = {}
    for repo in c.repos:
        fr = [f for f in findings if f.get("repo") == repo]
        plants = [p.id for p in c.plants if p.repo == repo]
        per_repo[repo] = {
            "claims": len(fr),
            "unsupported": sum(1 for f in fr if not f.get("quote_verified")),
            "survivors": sum(1 for f in fr if f.get("quote_verified")
                             and f.get("n_survived")),
            "plants": len(plants),
            "found_at_hunt": sum(1 for x in plants if per_plant[x]["found_at_hunt"]),
            "found_after_refute": sum(1 for x in plants
                                      if per_plant[x]["found_after_refute"]),
        }
    return {
        "plants": n,
        "missed_at_hunt": {**_frac(len(missed_hunt), n), "ids": missed_hunt},
        "missed_after_refute": {**_frac(len(missed_ref), n), "ids": missed_ref},
        "claims": len(findings),
        "unsupported_claims": _frac(len(findings) - len(verified), len(findings)),
        "survivors": _frac(len(survivors), len(findings)),
        "verified_claims_on_no_plant": _frac(
            sum(1 for i in verified if i not in on_plant), len(verified)),
        "per_repo": per_repo,
        "per_plant": per_plant,
    }


def rescore(result: dict[str, Any], c: Corpus) -> dict[str, Any]:
    """The result with its score recomputed by the current scorer from the findings it
    saved, so two replays scored under different matching rules can be compared on
    one. Only for the corpus the replay ran on: a different corpus is refused."""
    if result["config"].get("corpus_sha") != corpus_sha(c):
        raise ValueError("this result was run on a different corpus; it cannot be "
                         "rescored against this one")
    files = {r: {str(p.relative_to(c.root / r)) for p in _files(c.root / r)}
             for r in c.repos}
    return {**result, "score": score(c, result["findings"], files), "rescored": True}


# ------------------------------------------------------------------ comparing

#: What a replay holds fixed. Two replays that differ here measure different things.
FIXED = ("models", "model_digests", "ollama", "budget", "sampling", "lenses", "corpus_sha")
#: What a replay is for: the thing allowed to differ between two of them.
VARIABLE = ("quarry_commit", "quarry_dirty", "layer2_sha", "route_intent")


def _rate(f: dict) -> float:
    return f["n"] / f["of"] if f["of"] else 0.0


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """The change from one replay to another. Lower is better for missed plants (at the
    hunt and after refutation) and for the unsupported-claim rate. Equal on all three is
    a tie. Wall time is reported but never decides it: it moves with machine load."""
    bc, ac = before["config"], after["config"]
    fixed = {k: [bc.get(k), ac.get(k)] for k in FIXED if bc.get(k) != ac.get(k)}
    changed = {k: [bc.get(k), ac.get(k)] for k in VARIABLE if bc.get(k) != ac.get(k)}
    bs, as_ = before["score"], after["score"]
    deltas = {
        "missed_at_hunt": as_["missed_at_hunt"]["n"] - bs["missed_at_hunt"]["n"],
        "missed_after_refute": (as_["missed_after_refute"]["n"]
                                - bs["missed_after_refute"]["n"]),
        "unsupported_rate": round(_rate(as_["unsupported_claims"])
                                  - _rate(bs["unsupported_claims"]), 4),
    }
    if fixed:
        verdict = "not comparable"
    elif all(v == 0 for v in deltas.values()):
        verdict = "tie"
    elif all(v <= 0 for v in deltas.values()):
        verdict = "better"
    elif all(v >= 0 for v in deltas.values()):
        verdict = "worse"
    else:
        verdict = "mixed"
    return {"verdict": verdict, "deltas": deltas, "fixed_differs": fixed,
            "what_changed": changed,
            "claims": [bs["claims"], as_["claims"]],
            "unsupported_claims": [bs["unsupported_claims"], as_["unsupported_claims"]],
            "missed_after_refute_ids": [bs["missed_after_refute"]["ids"],
                                        as_["missed_after_refute"]["ids"]],
            "wall_seconds": [before.get("wall_seconds"), after.get("wall_seconds")]}


# ------------------------------------------------------------------ running


def _git(*args: str) -> str | None:
    root = Path(__file__).resolve().parents[2]
    try:
        p = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                           text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def config(c: Corpus, models: list[str], *, route_intent: bool) -> dict[str, Any]:
    prov = E.model_provenance(models)
    status = _git("status", "--porcelain", "--", "quarry")
    return {
        "corpus": c.name, "corpus_sha": corpus_sha(c),
        "models": list(models), "model_digests": prov.get("models"),
        "ollama": prov.get("ollama"),
        "budget": {"unit_budget_tokens": runner.UNIT_BUDGET_TOKENS,
                   "num_ctx": runner.NUM_CTX,
                   "hunt_num_predict": runner.HUNT_NUM_PREDICT,
                   "refute_num_predict": runner.REFUTE_NUM_PREDICT},
        "sampling": dict(E.SAMPLING),
        "lenses": list(c.lenses),
        "quarry_commit": _git("rev-parse", "HEAD"),
        "quarry_dirty": bool(status) if status is not None else None,
        "layer2_sha": layer2_sha(),
        "route_intent": route_intent,
    }


def run(c: Corpus, models: list[str], *, workdir: Path, route_intent: bool = True,
        max_minutes: float = 0.0, progress: Callable[[str], None] = print) -> dict:
    """Replay the corpus through Layer 2 once and score it.

    Everything is written under `workdir`: a copy of each repository (the answer key is
    not copied) and a scratch database. `max_minutes` is a safety cap only; a replay it
    cuts short is marked incomplete, because unrefuted findings would score as misses."""
    problems = preflight(c)
    if problems:
        raise ValueError("corpus failed preflight: " + "; ".join(problems))
    if len({E.family(m) for m in models}) < 2:
        raise ValueError("a replay needs models from at least two families, or nothing "
                         "is refuted cross-family")
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    cfg = config(c, models, route_intent=route_intent)
    con = db.init(workdir / "replay.db")
    deadline = (datetime.now() + timedelta(minutes=max_minutes)) if max_minutes else None
    findings: list[dict[str, Any]] = []
    repo_files: dict[str, set[str]] = {}
    repos: dict[str, dict] = {}
    t0 = time.time()
    for repo in c.repos:
        src = workdir / repo / "src"
        if src.exists():
            shutil.rmtree(src)
        shutil.copytree(c.root / repo, src)
        repo_files[repo] = {str(p.relative_to(src)) for p in _files(src)}
        run_id = db.start_run(con, f"replay/{repo}", "fixture")
        rid, subs, lenses = runner.plan(con, run_id, src, models=models, lenses=c.lenses)
        progress(f"{repo}: {len(subs)} subsystem(s) x {len(lenses)} lens(es) x "
                 f"{len(models)} model(s)")
        t_repo = time.time()
        stats = runner.execute(con, rid, src, deadline=deadline, progress=progress,
                               route_intent=route_intent)
        repos[repo] = {"lenses": [l.key for l in lenses],
                       "units": len(subs) * len(lenses) * len(models),
                       "wall_seconds": round(time.time() - t_repo, 1), "stats": stats}
        for r in con.execute("SELECT * FROM research_findings WHERE research_id=? "
                             "ORDER BY id", (rid,)):
            findings.append({**{k: r[k] for k in r.keys() if k != "refutations"},
                             "repo": repo})
    wall = round(time.time() - t0, 1)
    unrefuted = sum(1 for f in findings if f.get("quote_verified")
                    and not (f.get("n_survived") or f.get("n_refuted")))
    complete = not any(r["stats"].get("skipped_deadline") for r in repos.values())
    return {"config": cfg, "repos": repos, "wall_seconds": wall,
            "complete": complete and not (deadline and unrefuted),
            "verified_without_a_verdict": unrefuted,
            "score": score(c, findings, repo_files), "findings": findings,
            "finished_at": datetime.now().isoformat(timespec="seconds")}
