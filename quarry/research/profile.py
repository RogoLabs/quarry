"""Deterministic repository profiling.

Deep mode's lenses must be chosen from what the repo *is*. Hardcoding them is how you
get a reviewer that finds nothing: the four ratified detectors (authz sibling anomaly,
multi-tenancy, state machine, sanitizer validity) all emit zero candidates on
`cve-validation-library`, because it has no routes, no ORM and no auth — and that is a
perfectly normal shape for a security-relevant package.

Everything here is grep and file-tree evidence, no model. The profile is what makes
lens selection auditable: every lens that runs can point at the fact that selected it,
and every lens that did not run can say why.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIR = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build",
            "coverage", "__pycache__", ".next", "target", ".tox", "tmp", "log"}

LANG_BY_EXT = {
    ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript",
    ".mjs": "JavaScript", ".cjs": "JavaScript", ".py": "Python", ".rb": "Ruby",
    ".go": "Go", ".php": "PHP", ".java": "Java", ".rs": "Rust", ".cs": "C#",
    ".c": "C", ".h": "C", ".cpp": "C++", ".kt": "Kotlin", ".swift": "Swift",
    ".erb": "ERB", ".svelte": "Svelte", ".vue": "Vue", ".sh": "Shell",
}

# (capability, regex, which extensions to search). Capabilities are the vocabulary
# lens selection speaks in.
CAPABILITY_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("http_routes", r"router\.(get|post|put|patch|delete)\b|app\.(get|post|put|use)\b"
                    r"|@(app|bp|router)[a-z_]*\.(route|get|post)|urlpatterns"
                    r"|APIRouter\(|as_view\(|resources\s+:|@(Get|Post|Controller)\("
                    r"|Rails\.application\.routes", (".js", ".ts", ".py", ".rb", ".go", ".java")),
    ("orm_models", r"models\.Model|db\.Model|declarative_base|DeclarativeBase|SQLModel"
                   r"|ApplicationRecord|ActiveRecord::Base|mongoose\.Schema|@Entity\b"
                   r"|prisma\.|sequelize\.define", (".py", ".rb", ".js", ".ts", ".java")),
    ("authn", r"passport|jwt\.|jsonwebtoken|devise|warden|authenticate_user|login_required"
              r"|session\[|bcrypt|argon2|OAuth|api[_-]?key", (".js", ".ts", ".py", ".rb", ".go")),
    ("authz", r"login_required|IsAuthenticated|permission_classes|PermissionRequiredMixin"
              r"|LoginRequiredMixin|Depends\(|authorize|Pundit|CanCan|can\?|ability"
              r"|before_action\s+:authenticate|requireAuth|ensureAuth|checkPermission",
     (".js", ".ts", ".py", ".rb")),
    ("raw_sql", r"execute\(\s*[\"'`].*SELECT|\.raw\(|sequelize\.query\(|cursor\.execute"
                r"|find_by_sql|where\(\s*[\"'].*#\{", (".js", ".ts", ".py", ".rb")),
    ("filesystem", r"readFile|writeFile|fs\.|open\(|Pathname|File\.(read|open|write)"
                   r"|os\.path\.join|path\.join", (".js", ".ts", ".py", ".rb")),
    # NOTE: an earlier version matched bare backticks, which in JS/TS are template
    # literals, not shell. It reported subprocess(741) on cve-services — a pure Express
    # API — which would have selected a command-injection lens over the authz lens that
    # repo actually needs. Backticks count as shell only in Ruby.
    ("subprocess", r"child_process|execSync|execFile|spawn\(|subprocess\.|os\.system"
                   r"|Open3|popen|shell_exec", (".js", ".ts", ".py", ".rb")),
    ("subprocess", r"`[^`\n]+`|%x\(|system\(", (".rb",)),
    ("deserialization", r"JSON\.parse|yaml\.load|pickle\.loads|Marshal\.load|YAML\.load"
                        r"|unserialize|ObjectInputStream", (".js", ".ts", ".py", ".rb", ".java")),
    ("template_render", r"render\(|render_template|ERB\.new|\.erb|Handlebars|ejs|jinja"
                        r"|dangerouslySetInnerHTML|html_safe|raw\(", (".js", ".ts", ".py", ".rb", ".erb")),
    ("file_upload", r"multer|ActiveStorage|CarrierWave|shrine|FileField|UploadFile"
                    r"|multipart", (".js", ".ts", ".py", ".rb")),
    ("crypto", r"crypto\.|hashlib|OpenSSL|Digest::|bcrypt|createCipher|Fernet|secrets\.",
     (".js", ".ts", ".py", ".rb")),
    ("background_jobs", r"Sidekiq|ActiveJob|celery|bull|agenda|resque|delayed_job|rq\.",
     (".js", ".ts", ".py", ".rb")),
    ("schema_validation", r"ajv|joi|zod|yup|jsonschema|JSON Schema|validates\s+:|marshmallow"
                          r"|pydantic|express-validator", (".js", ".ts", ".py", ".rb", ".json")),
    ("multi_tenant", r"tenant_id|organization_id|org_id|workspace_id|account_id|team_id",
     (".js", ".ts", ".py", ".rb")),
)

FRAMEWORK_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Ruby on Rails", ("config/application.rb", "config/routes.rb", "Gemfile")),
    ("Django", ("manage.py", "wsgi.py")),
    ("Flask", ("app.py", "wsgi.py")),
    ("Express", ("package.json",)),
    ("Next.js", ("next.config.js", "next.config.mjs", "next.config.ts")),
    ("Spring", ("pom.xml", "build.gradle")),
    ("Laravel", ("artisan",)),
)


@dataclass
class RepoProfile:
    root: Path
    languages: dict[str, int] = field(default_factory=dict)       # lang -> file count
    frameworks: list[str] = field(default_factory=list)
    capabilities: dict[str, int] = field(default_factory=dict)    # capability -> hit count
    dependencies: list[str] = field(default_factory=list)
    dependency_overrides: dict[str, str] = field(default_factory=dict)
    artifact_kind: str = "unknown"      # library | service | cli | data | unknown
    code_tokens: int = 0
    file_count: int = 0
    evidence: dict[str, str] = field(default_factory=dict)        # capability -> a real path

    def has(self, capability: str, minimum: int = 1) -> bool:
        return self.capabilities.get(capability, 0) >= minimum

    @property
    def primary_language(self) -> str:
        return max(self.languages, key=self.languages.get) if self.languages else "unknown"

    def summary(self) -> str:
        caps = ", ".join(f"{k}({v})" for k, v in
                         sorted(self.capabilities.items(), key=lambda kv: -kv[1]))
        return (f"{self.primary_language} {self.artifact_kind}"
                f"{' [' + ', '.join(self.frameworks) + ']' if self.frameworks else ''}, "
                f"{self.file_count} files, ~{self.code_tokens // 1000}k tokens\n"
                f"capabilities: {caps or 'none detected'}")


def _detect_artifact_kind(root: Path, caps: dict[str, int]) -> str:
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            d = json.loads(pkg.read_text(errors="replace"))
        except ValueError:
            d = {}
        # A package that declares an entry point for consumers is a library; one that
        # only has start scripts is a service. This distinction changes the threat model
        # completely — a library's attacker is its consumer's input.
        if d.get("main") or d.get("exports") or d.get("module"):
            if not caps.get("http_routes"):
                return "library"
        if "start" in (d.get("scripts") or {}):
            return "service"
    if (root / "setup.py").is_file() or (root / "pyproject.toml").is_file():
        if not caps.get("http_routes"):
            return "library"
    if (root / "config" / "routes.rb").is_file() or (root / "manage.py").is_file():
        return "service"
    if caps.get("http_routes"):
        return "service"
    return "cli" if (root / "bin").is_dir() else "unknown"


def profile_repo(root: Path, *, max_file_bytes: int = 400_000) -> RepoProfile:
    root = root.resolve()
    prof = RepoProfile(root=root)
    compiled = [(cap, re.compile(pat, re.I), exts) for cap, pat, exts in CAPABILITY_PATTERNS]

    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIR]
        for name in fn:
            p = Path(dp) / name
            ext = p.suffix.lower()
            lang = LANG_BY_EXT.get(ext)
            if lang:
                prof.languages[lang] = prof.languages.get(lang, 0) + 1
                prof.file_count += 1
            if ext not in LANG_BY_EXT and ext != ".json":
                continue
            try:
                if p.stat().st_size > max_file_bytes:
                    continue
                text = p.read_text(errors="replace")
            except OSError:
                continue
            if lang:
                prof.code_tokens += int(len(text) / 3.6)
            rel = str(p.relative_to(root))
            for cap, pat, exts in compiled:
                if ext not in exts:
                    continue
                n = len(pat.findall(text))
                if n:
                    prof.capabilities[cap] = prof.capabilities.get(cap, 0) + n
                    prof.evidence.setdefault(cap, f"{rel}")

    for fw, markers in FRAMEWORK_MARKERS:
        for m in markers:
            if (root / m).is_file():
                if fw == "Express":
                    try:
                        deps = json.loads((root / "package.json").read_text(errors="replace"))
                        alldeps = {**(deps.get("dependencies") or {}),
                                   **(deps.get("devDependencies") or {})}
                        prof.dependencies = sorted(alldeps)
                        prof.dependency_overrides = deps.get("overrides") or {}
                        if "express" not in alldeps:
                            continue
                    except (ValueError, OSError):
                        continue
                if fw == "Flask" and (root / "manage.py").is_file():
                    continue
                prof.frameworks.append(fw)
                break

    if (root / "Gemfile").is_file() and not prof.dependencies:
        try:
            prof.dependencies = sorted(set(re.findall(
                r"^\s*gem\s+['\"]([^'\"]+)", (root / "Gemfile").read_text(errors="replace"),
                re.M)))
        except OSError:
            pass

    prof.artifact_kind = _detect_artifact_kind(root, prof.capabilities)
    return prof
