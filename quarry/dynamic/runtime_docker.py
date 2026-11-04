"""Tier 2 target runtime: bring a target up in Docker on an egress-blocked network.

Docker does not run under sandbox-exec. On macOS it runs inside a Linux VM, so what
keeps a hostile target contained is the compose document Quarry hands to Docker, and
this module writes that document itself rather than editing the author's:

1. The author's file is checked before compose reads it: top-level `include` and
   `extends.file` are refused, and every `env_file` must resolve inside the clone.
2. `docker compose config` resolves interpolation and `extends` under a scrubbed
   environment (PATH, a temp HOME and DOCKER_CONFIG, the daemon address), so a
   `${VAR}` in the file cannot pull a token from the operator's shell. The target's
   own `.env` is passed through with every COMPOSE_/DOCKER_/BUILDKIT_ key removed.
3. `harden_compose` emits a fresh document from an allowlist of service and build keys.
   Anything not on the list (privileged, pid, cap_add, devices, volumes_from,
   security_opt, secrets, logging, use_api_socket and the rest) is simply never copied.
   Every bind must resolve inside the clone, every service gets dropped capabilities,
   no-new-privileges and resource limits, and builds run with `network: none`.

Image pulls happen during provisioning and may touch the network; Dockerfile RUN steps
may not, unless the operator passes `build_network="default"` (`quarry validate
--build-network`). Most real Dockerfiles install their dependencies in RUN steps, so
without it they cannot be validated at all. With it, RUN steps can reach the internet,
the LAN and the host (Docker Desktop routes host.docker.internal to the Mac), but they
still see no operator environment, registry credentials, SSH agent or BuildKit secrets,
because none of those are passed to the build. The running target stays on the internal
network either way. A probe reaches the target by joining the isolated network as an
ephemeral sidecar; nothing is ever published to the host.

`harden_compose` and the checks around it are pure, so they are unit-tested without
Docker. Resolution needs the docker CLI; bring-up needs a daemon.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .validate import RuntimeSpec, RunningTarget, TargetRuntime, register_runtime

COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml",
                 "compose.yml", "compose.yaml")
ISOLATED_NET = "quarry_isolated"
# A minimal, pinned image used only as an ephemeral sidecar on the isolated network
# (health-gating and, later, probes). Pulled during provisioning.
SIDECAR_IMAGE = "curlimages/curl:8.11.1"
# Forced into every service's environment. On the internal network a hub lookup cannot
# succeed, so these only tell the client not to try. MEASURED (ML-Gateway, run 2): five
# models whose weights were baked into the image at build time, but each from_pretrained
# first retried two hub HEADs five times on a failed DNS lookup: 3m59s before uvicorn
# bound, past the 120s health budget. Weights a build did not bake still fail to load;
# that is the target's provisioning gap, not something the runtime may paper over.
OFFLINE_ENV = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
               "HF_DATASETS_OFFLINE": "1"}

# The service keys copied from the resolved document. Everything else is dropped by
# omission, which is the point: a key compose adds next year is not copied either.
# `image` is copied only for services that do not build (see _rebuild_service).
SERVICE_KEYS = ("image", "command", "entrypoint", "working_dir", "user", "healthcheck",
                "expose", "tmpfs", "init", "stop_signal", "stop_grace_period",
                "read_only", "tty", "stdin_open", "hostname", "platform")
BUILD_KEYS = ("dockerfile", "dockerfile_inline", "args", "target")
DEPENDS_CONDITIONS = ("service_started", "service_healthy",
                      "service_completed_successfully")
# Capabilities given back after cap_drop ALL. These are what entrypoints that start as
# root and step down need (postgres and mysql chown their data directory, then setuid
# through gosu). Left out of Docker's default set: NET_RAW (raw packets on the shared
# network), MKNOD, SETFCAP, SETPCAP, SYS_CHROOT and AUDIT_WRITE.
KEEP_CAPS = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETUID", "SETGID", "KILL",
             "NET_BIND_SERVICE")
LIMITS = {"mem_limit": "2g", "pids_limit": 512, "cpus": 2.0}
# The memory cap is a resource guard, not a containment control, so the operator may
# raise it (`--memory`). MEASURED: VulnLookup runs 49 preloaded gunicorn workers and its
# feeders in one container, and at 2g the kernel OOM-killed the web server 53 times
# before it bound a port.
_MEM = re.compile(r"^[1-9][0-9]*[kmg]$")
# Keys that steer the docker or compose CLI itself rather than the target. A target's
# .env may set them (COMPOSE_PROJECT_NAME is honoured from .env, MEASURED with compose
# v5.6.1), and build args named BUILDKIT_* reach the builder, so none are passed on.
_RESERVED_ENV = ("COMPOSE_", "DOCKER_", "BUILDKIT_", "BUILDX_")
# The only Dockerfile frontends accepted in a `# syntax=` directive. The build's network
# mode reaches the frontend as an option, and a frontend image the target chose need
# not honour it.
_OFFICIAL_FRONTEND = re.compile(
    r"^(docker\.io/)?docker/dockerfile(-upstream)?(:[\w.-]+)?(@sha256:[0-9a-f]{64})?$")
# The build network modes an operator may choose. `host` is never offered: on Docker
# Desktop it is the VM's own network namespace, which is more reach than a build needs.
BUILD_NETWORKS = ("none", "default")
# Where a project keeps the .env it expects you to copy. Used only when the file the
# compose document names does not exist, which is the normal state of a fresh clone.
ENV_SAMPLE_SUFFIXES = (".example", ".sample", ".dist", ".template")
# The oldest versions this is written for. Compose v2 is the plugin that reads
# `config --format json` (v1 docker-compose is a different program), and engine 20.10
# is the first with cgroup v2 support, which the pids and memory limits rely on in
# current Docker Desktop VMs.
MIN_ENGINE = (20, 10)
MIN_COMPOSE = (2, 0)


class DockerError(RuntimeError):
    pass


class ComposeRefused(DockerError):
    """The compose file asks for something the runtime will not do on a target's behalf."""


class ProvisioningGap(DockerError):
    """The target could not be built or started under containment. Recorded, not
    worked around: a build that needs the network fails closed."""


def docker_available(env: dict[str, str] | None = None) -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20, env=env).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _version(text: str) -> tuple[int, int]:
    m = re.match(r"v?(\d+)\.(\d+)", text.strip())
    return (int(m[1]), int(m[2])) if m else (0, 0)


def check_versions(engine: str, compose: str) -> None:
    """Refuse an engine or compose plugin older than this module was written against,
    or one that did not report a version at all."""
    for what, got, need in (("docker engine", engine, MIN_ENGINE),
                            ("docker compose", compose, MIN_COMPOSE)):
        if _version(got) < need:
            raise ProvisioningGap(
                f"{what} {got.strip() or 'unknown'} is older than "
                f"{'.'.join(map(str, need))}, the minimum validate supports")


def _operator_docker_host() -> str | None:
    """The daemon address the operator's own docker CLI would use. Read once, from the
    operator's environment and context, because the scrubbed environment has neither."""
    if host := os.environ.get("DOCKER_HOST"):
        return host
    try:
        r = subprocess.run(["docker", "context", "inspect", "--format",
                            "{{.Endpoints.docker.Host}}"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return (r.stdout.strip() or None) if r.returncode == 0 else None


def scrubbed_env(home: Path, *, docker_host: str | None = None) -> dict[str, str]:
    """The whole environment `docker compose` gets: PATH, a temp HOME, a DOCKER_CONFIG
    whose config.json only says where CLI plugins live (no auths, no credsStore, no
    proxies), and the daemon address. Nothing from the operator's shell is
    interpolated into a target's compose file, and the target's registry pulls are
    anonymous."""
    cfg = home / ".docker"
    cfg.mkdir(parents=True, exist_ok=True)
    real = Path(os.environ.get("DOCKER_CONFIG") or Path.home() / ".docker")
    plugins = [str(real / "cli-plugins")] if (real / "cli-plugins").is_dir() else []
    (cfg / "config.json").write_text(json.dumps({"cliPluginsExtraDirs": plugins}))
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "DOCKER_CONFIG": str(cfg)}
    if docker_host:
        env["DOCKER_HOST"] = docker_host
    return env


# Where a compose file lives, in priority order. Many projects (cve-services among them)
# keep it under docker/ or deploy/ rather than at the root. We look at the root first,
# then these known homes, then a shallow bounded search, so discovery is deterministic
# and never wanders into a test or vendor tree that ships its own throwaway stack.
COMPOSE_SUBDIRS = ("docker", "deploy", "deployment", "compose", "infra", "build")
_COMPOSE_SKIP = {".git", "node_modules", "vendor", "test", "tests", "test-http",
                 "test-examples", "examples", "example", "fixtures", "__pycache__"}


def _compose_in(d: Path) -> Path | None:
    for name in COMPOSE_NAMES:
        p = d / name
        if p.is_file():
            return p
    return None


def find_compose(src: Path) -> Path | None:
    if hit := _compose_in(src):
        return hit
    for sub in COMPOSE_SUBDIRS:
        if (d := src / sub).is_dir() and (hit := _compose_in(d)):
            return hit
    # Last resort: the shallowest compose file anywhere outside the skip set, chosen by
    # a stable sort so the same repo always resolves to the same file.
    candidates: list[tuple[int, str]] = []
    for p in src.rglob("*"):
        if p.name in COMPOSE_NAMES and p.is_file():
            rel = p.relative_to(src)
            if _COMPOSE_SKIP.isdisjoint(rel.parts):
                candidates.append((len(rel.parts), str(rel)))
    if candidates:
        candidates.sort()
        return src / candidates[0][1]
    return None


def _inside(path: str | Path, root: Path) -> bool:
    """Whether `path`, with every symlink resolved, is `root` or below it."""
    try:
        Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
        return True
    except ValueError:
        return False


def _file_list(value) -> list[str]:
    """env_file and label_file entries, in any of compose's syntaxes."""
    items = value if isinstance(value, list) else [value]
    out = []
    for it in items:
        if isinstance(it, dict):
            it = it.get("path")
        if it is not None:
            out.append(str(it))
    return out


def precheck_compose(doc: dict, compose_dir: Path, src: Path) -> None:
    """Refuse what `docker compose config` would itself read from outside the clone.
    Runs on the author's file before compose sees it, because config inlines included
    files, extended files and env_file contents, and after that there is no telling
    where a value came from."""
    if not isinstance(doc, dict):
        raise ComposeRefused("compose file is not a mapping")
    if "include" in doc:
        raise ComposeRefused("top-level include is not supported: it pulls in files, "
                             "possibly remote, that are resolved before any check")
    services = doc.get("services")
    if not isinstance(services, dict) or not services:
        raise DockerError("compose file has no services")
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        ext = svc.get("extends")
        if isinstance(ext, dict) and ext.get("file"):
            raise ComposeRefused(f"service {name!r}: extends.file is not supported")
        for key in ("env_file", "label_file"):
            for f in _file_list(svc.get(key, [])):
                if "$" in f or not _inside(compose_dir / os.path.expanduser(f), src):
                    raise ComposeRefused(
                        f"service {name!r}: {key} {f!r} is not a file inside the clone")


_DOTENV = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def env_sample(p: Path, src: Path) -> Path | None:
    """The sample a project ships for a missing env file (`.env.sample` for `.env`), if
    exactly that file exists inside the clone."""
    for suffix in ENV_SAMPLE_SUFFIXES:
        s = p.with_name(p.name + suffix)
        if s.is_file() and _inside(s, src):
            return s
    return None


def dotenv_path(compose_dir: Path, src: Path) -> Path | None:
    """The file compose interpolates from: the target's .env, or its shipped sample when
    the clone has none (a committed .env is rare; `cp .env.sample .env` is the norm)."""
    p = compose_dir / ".env"
    if p.is_file():
        return p if _inside(p, src) else None
    return env_sample(p, src)


def filtered_dotenv(compose_dir: Path, src: Path) -> str:
    """The target's .env (or its sample) as compose will see it: simple KEY=VALUE lines
    only, and no key that steers the CLI (COMPOSE_ENV_FILES could name a host file to
    interpolate from, COMPOSE_FILE another compose file). A quoted value that does not
    close on its own line is dropped rather than parsed, so a continuation line cannot
    become a key."""
    p = dotenv_path(compose_dir, src)
    if p is None:
        return ""
    kept = []
    for line in p.read_text(errors="replace").splitlines():
        m = _DOTENV.match(line)
        if not m or m[1].startswith(_RESERVED_ENV):
            continue
        val = m[2].strip()
        if val[:1] in ("'", '"') and (len(val) < 2 or not val.endswith(val[0])):
            continue
        kept.append(f"{m[1]}={val}")
    return "\n".join(kept) + ("\n" if kept else "")


def stage_env_files(doc: dict, compose_dir: Path, src: Path) -> tuple[dict, list[str]]:
    """Point each `env_file` that does not exist at its shipped sample, or mark it
    optional when there is none, so `compose config` does not fail on a fresh clone.
    Runs after precheck_compose, so every entry is already known to be inside the clone.
    Returns the document (a copy when anything changed) and one note per change."""
    notes: list[str] = []
    out = json.loads(json.dumps(doc))
    for name, svc in (out.get("services") or {}).items():
        if not isinstance(svc, dict) or svc.get("env_file") is None:
            continue
        raw = svc["env_file"]
        entries = raw if isinstance(raw, list) else [raw]
        staged = []
        for e in entries:
            f = e.get("path") if isinstance(e, dict) else e
            p = compose_dir / os.path.expanduser(str(f))
            if f is None or p.is_file():
                staged.append(e)
                continue
            if (sample := env_sample(p, src)) is not None:
                staged.append(str(sample))
                notes.append(f"service {name!r}: env_file {f} is missing; "
                             f"used {sample.relative_to(src)}")
            else:
                staged.append({"path": str(f), "required": False})
                notes.append(f"service {name!r}: env_file {f} is missing and has no "
                             "sample; started without it")
        svc["env_file"] = staged
    return (out, notes) if notes else (doc, [])


_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def check_env_overrides(overrides: dict[str, str]) -> None:
    """Refuse an operator value compose would treat as anything but data: a key that
    steers the CLI, a malformed key, or a value with a line break (it would become a
    second line of the env file)."""
    for k, v in overrides.items():
        if not _ENV_KEY.match(k) or k.startswith(_RESERVED_ENV):
            raise ValueError(f"--env {k!r}: not a key validate will set")
        if "\n" in v or "\r" in v:
            raise ValueError(f"--env {k}: the value has a line break")


def apply_env_overrides(dotenv: str, resolved: dict, overrides: dict[str, str]) -> str:
    """Put the operator's values where the target's own would have gone: in the env file
    compose interpolates from (replacing the target's line), and in every resolved
    service environment that already has the key, which is where env_file contents
    land. A key no service declares is only interpolated. Returns the new env text;
    `resolved` is changed in place."""
    if not overrides:
        return dotenv
    kept = [ln for ln in dotenv.splitlines() if ln.split("=", 1)[0] not in overrides]
    text = "\n".join(kept + [f"{k}={v}" for k, v in overrides.items()]) + "\n"
    for svc in (resolved.get("services") or {}).values():
        env = svc.get("environment") if isinstance(svc, dict) else None
        if isinstance(env, dict):
            for k in overrides.keys() & env.keys():
                env[k] = overrides[k]
        elif isinstance(env, list):
            svc["environment"] = [
                f"{k}={overrides[k]}" if (k := str(e).split("=", 1)[0]) in overrides
                else e for e in env]
    return text


def _is_remote(ref: str) -> bool:
    return "://" in ref or ref.startswith("git@")


def _rebuild_build(name: str, build, src: Path, network: str = "none") -> dict:
    b = {"context": build} if isinstance(build, str) else dict(build or {})
    ctx = str(b.get("context") or ".")
    if _is_remote(ctx) or not os.path.isabs(ctx) or not _inside(ctx, src):
        raise ComposeRefused(f"service {name!r}: build context {ctx!r} is not inside "
                             "the clone")
    out: dict = {"context": ctx}
    for k in BUILD_KEYS:
        if b.get(k) is not None:
            out[k] = b[k]
    if "dockerfile_inline" not in out:
        df = str(out.get("dockerfile") or "Dockerfile")
        if _is_remote(df) or not _inside(os.path.join(ctx, df), src):
            raise ComposeRefused(f"service {name!r}: dockerfile {df!r} is not inside "
                                 "the clone")
    args = out.get("args")
    if isinstance(args, dict):
        out["args"] = {k: v for k, v in args.items()
                       if not str(k).startswith(_RESERVED_ENV)}
    elif args is not None:
        out.pop("args")                     # config emits a mapping; anything else is odd
    if network not in BUILD_NETWORKS:
        raise ValueError(f"build network {network!r} is not one of {BUILD_NETWORKS}")
    out["network"] = network                # "none" unless the operator opted in
    return out


def _volume_entry(v) -> dict | None:
    """Normalise a short-syntax volume to the long form config emits."""
    if isinstance(v, dict):
        return v
    if not isinstance(v, str):
        return None
    parts = v.split(":")
    if len(parts) == 1:
        return {"type": "volume", "target": parts[0]}
    source, target = parts[0], parts[1]
    ro = len(parts) > 2 and "ro" in parts[2].split(",")
    kind = "bind" if source[:1] in ("/", ".", "~") else "volume"
    return {"type": kind, "source": source, "target": target, "read_only": ro}


def _rebuild_volume(v, src: Path, named: set[str]) -> dict | None:
    e = _volume_entry(v)
    if not e or not e.get("target"):
        return None
    kind, source = e.get("type"), e.get("source")
    out = {"type": kind, "target": e["target"]}
    if e.get("read_only"):
        out["read_only"] = True
    if kind == "bind":
        # config makes bind sources absolute. Anything still relative, or that resolves
        # outside the clone through `..` or a symlink, would mount a host path.
        if not source or not os.path.isabs(source) or not _inside(source, src):
            return None
        out["source"] = source
    elif kind == "volume":
        if source:
            out["source"] = str(source)
            named.add(str(source))
    elif kind == "tmpfs":
        size = (e.get("tmpfs") or {}).get("size")
        if size:
            out["tmpfs"] = {"size": size}
    else:
        return None                         # npipe, cluster, image: not on the list
    return out


def _rebuild_depends(dep) -> dict | list | None:
    if isinstance(dep, list):
        return [str(d) for d in dep]
    if isinstance(dep, dict):
        out = {}
        for svc, opts in dep.items():
            cond = (opts or {}).get("condition") if isinstance(opts, dict) else None
            out[svc] = {"condition": cond if cond in DEPENDS_CONDITIONS
                        else "service_started"}
        return out
    return None


def _force_offline_env(svc: dict) -> None:
    """Set OFFLINE_ENV in a service, in whichever syntax it already uses (mapping or
    KEY=VALUE list), replacing any value the author gave those keys."""
    env = svc.get("environment")
    if isinstance(env, list):
        kept = [e for e in env
                if str(e).split("=", 1)[0] not in OFFLINE_ENV]
        svc["environment"] = kept + [f"{k}={v}" for k, v in OFFLINE_ENV.items()]
    else:
        merged = dict(env) if isinstance(env, dict) else {}
        merged.update(OFFLINE_ENV)
        svc["environment"] = merged


def _rebuild_service(name: str, svc: dict, src: Path, network: str,
                     named: set[str], build_network: str = "none",
                     mem_limit: str = LIMITS["mem_limit"]) -> dict:
    out = {k: json.loads(json.dumps(svc[k])) for k in SERVICE_KEYS
           if svc.get(k) is not None}
    if svc.get("build") is not None:
        out["build"] = _rebuild_build(name, svc["build"], src, build_network)
        # A built service keeps compose's own project-scoped image name. With `image:`
        # set, compose tags the build with it, and a target could overwrite the
        # operator's local postgres:16, or Quarry's own SIDECAR_IMAGE.
        out.pop("image", None)
    elif not out.get("image"):
        raise ComposeRefused(f"service {name!r} has neither image nor build")
    vols = [r for v in (svc.get("volumes") or []) if (r := _rebuild_volume(v, src, named))]
    if vols:
        out["volumes"] = vols
    if (dep := _rebuild_depends(svc.get("depends_on"))):
        out["depends_on"] = dep
    if svc.get("environment") is not None:
        out["environment"] = json.loads(json.dumps(svc["environment"]))
    _force_offline_env(out)
    out["networks"] = [network]
    out["cap_drop"] = ["ALL"]
    out["cap_add"] = list(KEEP_CAPS)
    out["security_opt"] = ["no-new-privileges:true"]
    out.update(LIMITS, mem_limit=mem_limit)
    out["restart"] = "no"                   # nothing outlives a failed bring-up
    return out


def harden_compose(doc: dict, src: Path, *, network: str = ISOLATED_NET,
                   build_network: str = "none",
                   mem_limit: str = LIMITS["mem_limit"]) -> dict:
    """Build the document Docker runs from a resolved one (the output of `docker
    compose config`), copying only allowlisted keys and forcing the containment ones:
    one internal network, no host ports, binds only inside `src`, dropped capabilities,
    no-new-privileges, resource limits, network-less builds (unless `build_network` is
    "default", the operator's opt-in). Named volumes are
    recreated empty and project-scoped, so `external:` and `driver_opts` bind devices
    never reach an operator's volume or a host path. Package-hub clients are told they
    are offline, so they fail fast instead of retrying a lookup that cannot succeed."""
    services = doc.get("services")
    if not isinstance(services, dict) or not services:
        raise DockerError("compose file has no services")
    named: set[str] = set()
    if not _MEM.match(mem_limit):
        raise ValueError(f"memory limit {mem_limit!r} is not like 2g or 512m")
    out_services = {name: _rebuild_service(str(name), svc, src, network, named,
                                           build_network, mem_limit)
                    for name, svc in services.items() if isinstance(svc, dict)}
    out: dict = {"services": out_services,
                 "networks": {network: {"internal": True, "driver": "bridge"}}}
    if named:
        out["volumes"] = {v: {} for v in sorted(named)}
    return out


_SYNTAX = re.compile(r"^#\s*syntax\s*=\s*(\S+)", re.IGNORECASE)


def check_dockerfiles(doc: dict, src: Path) -> None:
    """Refuse a Dockerfile that picks its own BuildKit frontend. Parser directives only
    count at the top of the file, before the first instruction or blank line."""
    for name, svc in doc.get("services", {}).items():
        b = svc.get("build")
        if not b:
            continue
        text = b.get("dockerfile_inline")
        if text is None:
            p = Path(b["context"]) / str(b.get("dockerfile") or "Dockerfile")
            if not p.is_file():
                continue                    # the build will fail and say so
            text = p.read_text(errors="replace")
        for line in str(text).splitlines():
            if not line.startswith("#"):
                break
            m = _SYNTAX.match(line)
            if m and not _OFFICIAL_FRONTEND.match(m[1]):
                raise ComposeRefused(f"service {name!r}: Dockerfile frontend {m[1]!r} "
                                     "is not docker/dockerfile")


def _entrypoint(doc: dict) -> tuple[str, int]:
    """The service and container port a probe should address, inferred from a document
    that still has its ports (harden_compose drops them): prefer a service that
    published or exposed a port, else the first service; default the port to 8080.
    A service built from the clone is the project's own code, so it outranks pulled
    images: VulnLookup publishes kvrocks on 10002 beside its web app on 10001, and
    `config` lists services alphabetically, so the datastore came first."""
    services = doc.get("services", {})
    if not isinstance(services, dict) or not services:
        raise DockerError("compose file has no services")

    def container_port(svc: dict) -> int | None:
        for entry in svc.get("ports", []) or []:
            if isinstance(entry, str):
                part = entry.rsplit(":", 1)[-1].split("/", 1)[0]
                if part.isdigit():
                    return int(part)
            elif isinstance(entry, dict) and entry.get("target"):
                return int(entry["target"])
        for entry in svc.get("expose", []) or []:
            s = str(entry).split("/", 1)[0]
            if s.isdigit():
                return int(s)
        return None

    svcs = [(n, s) for n, s in services.items() if isinstance(s, dict)]
    for want_build in (True, False):
        for name, svc in svcs:
            if want_build and not svc.get("build"):
                continue
            p = container_port(svc)
            if p is not None:
                return name, p
    built = [n for n, s in svcs if s.get("build")]
    return (built[0] if built else next(iter(services))), 8080


def resolve_compose(base: Path, env_file: Path, env: dict[str, str], *,
                    project_dir: Path | None = None, timeout: int = 60) -> dict:
    """`docker compose config` on the author's file under `env`, with `env_file` in
    place of the target's .env. Interpolation, extends, env_file contents and relative
    paths are all resolved here, so the document harden_compose sees is final. Relative
    paths resolve against `project_dir` (default: the file's own directory), which lets
    a staged copy of the author's file live outside the clone."""
    cmd = ["docker", "compose", "-f", str(base),
           "--project-directory", str(project_dir or base.parent),
           "--env-file", str(env_file), "config", "--format", "json"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        raise ProvisioningGap(f"compose config did not run: {e}") from e
    if r.returncode != 0:
        raise ComposeRefused(f"compose config failed: {r.stderr[-800:]}")
    try:
        return json.loads(r.stdout)
    except ValueError as e:
        raise ProvisioningGap(f"compose config printed no JSON: {e}") from e


@dataclass
class DockerRuntime:
    """A TargetRuntime backed by Docker Compose. Compose files are the target author's
    own declared boot contract, which is why this is the primary runtime. Quarry never
    runs the author's file: `start` runs the document harden_compose wrote."""
    project_prefix: str = "quarry"
    up_timeout: int = 300
    # A build that installs a real project's dependencies (VulnLookup: apt, poetry and
    # every Python package) takes far longer than bringing the built stack up.
    build_timeout: int = 1800
    health_timeout: int = 120
    # "none" keeps RUN steps offline. "default" is the operator's opt-in (see the module
    # docstring for what it does and does not expose).
    build_network: str = "none"
    # Values the operator supplies for the target's own variables (`--env KEY=VALUE`),
    # for the placeholders a sample .env ships with. Never read from the shell.
    env_overrides: dict[str, str] = field(default_factory=dict)
    # Per service. Raising it does not loosen containment (see _MEM).
    mem_limit: str = LIMITS["mem_limit"]
    _env: dict[str, str] | None = field(default=None, init=False, repr=False)
    # What provisioning did that a reader of the run should know: the build network,
    # whether a sample stood in for .env, and env_file substitutions. run_validation
    # copies it onto the run page.
    provisioning: dict = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if self.build_network not in BUILD_NETWORKS:
            raise ValueError(f"build network {self.build_network!r} is not one of "
                             f"{BUILD_NETWORKS}")
        check_env_overrides(self.env_overrides)
        if not _MEM.match(self.mem_limit):
            raise ValueError(f"memory limit {self.mem_limit!r} is not like 2g or 512m")

    def detect(self, src: Path) -> RuntimeSpec | None:
        comp = find_compose(src)
        if comp is not None:
            service, port = _entrypoint(yaml.safe_load(comp.read_text()) or {})
            return RuntimeSpec(kind="compose", detail=comp.name,
                               base_url=f"http://{service}:{port}")
        if (src / "Dockerfile").is_file():
            return RuntimeSpec(kind="dockerfile", detail="Dockerfile")
        return None

    # -- live bring-up (requires a docker daemon) ----------------------------

    def _project(self, rundir: Path) -> str:
        return f"{self.project_prefix}-{rundir.name}".lower().replace("_", "-")

    def prepare(self, base: Path, src: Path, work: Path) -> tuple[Path, str, int]:
        """Check, resolve and rebuild the author's compose file. Returns the hardened
        file, which lives under `work` (outside the clone), and the service and port a
        probe should address. Needs the docker CLI but not a daemon."""
        work.mkdir(parents=True, exist_ok=True)
        author = yaml.safe_load(base.read_text()) or {}
        precheck_compose(author, base.parent, src)
        if self._env is None:
            self._env = scrubbed_env(work / "home",
                                     docker_host=_operator_docker_host())
        target_env = work / "target.env"
        dotenv_text = apply_env_overrides(filtered_dotenv(base.parent, src), {},
                                          self.env_overrides)
        target_env.write_text(dotenv_text)
        dotenv = dotenv_path(base.parent, src)
        staged, notes = stage_env_files(author, base.parent, src)
        file = base
        if staged is not author:
            # The staged copy lives outside the clone; its relative paths still resolve
            # against the author's directory through --project-directory.
            file = work / "compose.author.yml"
            file.write_text(yaml.safe_dump(staged, sort_keys=False))
        self.provisioning = {
            "build_network": self.build_network,
            "dotenv": str(dotenv.relative_to(src)) if dotenv else None,
            "env_files": notes,
            # Keys only: a value may be a test credential, and the manifest is shown.
            "env_overrides": sorted(self.env_overrides),
            "mem_limit": self.mem_limit,
        }
        resolved = resolve_compose(file, target_env, self._env, project_dir=base.parent)
        apply_env_overrides("", resolved, self.env_overrides)
        service, port = _entrypoint(resolved)
        doc = harden_compose(resolved, src, build_network=self.build_network,
                             mem_limit=self.mem_limit)
        check_dockerfiles(doc, src)
        (work / "empty.env").write_text("")
        hardened = work / "compose.hardened.yml"
        hardened.write_text(yaml.safe_dump(doc, sort_keys=False))
        return hardened, service, port

    def _preflight(self, work: Path) -> None:
        self._env = scrubbed_env(work / "home", docker_host=_operator_docker_host())
        if not docker_available(self._env):
            raise ProvisioningGap("docker daemon not reachable")

        def ask(*argv: str) -> str:
            r = subprocess.run(["docker", *argv], capture_output=True, text=True,
                               timeout=30, env=self._env)
            return r.stdout.strip() if r.returncode == 0 else ""
        check_versions(ask("version", "--format", "{{.Server.Version}}"),
                       ask("compose", "version", "--short"))

    def start(self, spec: RuntimeSpec, rundir: Path) -> RunningTarget:
        if spec.kind != "compose":
            raise DockerError(f"runtime kind {spec.kind!r} not implemented yet")
        src = rundir / "src"
        base = find_compose(src)
        if base is None:
            raise DockerError("compose file vanished between detect and start")
        work = rundir / "compose"
        self._preflight(work)
        hardened, service, port = self.prepare(base, src, work)

        project = self._project(rundir)
        net = f"{project}_{ISOLATED_NET}"

        def stop() -> None:
            self._compose(project, hardened, "down", "-v", "--remove-orphans",
                          timeout=120, check=False)

        # Provisioning: image pulls may touch the network; builds may not, because
        # every build has `network: none`, unless the operator opted in. The contained
        # run that follows cannot either way, because every service is on the internal
        # network. A stack that fails to come up is torn down here: the caller only
        # gets `stop` on success.
        base_url = f"http://{service}:{port}"
        try:
            r = self._compose(project, hardened, "build", timeout=self.build_timeout,
                              check=False)
            if r.returncode != 0:
                tail = (r.stderr or "")[-800:]
                if self.build_network == "none":
                    raise ProvisioningGap(
                        "build failed with the network disabled (a build that fetches "
                        "during RUN needs --build-network): " + tail)
                raise ProvisioningGap("build failed: " + tail)
            self._compose(project, hardened, "up", "-d", "--no-build",
                          timeout=self.up_timeout)
            self._pull_sidecar()
            self._await_health(net, base_url)
        except BaseException as e:
            log = self._save_logs(project, hardened, rundir)
            stop()
            if isinstance(e, DockerError) and log is not None:
                raise type(e)(f"{e}; container logs: {log}") from e
            raise

        return RunningTarget(base_url=base_url, stop=stop, network=net,
                             service=service, port=port)

    def _save_logs(self, project: str, file: Path, rundir: Path) -> Path | None:
        """Write every service's logs into the run's logs/ before teardown removes them,
        so a target that never came up says why. Best-effort: None if nothing to save."""
        try:
            r = self._compose(project, file, "logs", "--no-color", "--timestamps",
                              timeout=60, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        text = (r.stdout or "") + (r.stderr or "")
        if not text.strip():
            return None
        out = rundir / "logs" / "validate-compose.log"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        return out

    def _compose(self, project: str, file: Path, *args: str,
                 timeout: int, check: bool = True) -> subprocess.CompletedProcess:
        # The hardened file's paths are all absolute, so its project directory is the
        # work dir, and an empty --env-file keeps the clone's .env out of this step.
        cmd = ["docker", "compose", "-p", project, "-f", str(file),
               "--project-directory", str(file.parent),
               "--env-file", str(file.parent / "empty.env"), *args]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=self._env)
        if check and r.returncode != 0:
            raise DockerError(f"{' '.join(args)} failed: {r.stderr[-800:]}")
        return r

    def _pull_sidecar(self) -> None:
        subprocess.run(["docker", "pull", SIDECAR_IMAGE],
                       capture_output=True, text=True, timeout=180, env=self._env)

    def probe_exec(self, running: RunningTarget, argv: list[str], *,
                   image: str = SIDECAR_IMAGE, timeout: int = 60) -> tuple[int, str]:
        """Run a command in an ephemeral container joined to the isolated network, so it
        can reach the target and nothing else. Returns (returncode, combined output)."""
        cmd = ["docker", "run", "--rm", "--network", running.network, image, *argv]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=self._env)
        return r.returncode, (r.stdout + r.stderr)

    def _await_health(self, net: str, base_url: str) -> None:
        deadline = time.monotonic() + self.health_timeout
        probe = ["--network", net, SIDECAR_IMAGE, "-s", "-o", "/dev/null",
                 "-w", "%{http_code}", "--max-time", "5", base_url]
        last = ""
        while time.monotonic() < deadline:
            r = subprocess.run(["docker", "run", "--rm", *probe],
                               capture_output=True, text=True, timeout=30, env=self._env)
            last = (r.stdout or "").strip()
            if last and last[0] in "2345":      # any HTTP response means it is up
                return
            time.sleep(2)
        raise DockerError(f"target did not become healthy at {base_url} (last={last!r})")


def register() -> DockerRuntime:
    """Register the Docker runtime with the Layer 3 selector and return it."""
    rt = DockerRuntime()
    register_runtime(rt)
    return rt
