"""Tier 2 target runtime: bring a target up in Docker on an egress-blocked network.

On macOS, Docker runs inside a Linux VM, so the isolation boundary is the VM. What
preserves Quarry's "nothing leaves the machine" guarantee at *runtime* is the network
posture, and that is what this module enforces: every target service is forced onto a
single `internal: true` network, host port publishing is stripped, `network_mode: host`
is removed, and host bind-mounts that escape the project are dropped. The target can
then serve a probe that joins that network, and can reach nothing off the machine.

Image pulls and builds happen before the contained run, as a declared provisioning step
that may touch the network, the same split vulndb uses: provisioning may fetch, the
contained run may not. A probe reaches the target by joining the isolated network as an
ephemeral sidecar; nothing is ever published to the host.

`harden_compose` is the security core and is pure, so it is unit-tested without Docker.
The bring-up path shells out to `docker` and is exercised only when a daemon is present.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from .validate import RuntimeSpec, RunningTarget, TargetRuntime, register_runtime

COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml",
                 "compose.yml", "compose.yaml")
ISOLATED_NET = "quarry_isolated"
# A minimal, pinned image used only as an ephemeral sidecar on the isolated network
# (health-gating and, later, probes). Pulled during provisioning.
SIDECAR_IMAGE = "curlimages/curl:8.11.1"


class DockerError(RuntimeError):
    pass


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def find_compose(src: Path) -> Path | None:
    for name in COMPOSE_NAMES:
        p = src / name
        if p.is_file():
            return p
    return None


def _escapes_project(source: str) -> bool:
    """A bind-mount source that reaches outside the target's own tree. Absolute paths
    and parent-relative paths (../) can read host files, so they are dropped."""
    s = source.strip()
    if not s:
        return False
    return s.startswith("/") or s.startswith("~") or s.startswith("..") or "/../" in s


def _strip_host_mounts(svc: dict) -> None:
    vols = svc.get("volumes")
    if not isinstance(vols, list):
        return
    kept = []
    for v in vols:
        if isinstance(v, str):
            src = v.split(":", 1)[0]
            if _escapes_project(src):
                continue
        elif isinstance(v, dict):
            if v.get("type") == "bind" and _escapes_project(str(v.get("source", ""))):
                continue
        kept.append(v)
    if kept:
        svc["volumes"] = kept
    else:
        svc.pop("volumes", None)


def harden_compose(doc: dict, *, network: str = ISOLATED_NET) -> dict:
    """Return a copy of a parsed compose document with the runtime egress guarantees
    forced on: one internal-only network for every service, no host port publishing, no
    host networking, no host bind-mounts that escape the project."""
    out = json.loads(json.dumps(doc))   # deep copy of plain data
    services = out.get("services")
    if not isinstance(services, dict):
        raise DockerError("compose file has no services")
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        svc.pop("ports", None)                 # no host port publishing
        nm = str(svc.get("network_mode", ""))
        if "host" in nm or "bridge" in nm or ":" in nm:
            svc.pop("network_mode", None)       # force onto our network, not the host's
        svc.pop("extra_hosts", None)            # no host-gateway back-channel
        svc["networks"] = [network]            # only the isolated network
        _strip_host_mounts(svc)
    # Replace the network topology wholesale: one internal network, nothing else.
    out["networks"] = {network: {"internal": True, "driver": "bridge"}}
    return out


def _entrypoint(doc: dict) -> tuple[str, int]:
    """The service and container port a probe should address, inferred from the ORIGINAL
    document (before ports are stripped): prefer a service that published or exposed a
    port, else the first service; default the port to 8080."""
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

    for name, svc in services.items():
        if isinstance(svc, dict):
            p = container_port(svc)
            if p is not None:
                return name, p
    first = next(iter(services))
    return first, 8080


@dataclass
class DockerRuntime:
    """A TargetRuntime backed by Docker Compose. Compose files are the target author's
    own declared boot contract, which is why this is the primary runtime."""
    project_prefix: str = "quarry"
    up_timeout: int = 300
    health_timeout: int = 120

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

    def start(self, spec: RuntimeSpec, rundir: Path) -> RunningTarget:
        if spec.kind != "compose":
            raise DockerError(f"runtime kind {spec.kind!r} not implemented yet")
        src = rundir / "src"
        base = find_compose(src)
        if base is None:
            raise DockerError("compose file vanished between detect and start")
        doc = yaml.safe_load(base.read_text()) or {}
        service, port = _entrypoint(doc)
        hardened = src / "quarry-compose.hardened.yml"
        hardened.write_text(yaml.safe_dump(harden_compose(doc), sort_keys=False))

        project = self._project(rundir)
        net = f"{project}_{ISOLATED_NET}"
        # Provisioning: build/pull may touch the network. The contained run that follows
        # cannot, because every service is on the internal network.
        self._compose(project, hardened, "up", "-d", "--build", timeout=self.up_timeout)
        self._pull_sidecar()

        base_url = f"http://{service}:{port}"
        self._await_health(net, base_url)

        def stop() -> None:
            self._compose(project, hardened, "down", "-v", "--remove-orphans",
                          timeout=120, check=False)

        return RunningTarget(base_url=base_url, stop=stop, network=net,
                             service=service, port=port)

    def _compose(self, project: str, file: Path, *args: str,
                 timeout: int, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["docker", "compose", "-p", project, "-f", str(file), *args]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise DockerError(f"{' '.join(args)} failed: {r.stderr[-800:]}")
        return r

    def _pull_sidecar(self) -> None:
        subprocess.run(["docker", "pull", SIDECAR_IMAGE],
                       capture_output=True, text=True, timeout=180)

    def probe_exec(self, running: RunningTarget, argv: list[str], *,
                   image: str = SIDECAR_IMAGE, timeout: int = 60) -> tuple[int, str]:
        """Run a command in an ephemeral container joined to the isolated network, so it
        can reach the target and nothing else. Returns (returncode, combined output)."""
        cmd = ["docker", "run", "--rm", "--network", running.network, image, *argv]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)

    def _await_health(self, net: str, base_url: str) -> None:
        deadline = time.monotonic() + self.health_timeout
        probe = ["--network", net, SIDECAR_IMAGE, "-s", "-o", "/dev/null",
                 "-w", "%{http_code}", "--max-time", "5", base_url]
        last = ""
        while time.monotonic() < deadline:
            r = subprocess.run(["docker", "run", "--rm", *probe],
                               capture_output=True, text=True, timeout=30)
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
