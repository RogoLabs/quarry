"""Tier 2 Docker runtime: the egress-hardening transform (hermetic) and a real
bring-up that proves a probe can reach the target but the target cannot reach the
internet (docker-gated).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic import runtime_docker as rt                     # noqa: E402
from quarry.dynamic.runtime_docker import DockerRuntime, harden_compose, ISOLATED_NET  # noqa: E402

# ------------------------------------------------------------------ hermetic

def test_harden_forces_internal_network_and_strips_host_reach():
    doc = {
        "services": {
            "web": {
                "image": "app:latest",
                "ports": ["80:8080"],
                "network_mode": "host",
                "extra_hosts": ["host.docker.internal:host-gateway"],
                "volumes": ["./app:/app", "/etc/passwd:/etc/passwd:ro", "data:/data"],
            },
        },
        "networks": {"default": {}},
    }
    out = harden_compose(doc)
    web = out["services"]["web"]
    assert "ports" not in web                       # no host publishing
    assert "network_mode" not in web                # no host networking
    assert "extra_hosts" not in web                 # no host-gateway back-channel
    assert web["networks"] == [ISOLATED_NET]
    assert web["volumes"] == ["./app:/app", "data:/data"]   # host bind dropped, others kept
    assert out["networks"] == {ISOLATED_NET: {"internal": True, "driver": "bridge"}}
    # input is not mutated
    assert doc["services"]["web"]["ports"] == ["80:8080"]


def test_harden_handles_long_syntax_bind_mounts():
    doc = {"services": {"db": {"image": "pg", "volumes": [
        {"type": "bind", "source": "/Users/me/secrets", "target": "/s"},
        {"type": "bind", "source": "./seed", "target": "/seed"},
        {"type": "volume", "source": "pgdata", "target": "/var/lib/pg"},
    ]}}}
    vols = harden_compose(doc)["services"]["db"]["volumes"]
    assert {"type": "bind", "source": "/Users/me/secrets", "target": "/s"} not in vols
    assert {"type": "bind", "source": "./seed", "target": "/seed"} in vols
    assert {"type": "volume", "source": "pgdata", "target": "/var/lib/pg"} in vols


def test_harden_forces_hub_clients_offline_in_either_env_syntax():
    doc = {"services": {
        "mapped": {"image": "a", "environment": {"PYTHONUNBUFFERED": "TRUE",
                                                 "HF_HUB_OFFLINE": "0"}},
        "listed": {"image": "b", "environment": ["PYTHONUNBUFFERED=TRUE",
                                                 "TRANSFORMERS_OFFLINE=0", "PASSTHRU"]},
        "bare": {"image": "c"},
    }}
    out = harden_compose(doc)["services"]
    assert out["mapped"]["environment"] == {"PYTHONUNBUFFERED": "TRUE", **rt.OFFLINE_ENV}
    assert out["listed"]["environment"] == [
        "PYTHONUNBUFFERED=TRUE", "PASSTHRU",
        *(f"{k}={v}" for k, v in rt.OFFLINE_ENV.items())]   # author's "=0" replaced
    assert out["bare"]["environment"] == rt.OFFLINE_ENV
    assert doc["services"]["mapped"]["environment"]["HF_HUB_OFFLINE"] == "0"  # not mutated


def test_start_tears_down_and_keeps_logs_when_target_never_gets_healthy(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "docker-compose.yml").write_text(
        "services:\n  api:\n    image: x\n    restart: always\n    ports: ['8000:8000']\n")
    calls: list[tuple[str, ...]] = []

    def fake_compose(self, project, file, *args, timeout, check=True):
        calls.append(args)
        out = "api-1  | Retrying in 8s [Retry 5/5].\n" if args[0] == "logs" else ""
        return rt.subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    def never_healthy(self, net, base_url):
        raise rt.DockerError(f"target did not become healthy at {base_url} (last='000')")

    monkeypatch.setattr(DockerRuntime, "_compose", fake_compose)
    monkeypatch.setattr(DockerRuntime, "_pull_sidecar", lambda self: None)
    monkeypatch.setattr(DockerRuntime, "_await_health", never_healthy)
    runtime = DockerRuntime()
    with pytest.raises(rt.DockerError, match="container logs: .*validate-compose.log"):
        runtime.start(runtime.detect(src), tmp_path)
    assert [c[0] for c in calls] == ["up", "logs", "down"]     # logs saved, then torn down
    assert "Retry 5/5" in (tmp_path / "logs" / "validate-compose.log").read_text()


def test_detect_compose_and_entrypoint(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  api:\n    image: x\n    ports: ['9000:3000']\n")
    spec = DockerRuntime().detect(tmp_path)
    assert spec is not None and spec.kind == "compose"
    assert spec.base_url == "http://api:3000"       # container port, not host port


def test_detect_dockerfile_and_none(tmp_path):
    assert DockerRuntime().detect(tmp_path) is None
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    spec = DockerRuntime().detect(tmp_path)
    assert spec is not None and spec.kind == "dockerfile"


def test_find_compose_prefers_root_then_known_subdirs(tmp_path):
    from quarry.dynamic.runtime_docker import find_compose
    # A test tree ships its own stack; it must not win.
    (tmp_path / "test-http" / "docker").mkdir(parents=True)
    (tmp_path / "test-http" / "docker" / "docker-compose.yml").write_text("services: {}\n")
    assert find_compose(tmp_path) is None
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "docker-compose.yml").write_text("services:\n  api:\n    image: x\n")
    assert find_compose(tmp_path) == tmp_path / "docker" / "docker-compose.yml"
    (tmp_path / "compose.yaml").write_text("services:\n  api:\n    image: x\n")
    assert find_compose(tmp_path) == tmp_path / "compose.yaml"   # root wins


def test_detect_finds_compose_under_docker_subdir(tmp_path):
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: x\n    ports: ['8080:5000']\n")
    spec = DockerRuntime().detect(tmp_path)
    assert spec is not None and spec.kind == "compose"
    assert spec.base_url == "http://web:5000"


# ------------------------------------------------------------------ live (docker)

docker = pytest.mark.skipif(not rt.docker_available(), reason="docker daemon not available")


@docker
def test_target_is_reachable_on_the_net_but_cannot_egress(tmp_path):
    """The whole guarantee, end to end: a sidecar on the isolated network reaches the
    target, and the same sidecar cannot reach the public internet."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: python:3.13-alpine\n"
        "    command: ['python','-m','http.server','8080']\n"
        "    ports: ['18080:8080']\n")
    runtime = DockerRuntime(health_timeout=90, up_timeout=300)
    spec = runtime.detect(src)
    assert spec is not None and spec.base_url == "http://web:8080"
    running = runtime.start(spec, tmp_path)
    try:
        code, out = runtime.probe_exec(running, [
            "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5",
            running.base_url])
        assert out.strip() == "200", f"target not reachable on net: {out!r}"

        code, out = runtime.probe_exec(running, [
            "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8",
            "https://example.com"])
        assert out.strip() != "200", f"egress was NOT blocked: got {out!r}"
    finally:
        running.stop()
