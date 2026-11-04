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

def _compose_cli() -> bool:
    import shutil, subprocess
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "compose", "version"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


compose_cli = pytest.mark.skipif(not _compose_cli(), reason="docker compose CLI not found")

FORCED = {"networks", "cap_drop", "cap_add", "security_opt", "restart", "environment",
          *rt.LIMITS}


def _hostile(src: Path, outside: Path) -> dict:
    """A resolved document (the shape `docker compose config` prints) that asks for
    every escape item 2 of the improvement plan lists, and a few it does not."""
    return {
        "name": "evil",
        "services": {
            "web": {
                "image": "curlimages/curl:8.11.1",       # with build: would retag the sidecar
                "build": {"context": str(src), "dockerfile": "Dockerfile",
                          "args": {"A": "1", "BUILDKIT_SYNTAX": "evil/frontend"},
                          "ssh": ["default"], "secrets": ["tok"], "network": "host",
                          "cache_to": [f"type=local,dest={outside}"], "tags": ["postgres:16"],
                          "additional_contexts": {"x": str(outside)},
                          "extra_hosts": ["h:host-gateway"], "privileged": True},
                "privileged": True, "pid": "host", "ipc": "host", "uts": "host",
                "userns_mode": "host", "cgroup": "host", "cgroup_parent": "/",
                "cap_add": ["SYS_ADMIN"], "devices": ["/dev/kmsg:/dev/kmsg"],
                "device_cgroup_rules": ["a *:* rwm"],
                "security_opt": ["apparmor=unconfined", "seccomp=unconfined"],
                "sysctls": {"net.ipv4.ip_forward": 1}, "ulimits": {"nproc": 999999},
                "volumes_from": ["other"], "network_mode": "host", "dns": ["1.1.1.1"],
                "ports": [{"target": 8080, "published": "8080"}],
                "extra_hosts": ["host.docker.internal:host-gateway"],
                "logging": {"driver": "syslog",
                            "options": {"syslog-address": "udp://203.0.113.9:514"}},
                "use_api_socket": True, "secrets": ["tok"], "configs": ["c"],
                "labels": {"com.docker.compose.project": "other"},
                "restart": "always", "deploy": {"resources": {}}, "runtime": "runc",
                "environment": {"KEEP": "yes"},
                "volumes": [
                    {"type": "bind", "source": str(outside), "target": "/host"},
                    {"type": "bind", "source": str(src / ".." / ".."), "target": "/up"},
                    {"type": "bind", "source": str(src / "app"), "target": "/app"},
                    {"type": "volume", "source": "data", "target": "/data"},
                    {"type": "npipe", "source": "x", "target": "/y"},
                    {"type": "tmpfs", "target": "/tmp", "tmpfs": {"size": 1024}},
                ],
                "depends_on": {"db": {"condition": "service_healthy", "restart": True}},
            },
            "db": {"image": "postgres:16", "healthcheck": {"test": ["CMD", "true"]}},
        },
        "volumes": {"data": {"external": True, "name": "operator_volume",
                             "driver_opts": {"type": "none", "o": "bind",
                                             "device": str(outside)}}},
        "secrets": {"tok": {"file": str(outside / "id_rsa")}},
        "configs": {"c": {"file": "/etc/passwd"}},
        "networks": {"default": {"name": "host"}},
        "models": {"m": {"model": "ai/x"}},
    }


def test_harden_rebuilds_from_an_allowlist(tmp_path):
    src, outside = tmp_path / "src", tmp_path / "home"
    (src / "app").mkdir(parents=True)
    outside.mkdir()
    out = harden_compose(_hostile(src, outside), src)

    assert set(out) == {"services", "networks", "volumes"}   # no secrets/configs/models/name
    assert out["networks"] == {ISOLATED_NET: {"internal": True, "driver": "bridge"}}
    # Named volumes come back empty and project-scoped: no external, name or driver_opts.
    assert out["volumes"] == {"data": {}}
    web = out["services"]["web"]
    allowed = set(rt.SERVICE_KEYS) | FORCED | {"build", "volumes", "depends_on"}
    assert set(web) <= allowed, set(web) - allowed
    assert "image" not in web                       # built, so never tagged with a chosen name
    assert web["build"] == {"context": str(src), "dockerfile": "Dockerfile",
                            "args": {"A": "1"}, "network": "none"}
    assert web["networks"] == [ISOLATED_NET]
    assert web["cap_drop"] == ["ALL"] and "SYS_ADMIN" not in web["cap_add"]
    assert set(web["cap_add"]) == set(rt.KEEP_CAPS)
    assert web["security_opt"] == ["no-new-privileges:true"]
    assert web["restart"] == "no"
    assert {k: web[k] for k in rt.LIMITS} == rt.LIMITS
    assert web["environment"] == {"KEEP": "yes", **rt.OFFLINE_ENV}
    assert web["volumes"] == [
        {"type": "bind", "source": str(src / "app"), "target": "/app"},
        {"type": "volume", "source": "data", "target": "/data"},
        {"type": "tmpfs", "target": "/tmp", "tmpfs": {"size": 1024}},
    ]
    assert web["depends_on"] == {"db": {"condition": "service_healthy"}}
    db = out["services"]["db"]
    assert db["image"] == "postgres:16" and db["healthcheck"] == {"test": ["CMD", "true"]}
    assert db["cap_drop"] == ["ALL"]


def test_harden_drops_a_bind_that_escapes_through_a_symlink(tmp_path):
    src, outside = tmp_path / "src", tmp_path / "secrets"
    src.mkdir()
    outside.mkdir()
    (src / "link").symlink_to(outside)
    doc = {"services": {"web": {"image": "x", "volumes": [
        {"type": "bind", "source": str(src / "link"), "target": "/s"},
        {"type": "bind", "source": "./rel", "target": "/r"},      # never resolved: dropped
    ]}}}
    assert "volumes" not in harden_compose(doc, src)["services"]["web"]


@pytest.mark.parametrize("build", [
    "https://github.com/evil/ctx.git",
    "git@github.com:evil/ctx.git",
    "/etc",
    {"context": "{src}", "dockerfile": "../../Dockerfile"},
])
def test_harden_refuses_a_build_from_outside_the_clone(tmp_path, build):
    src = tmp_path / "src"
    src.mkdir()
    if isinstance(build, dict):
        build = {k: v.format(src=src) for k, v in build.items()}
    with pytest.raises(rt.ComposeRefused, match="not inside the clone"):
        harden_compose({"services": {"web": {"build": build}}}, src)


def test_harden_handles_short_syntax_and_offline_env_in_either_syntax(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    doc = {"services": {
        "mapped": {"image": "a", "environment": {"PYTHONUNBUFFERED": "TRUE",
                                                 "HF_HUB_OFFLINE": "0"},
                   "volumes": [f"{src}:/app:ro", "/etc/passwd:/etc/passwd", "pg:/var/pg"]},
        "listed": {"image": "b", "environment": ["PYTHONUNBUFFERED=TRUE",
                                                 "TRANSFORMERS_OFFLINE=0", "PASSTHRU"]},
    }}
    out = harden_compose(doc, src)["services"]
    assert out["mapped"]["environment"] == {"PYTHONUNBUFFERED": "TRUE", **rt.OFFLINE_ENV}
    assert out["listed"]["environment"] == [
        "PYTHONUNBUFFERED=TRUE", "PASSTHRU",
        *(f"{k}={v}" for k, v in rt.OFFLINE_ENV.items())]   # author's "=0" replaced
    assert out["mapped"]["volumes"] == [
        {"type": "bind", "source": str(src), "target": "/app", "read_only": True},
        {"type": "volume", "source": "pg", "target": "/var/pg"}]
    assert doc["services"]["mapped"]["environment"]["HF_HUB_OFFLINE"] == "0"  # not mutated


def test_precheck_refuses_what_config_would_read_from_outside(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.env").write_text("A=1\n")
    ok = {"services": {"web": {"image": "x", "env_file": ["ok.env", {"path": "ok.env"}],
                               "extends": {"service": "base"}}}}
    rt.precheck_compose(ok, src, src)                    # same-file extends is fine
    for doc, why in [
        ({"include": ["https://example.com/c.yml"], "services": {"w": {"image": "x"}}},
         "include"),
        ({"services": {"w": {"image": "x", "extends": {"file": "../b.yml", "service": "b"}}}},
         "extends.file"),
        ({"services": {"w": {"image": "x", "env_file": "../../.aws/credentials"}}},
         "env_file"),
        ({"services": {"w": {"image": "x", "env_file": "${HOME}/.netrc"}}}, "env_file"),
        ({"services": {"w": {"image": "x", "env_file": "~/.netrc"}}}, "env_file"),
        ({"services": {"w": {"image": "x", "label_file": "/etc/hosts"}}}, "label_file"),
    ]:
        with pytest.raises(rt.ComposeRefused, match=why):
            rt.precheck_compose(doc, src, src)


def test_filtered_dotenv_keeps_values_and_drops_cli_steering_keys(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / ".env").write_text(
        "FOO=bar\nexport PORT=8000\nCOMPOSE_PROJECT_NAME=evil\n"
        "COMPOSE_ENV_FILES=/Users/me/.secrets\nDOCKER_HOST=tcp://203.0.113.9:2375\n"
        "BUILDKIT_SYNTAX=evil/frontend\nQ=\"open\nCOMPOSE_FILE=/etc/x.yml\n# comment\n")
    assert rt.filtered_dotenv(src, src) == "FOO=bar\nPORT=8000\n"


def test_filtered_dotenv_ignores_a_dotenv_that_resolves_outside(tmp_path):
    src, outside = tmp_path / "src", tmp_path / "home.env"
    src.mkdir()
    outside.write_text("TOKEN=ghp_operator\n")
    (src / ".env").symlink_to(outside)
    assert rt.filtered_dotenv(src, src) == ""


def test_check_dockerfiles_refuses_a_chosen_frontend(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    doc = {"services": {"web": {"build": {"context": str(src), "dockerfile": "Dockerfile"}}}}
    (src / "Dockerfile").write_text("# syntax=docker/dockerfile:1.7\nFROM alpine\n")
    rt.check_dockerfiles(doc, src)
    (src / "Dockerfile").write_text("# escape=`\n# syntax = evil.example/frontend:1\nFROM a\n")
    with pytest.raises(rt.ComposeRefused, match="frontend"):
        rt.check_dockerfiles(doc, src)
    # A directive after the first instruction is a comment, and BuildKit ignores it.
    (src / "Dockerfile").write_text("FROM alpine\n# syntax=evil/frontend\n")
    rt.check_dockerfiles(doc, src)
    inline = {"services": {"web": {"build": {"context": str(src),
                                             "dockerfile_inline": "#syntax=evil/f\nFROM a"}}}}
    with pytest.raises(rt.ComposeRefused, match="frontend"):
        rt.check_dockerfiles(inline, src)


def test_scrubbed_env_carries_nothing_from_the_operator(tmp_path, monkeypatch):
    import json
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_operator")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    monkeypatch.setenv("HTTPS_PROXY", "http://203.0.113.9:3128")
    env = rt.scrubbed_env(tmp_path / "home", docker_host="unix:///d.sock")
    assert set(env) == {"PATH", "HOME", "DOCKER_CONFIG", "DOCKER_HOST"}
    assert env["HOME"] == str(tmp_path / "home")
    cfg = json.loads((tmp_path / "home" / ".docker" / "config.json").read_text())
    assert set(cfg) == {"cliPluginsExtraDirs"}           # no auths, credsStore or proxies


@pytest.mark.parametrize("engine,compose,ok", [
    ("29.0.1", "5.6.1", True), ("20.10.24", "v2.0.0", True),
    ("19.03.15", "2.20.0", False), ("27.0.0", "1.29.2", False), ("", "2.20.0", False)])
def test_check_versions(engine, compose, ok):
    if ok:
        rt.check_versions(engine, compose)
    else:
        with pytest.raises(rt.ProvisioningGap, match="minimum"):
            rt.check_versions(engine, compose)


@compose_cli
def test_prepare_resolves_without_the_operator_environment(tmp_path, monkeypatch):
    """The real `docker compose config` (no daemon needed) on a hostile file: the
    operator's token must not reach the hardened document, while the target's own
    .env still fills its own variables."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_operator_token")
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM alpine\n")
    (src / ".env").write_text("FOO=from_dotenv\nCOMPOSE_PROJECT_NAME=evil\n")
    (src / "compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    build: {context: ., args: {T: '${GITHUB_TOKEN}'}}\n"
        "    privileged: true\n"
        "    environment: {TOKEN: '${GITHUB_TOKEN:-none}', FOO: '${FOO}', LIT: 'pa$$word'}\n"
        "    ports: ['9000:3000']\n"
        "    volumes: ['./app:/app', '../../:/up']\n"
        "    secrets: [tok]\n"
        "secrets:\n"
        "  tok: {file: ../../id_rsa}\n")
    runtime = DockerRuntime()
    hardened, service, port = runtime.prepare(src / "compose.yml", src, tmp_path / "compose")
    text = hardened.read_text()
    assert "ghp_operator_token" not in text
    assert "ghp_operator_token" not in (tmp_path / "compose" / "target.env").read_text()
    assert (service, port) == ("web", 3000)
    assert hardened.parent == tmp_path / "compose"       # outside the clone
    import yaml
    web = yaml.safe_load(text)["services"]["web"]
    assert web["environment"]["TOKEN"] == "none"
    assert web["environment"]["FOO"] == "from_dotenv"
    assert web["environment"]["LIT"] == "pa$$word"       # stays escaped for the next read
    assert web["build"]["args"] == {"T": ""} and web["build"]["network"] == "none"
    assert "privileged" not in web and "secrets" not in web and "ports" not in web
    assert [v["target"] for v in web["volumes"]] == ["/app"]
    assert set(runtime._env) <= {"PATH", "HOME", "DOCKER_CONFIG", "DOCKER_HOST"}


def _fake_start(monkeypatch, *, build_rc=0):
    calls: list[tuple[str, ...]] = []

    def fake_compose(self, project, file, *args, timeout, check=True):
        calls.append(args)
        rc = build_rc if args[0] == "build" else 0
        out = "api-1  | Retrying in 8s [Retry 5/5].\n" if args[0] == "logs" else ""
        return rt.subprocess.CompletedProcess(args, rc, stdout=out,
                                              stderr="ERROR: could not resolve host")

    monkeypatch.setattr(DockerRuntime, "_preflight", lambda self, work: None)
    monkeypatch.setattr(rt, "resolve_compose",
                        lambda base, env_file, env, **kw: rt.yaml.safe_load(base.read_text()))
    monkeypatch.setattr(rt, "_operator_docker_host", lambda: None)
    monkeypatch.setattr(DockerRuntime, "_compose", fake_compose)
    monkeypatch.setattr(DockerRuntime, "_pull_sidecar", lambda self: None)
    return calls


def test_start_tears_down_and_keeps_logs_when_target_never_gets_healthy(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "docker-compose.yml").write_text(
        "services:\n  api:\n    image: x\n    restart: always\n    ports: ['8000:8000']\n")
    calls = _fake_start(monkeypatch)

    def never_healthy(self, net, base_url):
        raise rt.DockerError(f"target did not become healthy at {base_url} (last='000')")

    monkeypatch.setattr(DockerRuntime, "_await_health", never_healthy)
    runtime = DockerRuntime()
    with pytest.raises(rt.DockerError, match="container logs: .*validate-compose.log"):
        runtime.start(runtime.detect(src), tmp_path)
    assert [c[0] for c in calls] == ["build", "up", "logs", "down"]
    assert "--no-build" in calls[1]                      # nothing builds outside `build`
    assert "Retry 5/5" in (tmp_path / "logs" / "validate-compose.log").read_text()
    hardened = rt.yaml.safe_load((tmp_path / "compose" / "compose.hardened.yml").read_text())
    assert hardened["services"]["api"]["restart"] == "no"
    assert not (src / "quarry-compose.hardened.yml").exists()   # nothing written to the clone


def test_a_build_that_needs_the_network_is_a_provisioning_gap(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Dockerfile").write_text("FROM alpine\nRUN apk add curl\n")
    (src / "compose.yml").write_text(f"services:\n  web:\n    build: {{context: {src}}}\n")
    calls = _fake_start(monkeypatch, build_rc=1)
    runtime = DockerRuntime()
    with pytest.raises(rt.ProvisioningGap, match="network disabled"):
        runtime.start(runtime.detect(src), tmp_path)
    assert [c[0] for c in calls] == ["build", "logs", "down"]   # never brought up


def test_a_failed_build_with_the_network_on_is_not_blamed_on_the_network(tmp_path,
                                                                         monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Dockerfile").write_text("FROM alpine\nRUN false\n")
    (src / "compose.yml").write_text(f"services:\n  web:\n    build: {{context: {src}}}\n")
    _fake_start(monkeypatch, build_rc=1)
    runtime = DockerRuntime()
    with pytest.raises(rt.ProvisioningGap, match="--build-network"):
        runtime.start(runtime.detect(src), tmp_path)
    runtime = DockerRuntime(build_network="default")
    with pytest.raises(rt.ProvisioningGap) as e:
        runtime.start(runtime.detect(src), tmp_path)
    assert "network disabled" not in str(e.value) and "build failed" in str(e.value)
    hardened = rt.yaml.safe_load((tmp_path / "compose" / "compose.hardened.yml").read_text())
    assert hardened["services"]["web"]["build"]["network"] == "default"
    assert runtime.provisioning["build_network"] == "default"


def test_build_network_is_none_unless_opted_in_and_never_host(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    doc = {"services": {"web": {"build": {"context": str(src), "network": "host"}}}}
    assert harden_compose(doc, src)["services"]["web"]["build"]["network"] == "none"
    opted = harden_compose(doc, src, build_network="default")
    assert opted["services"]["web"]["build"]["network"] == "default"
    assert opted["networks"][ISOLATED_NET]["internal"] is True     # the run stays offline
    with pytest.raises(ValueError):
        harden_compose(doc, src, build_network="host")
    with pytest.raises(ValueError):
        DockerRuntime(build_network="host")


def test_a_shipped_env_sample_stands_in_for_a_missing_dotenv(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / ".env.sample").write_text("PORT=10001\nCOMPOSE_FILE=/etc/x.yml\n")
    assert rt.dotenv_path(src, src) == src / ".env.sample"
    assert rt.filtered_dotenv(src, src) == "PORT=10001\n"
    (src / ".env").write_text("PORT=1\n")                 # a real .env still wins
    assert rt.filtered_dotenv(src, src) == "PORT=1\n"


def test_stage_env_files_uses_a_sample_or_makes_a_missing_file_optional(tmp_path):
    src = tmp_path / "src"
    (src / "conf").mkdir(parents=True)
    (src / ".env.sample").write_text("A=1\n")
    (src / "conf" / "app.env").write_text("B=2\n")
    doc = {"services": {
        "web": {"image": "x", "env_file": [".env", "conf/app.env"]},
        "worker": {"image": "x", "env_file": {"path": "worker.env"}},
    }}
    staged, notes = rt.stage_env_files(doc, src, src)
    assert staged["services"]["web"]["env_file"] == [str(src / ".env.sample"), "conf/app.env"]
    assert staged["services"]["worker"]["env_file"] == [
        {"path": "worker.env", "required": False}]
    assert len(notes) == 2 and ".env.sample" in notes[0]
    assert doc["services"]["web"]["env_file"] == [".env", "conf/app.env"]  # not mutated
    present = {"services": {"web": {"image": "x", "env_file": "conf/app.env"}}}
    assert rt.stage_env_files(present, src, src) == (present, [])


def test_entrypoint_prefers_the_service_built_from_the_clone():
    # VulnLookup's shape: `config` sorts services, so a datastore publishing a port comes
    # before the web app the project builds.
    doc = {"services": {
        "db": {"image": "postgres:13"},
        "kvrocks_master": {"image": "apache/kvrocks", "ports": ["10002:10002"]},
        "vulnerability_lookup": {"build": {"context": "."}, "ports": ["10001:10001"]},
    }}
    assert rt._entrypoint(doc) == ("vulnerability_lookup", 10001)
    doc["services"]["vulnerability_lookup"].pop("ports")
    assert rt._entrypoint(doc) == ("kvrocks_master", 10002)    # no port on the build
    doc["services"]["kvrocks_master"].pop("ports")
    assert rt._entrypoint(doc) == ("vulnerability_lookup", 8080)


@compose_cli
def test_prepare_boots_a_fresh_clone_from_its_env_sample(tmp_path):
    """The real `docker compose config` on a file whose env_file is the .env a fresh
    clone does not have. Relative paths in the staged copy still resolve to the clone."""
    src = tmp_path / "src"
    (src / "cache").mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM alpine\n")
    (src / ".env.sample").write_text("PORT=10001\nPASS=sample_pw\n")
    (src / "docker-compose.yml").write_text(
        "services:\n"
        "  cache:\n"
        "    image: valkey/valkey\n"
        "    command: valkey-server --requirepass ${PASS}\n"
        "    volumes: ['./cache:/cache']\n"
        "  web:\n"
        "    build: {context: .}\n"
        "    env_file: [.env]\n"
        "    ports: ['${PORT}:${PORT}']\n")
    runtime = DockerRuntime()
    hardened, service, port = runtime.prepare(src / "docker-compose.yml", src,
                                              tmp_path / "compose")
    import yaml
    doc = yaml.safe_load(hardened.read_text())
    assert (service, port) == ("web", 10001)
    assert doc["services"]["web"]["environment"]["PASS"] == "sample_pw"
    assert doc["services"]["web"]["build"]["context"] == str(src)
    assert doc["services"]["cache"]["volumes"][0]["source"] == str(src / "cache")
    assert "sample_pw" in str(doc["services"]["cache"]["command"])
    assert runtime.provisioning["dotenv"] == ".env.sample"
    assert not (src / ".env").exists()                 # nothing written to the clone


def test_memory_cap_is_the_operators_but_must_be_a_size(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    doc = {"services": {"web": {"image": "x", "mem_limit": "64g"}}}
    assert harden_compose(doc, src)["services"]["web"]["mem_limit"] == "2g"
    assert harden_compose(doc, src, mem_limit="6g")["services"]["web"]["mem_limit"] == "6g"
    for bad in ("6", "0g", "-1g", "6g; rm", "6gb"):
        with pytest.raises(ValueError):
            harden_compose(doc, src, mem_limit=bad)
        with pytest.raises(ValueError):
            DockerRuntime(mem_limit=bad)


def test_env_overrides_refuse_cli_keys_and_line_breaks():
    rt.check_env_overrides({"INSTANCE_UUID": "x", "_A1": ""})
    for bad in ({"COMPOSE_FILE": "/etc/x"}, {"DOCKER_HOST": "tcp://h"}, {"1X": "y"},
                {"A-B": "y"}, {"A": "x\nCOMPOSE_FILE=/etc/x"}):
        with pytest.raises(ValueError):
            rt.check_env_overrides(bad)
    with pytest.raises(ValueError):
        DockerRuntime(env_overrides={"BUILDKIT_SYNTAX": "evil/f"})


def test_env_overrides_replace_the_targets_value_everywhere_it_lands():
    resolved = {"services": {
        "web": {"environment": {"INSTANCE_UUID": "set_instance_uuid", "PORT": "1"}},
        "worker": {"environment": ["INSTANCE_UUID=set_instance_uuid", "X=1"]},
        "db": {"environment": {"POSTGRES_DB": "v"}},
    }}
    text = rt.apply_env_overrides("PORT=1\nINSTANCE_UUID=set_instance_uuid\n", resolved,
                                  {"INSTANCE_UUID": "6f1d"})
    assert text == "PORT=1\nINSTANCE_UUID=6f1d\n"
    assert resolved["services"]["web"]["environment"]["INSTANCE_UUID"] == "6f1d"
    assert resolved["services"]["worker"]["environment"] == ["INSTANCE_UUID=6f1d", "X=1"]
    assert "INSTANCE_UUID" not in resolved["services"]["db"]["environment"]
    assert rt.apply_env_overrides("A=1\n", resolved, {}) == "A=1\n"


@compose_cli
def test_an_operator_value_replaces_a_sample_placeholder_in_args_and_env(tmp_path,
                                                                        monkeypatch):
    monkeypatch.setenv("INSTANCE_UUID", "from_the_operator_shell")
    src = tmp_path / "src"
    src.mkdir()
    (src / "Dockerfile").write_text("FROM alpine\n")
    (src / ".env.sample").write_text("INSTANCE_UUID=set_instance_uuid\nNAME=YOURORG\n")
    (src / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    build: {context: ., args: {INSTANCE_UUID: '${INSTANCE_UUID}'}}\n"
        "    env_file: .env\n"
        "    expose: ['10001']\n")
    runtime = DockerRuntime(env_overrides={"INSTANCE_UUID": "6f1d0c1e-0000-4000-8000-1"})
    hardened, _, _ = runtime.prepare(src / "docker-compose.yml", src, tmp_path / "compose")
    import yaml
    web = yaml.safe_load(hardened.read_text())["services"]["web"]
    assert web["build"]["args"]["INSTANCE_UUID"] == "6f1d0c1e-0000-4000-8000-1"
    assert web["environment"]["INSTANCE_UUID"] == "6f1d0c1e-0000-4000-8000-1"
    assert web["environment"]["NAME"] == "YOURORG"          # the rest of the sample stays
    assert "from_the_operator_shell" not in hardened.read_text()
    assert runtime.provisioning["env_overrides"] == ["INSTANCE_UUID"]


def test_start_refuses_a_hostile_file_before_any_docker_call(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "compose.yml").write_text(
        "include: ['https://example.com/x.yml']\nservices:\n  web:\n    image: x\n")
    calls = _fake_start(monkeypatch)
    resolved = []
    monkeypatch.setattr(rt, "resolve_compose", lambda *a: resolved.append(a))
    runtime = DockerRuntime()
    with pytest.raises(rt.ComposeRefused, match="include"):
        runtime.start(runtime.detect(src), tmp_path)
    assert calls == [] and resolved == []


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


# Bit positions from linux/capability.h for rt.KEEP_CAPS.
_CAP_BITS = {"CHOWN": 0, "DAC_OVERRIDE": 1, "FOWNER": 3, "FSETID": 4, "KILL": 5,
             "SETGID": 6, "SETUID": 7, "NET_BIND_SERVICE": 10}


@docker
def test_a_hostile_service_runs_with_only_the_kept_capabilities(tmp_path):
    """Asks for privileged, SYS_ADMIN and host networking, and reports what it got from
    inside the container through a bind in the clone."""
    src = tmp_path / "src"
    (src / "out").mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM python:3.13-alpine\nRUN echo built > /built\n")
    (src / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    build: .\n"
        "    privileged: true\n"
        "    cap_add: [SYS_ADMIN, NET_RAW]\n"
        "    pid: host\n"
        "    command: ['sh','-c','cat /proc/self/status > /out/status; cat /built > /out/built;"
        " exec python -m http.server 8080']\n"
        "    volumes: ['./out:/out']\n"
        "    ports: ['18082:8080']\n")
    runtime = DockerRuntime(health_timeout=90, up_timeout=300)
    running = runtime.start(runtime.detect(src), tmp_path)
    try:
        status = dict(line.split(":\t", 1) for line in
                      (src / "out" / "status").read_text().splitlines() if ":\t" in line)
    finally:
        running.stop()
    want = sum(1 << _CAP_BITS[c] for c in rt.KEEP_CAPS)
    assert int(status["CapEff"], 16) == want
    assert int(status["CapBnd"], 16) == want
    assert status["NoNewPrivs"].strip() == "1"
    assert (src / "out" / "built").read_text().strip() == "built"   # offline build ran


@docker
def test_a_build_step_cannot_reach_the_network(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Dockerfile").write_text(
        "FROM python:3.13-alpine\nRUN wget -q -T 5 -O /dev/null https://example.com\n")
    (src / "compose.yml").write_text(
        "services:\n  web:\n    build: {context: ., network: host}\n    expose: ['8080']\n")
    runtime = DockerRuntime(health_timeout=30, up_timeout=300)
    with pytest.raises(rt.ProvisioningGap, match="network disabled"):
        runtime.start(runtime.detect(src), tmp_path)


def test_service_exec_targets_the_service_container_not_a_sidecar(monkeypatch):
    from quarry.dynamic.validate import RunningTarget
    runtime = DockerRuntime()
    runtime._env = {"PATH": "/usr/bin"}
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return rt.subprocess.CompletedProcess(cmd, 0, stdout="apikey123", stderr="")

    monkeypatch.setattr(rt.subprocess, "run", fake_run)
    running = RunningTarget("http://web:10001", stop=lambda: None, network="net",
                            service="web", project="quarry-run-3",
                            compose_file="/tmp/compose/compose.hardened.yml")
    rc, out = runtime.service_exec(running, ["flask", "user_get_api_key"], service="web")
    assert rc == 0 and out == "apikey123"
    c = seen["cmd"]
    assert c[:3] == ["docker", "compose", "-p"] and "quarry-run-3" in c
    assert c[c.index("exec") + 1:] == ["-T", "web", "flask", "user_get_api_key"]
    assert "run" not in c[:3] and "--network" not in c         # not a sidecar run


def test_service_exec_refuses_without_a_recorded_project(monkeypatch):
    from quarry.dynamic.validate import RunningTarget
    runtime = DockerRuntime()
    running = RunningTarget("http://web:10001", stop=lambda: None, network="net")
    with pytest.raises(rt.DockerError, match="service containers"):
        runtime.service_exec(running, ["echo", "hi"])
