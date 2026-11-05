"""Hostile compose documents (IMPROVEMENT-PLAN P4; item 2's containment).

test_runtime_docker.py already feeds harden_compose a resolved document carrying every
escape item 2 lists, and checks the prechecks one key at a time. These add what that
left open: a raw author file put through the real `docker compose config` (so the
shapes harden_compose relies on are the ones compose actually prints, with `extends`,
YAML merge keys and short-syntax binds resolved), compose's own reading of the file
Quarry writes, external networks and network modes, bind options, and the env_file and
Dockerfile escapes that go through a symlink or an absolute path. No daemon needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic import runtime_docker as rt                     # noqa: E402
from quarry.dynamic.runtime_docker import (                         # noqa: E402
    ISOLATED_NET, DockerRuntime, harden_compose)
from test_runtime_docker import _fake_start, compose_cli            # noqa: E402

# What the author's file asks for, in the raw syntax an author writes: a merge key that
# carries the escalation into two services, `extends` into a third, host binds in short
# and long syntax, a network mode, an external network and operator-owned volumes.
HOSTILE = """
x-evil: &evil
  privileged: true
  pid: host
  ipc: host
  userns_mode: host
  cap_add: [SYS_ADMIN, NET_RAW, ALL]
  devices: ["/dev/kmsg:/dev/kmsg", "/dev/mem"]
  security_opt: ["seccomp=unconfined", "apparmor=unconfined"]
  sysctls: {net.ipv4.ip_forward: 1}
  ports: ["2375:2375"]
services:
  base:
    image: alpine
    <<: *evil
    network_mode: host
    volumes:
      - /:/host
      - /var/run/docker.sock:/var/run/docker.sock
      - ~/.ssh:/root/.ssh:ro
      - ../home:/home-outside
      - ./app:/app
      - type: bind
        source: ./app
        target: /app-shared
        bind: {propagation: rshared, create_host_path: true}
      - opvol:/data
  web:
    extends: {service: base}
    build: {context: ., network: host}
    expose: ["8080"]
  worker:
    image: alpine
    <<: *evil
    networks:
      ext: {aliases: [db], ipv4_address: 172.30.0.9}
      default: {}
    volumes_from: [base]
    volumes: [hostvol:/x]
networks:
  ext: {external: true, name: bridge}
volumes:
  opvol: {external: true, name: operator_volume}
  hostvol:
    driver: local
    driver_opts: {type: none, o: bind, device: /Users}
"""

ESCALATION = {"privileged", "pid", "ipc", "userns_mode", "devices", "sysctls", "ports",
              "network_mode", "volumes_from", "extends"}


def _assert_contained(doc: dict, src: Path) -> None:
    assert set(doc["networks"]) == {ISOLATED_NET}
    assert doc["networks"][ISOLATED_NET].get("internal") is True
    assert "external" not in str(doc.get("volumes", {}))
    assert "driver_opts" not in str(doc.get("volumes", {}))
    for name, svc in doc["services"].items():
        assert not (ESCALATION & set(svc)), (name, ESCALATION & set(svc))
        nets = svc["networks"]
        assert set(nets if isinstance(nets, list) else nets) == {ISOLATED_NET}, name
        assert svc["cap_drop"] == ["ALL"] and set(svc["cap_add"]) == set(rt.KEEP_CAPS)
        assert svc["security_opt"] == ["no-new-privileges:true"]
        for v in svc.get("volumes", []):
            assert set(v) <= {"type", "source", "target", "read_only"}, v
            if v["type"] == "bind":
                assert Path(v["source"]).resolve().is_relative_to(src.resolve()), v
            else:
                assert v["type"] in ("volume", "tmpfs"), v


@compose_cli
def test_a_raw_hostile_compose_file_is_rebuilt_contained(tmp_path):
    """The author's own file through `prepare`, which runs the real `docker compose
    config` and then harden_compose. Every escalation, host path, network and
    operator volume the file asks for is gone from what Quarry writes."""
    src, outside = tmp_path / "src", tmp_path / "home"
    (src / "app").mkdir(parents=True)
    (outside / ".ssh").mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM alpine\n")
    (src / "compose.yml").write_text(HOSTILE)

    hardened, service, port = DockerRuntime().prepare(src / "compose.yml", src,
                                                      tmp_path / "compose")
    doc = yaml.safe_load(hardened.read_text())

    assert set(doc["services"]) == {"base", "web", "worker"}
    # The published port still names the container port a probe addresses on the
    # isolated network; nothing is published on the host (no `ports` survive).
    assert (service, port) == ("web", 2375)
    _assert_contained(doc, src)
    # The only binds left are the two of ./app, and the propagation and host-path
    # options on the long-syntax one are gone with everything else not on the list.
    binds = [v for v in doc["services"]["base"]["volumes"] if v["type"] == "bind"]
    assert [(v["source"], v["target"]) for v in binds] == [
        (str(src / "app"), "/app"), (str(src / "app"), "/app-shared")]
    # extends carried base's escalation into web; the rebuild took it out again.
    assert doc["services"]["web"]["build"]["network"] == "none"
    assert {v["target"] for v in doc["services"]["web"]["volumes"]} == {
        "/app", "/app-shared", "/data"}
    # Named volumes come back empty and project-scoped: no operator_volume, no /Users.
    assert doc["volumes"] == {"opvol": {}, "hostvol": {}}
    assert "/Users" not in hardened.read_text().replace(str(tmp_path), "")


@compose_cli
def test_compose_reads_the_hardened_file_as_contained(tmp_path):
    """What runs is compose's reading of the file Quarry wrote, not the dict. Compose
    must accept it as written and must not add back a default network, a port or a
    host path when it reads it."""
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (tmp_path / "home" / ".ssh").mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM alpine\n")
    (src / "compose.yml").write_text(HOSTILE)
    runtime = DockerRuntime()
    hardened, _, _ = runtime.prepare(src / "compose.yml", src, tmp_path / "compose")

    reread = rt.resolve_compose(hardened, hardened.parent / "empty.env", runtime._env)

    _assert_contained(reread, src)
    for name, svc in reread["services"].items():
        assert not svc.get("ports"), name
        assert svc.get("mem_limit") and svc.get("pids_limit") == rt.LIMITS["pids_limit"]
    assert reread["services"]["web"]["build"]["network"] == "none"


def test_harden_replaces_external_networks_and_network_modes(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    doc = {
        "services": {
            "a": {"image": "x", "networks": {"ext": {"aliases": ["db"],
                                                     "ipv4_address": "172.30.0.9"},
                                             "default": None}},
            "b": {"image": "x", "network_mode": "service:a"},
            "c": {"image": "x", "network_mode": "container:operator_db"},
            "d": {"image": "x", "network_mode": "bridge", "networks": ["host"]},
        },
        "networks": {"ext": {"external": True, "name": "bridge"},
                     "default": {"name": "host", "driver": "host"}},
    }
    out = harden_compose(doc, src)
    assert out["networks"] == {ISOLATED_NET: {"internal": True, "driver": "bridge"}}
    for name, svc in out["services"].items():
        assert svc["networks"] == [ISOLATED_NET], name
        assert "network_mode" not in svc, name


def test_harden_keeps_only_type_source_target_and_read_only_of_a_bind(tmp_path):
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    doc = {"services": {"web": {"image": "x", "volumes": [
        {"type": "bind", "source": str(src / "app"), "target": "/app", "read_only": True,
         "bind": {"propagation": "rshared", "create_host_path": True,
                  "selinux": "z"}, "consistency": "delegated"},
        {"type": "volume", "source": "data", "target": "/data",
         "volume": {"nocopy": True, "subpath": "../../"}},
    ]}}}
    assert harden_compose(doc, src)["services"]["web"]["volumes"] == [
        {"type": "bind", "target": "/app", "read_only": True, "source": str(src / "app")},
        {"type": "volume", "target": "/data", "source": "data"},
    ]


def test_precheck_refuses_an_env_file_that_links_out_of_the_clone(tmp_path):
    """compose config inlines env_file contents, so a link in the clone to the
    operator's credentials would put them in the resolved document."""
    src, outside = tmp_path / "src", tmp_path / "home"
    src.mkdir()
    outside.mkdir()
    (outside / "credentials").write_text("AWS_SECRET_ACCESS_KEY=operator\n")
    (src / "app.env").symlink_to(outside / "credentials")
    (src / "conf").symlink_to(outside)
    for env_file in ("app.env", ["ok.env", "conf/credentials"],
                     {"path": "app.env", "required": False}):
        doc = {"services": {"web": {"image": "x", "env_file": env_file}}}
        with pytest.raises(rt.ComposeRefused, match="env_file"):
            rt.precheck_compose(doc, src, src)


@pytest.mark.parametrize("entry", [
    {"path": "../../.aws/credentials", "required": False},
    [{"path": "ok.env"}, {"path": "/etc/hosts"}],
    ["ok.env", "subdir/../../outside.env"],
])
def test_precheck_refuses_env_and_label_files_outside_in_every_syntax(tmp_path, entry):
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.env").write_text("A=1\n")
    for key in ("env_file", "label_file"):
        doc = {"services": {"web": {"image": "x", key: entry}}}
        with pytest.raises(rt.ComposeRefused, match=key):
            rt.precheck_compose(doc, src, src)


@pytest.mark.parametrize("dockerfile", ["/etc/shadow", "link/Dockerfile"])
def test_harden_refuses_a_dockerfile_outside_the_clone(tmp_path, dockerfile):
    src, outside = tmp_path / "src", tmp_path / "home"
    src.mkdir()
    outside.mkdir()
    (outside / "Dockerfile").write_text("FROM alpine\n")
    (src / "link").symlink_to(outside)
    doc = {"services": {"web": {"build": {"context": str(src), "dockerfile": dockerfile}}}}
    with pytest.raises(rt.ComposeRefused, match="dockerfile"):
        harden_compose(doc, src)


@pytest.mark.parametrize("compose, why", [
    ("services:\n  web:\n    image: x\n    extends: {file: ../../base.yml, service: b}\n",
     "extends.file"),
    ("services:\n  web:\n    image: x\n    env_file: ../../.netrc\n", "env_file"),
    ("services:\n  web:\n    image: x\n    env_file: [{path: /etc/hosts}]\n", "env_file"),
    ("services:\n  web:\n    image: x\n    label_file: ${HOME}/x\n", "label_file"),
])
def test_start_refuses_extends_and_env_file_escapes_before_any_docker_call(
        tmp_path, monkeypatch, compose, why):
    src = tmp_path / "src"
    src.mkdir()
    (src / "compose.yml").write_text(compose)
    calls = _fake_start(monkeypatch)
    resolved = []
    monkeypatch.setattr(rt, "resolve_compose", lambda *a, **kw: resolved.append(a))
    runtime = DockerRuntime()
    with pytest.raises(rt.ComposeRefused, match=why):
        runtime.start(runtime.detect(src), tmp_path)
    assert calls == [] and resolved == []
