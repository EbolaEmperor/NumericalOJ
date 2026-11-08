"""精确项目缓存回收：来源闭包、活跃租约、刷新竞态和开发边界。"""

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from deploy import project_build_cache as cache


def _id(name):
    return name.ljust(25, "0")


def _row(name, description, *parents, **changes):
    return {"ID": _id(name), "Description": description, "Parents": [_id(parent) for parent in parents],
            "Reclaimable": True, "Shared": False, "Mutable": False, "Type": "regular", "Size": "1024", **changes}


def _records():
    rows = [
        _row("jbase", "pulled from public.example/debian"),
        _row("jrun", "RUN texlive-full intel-oneapi-mkl-devel", "jbase"),
        _row("jleaf", "[12/12] WORKDIR /sandbox", "jrun"),
        _row("lbase", "pulled from public.example/debian"),
        _row("lrun", "RUN elan-init.sh; lake exe cache get; numoj-lean-verifier", "lbase"),
        _row("lleaf", "[12/12] WORKDIR /sandbox", "lrun"),
        _row("abase", "pulled from public.example/node"),
        _row("arun", "RUN torch torchvision; paddlepaddle paddleocr; pi-coding-agent; run_harness", "abase"),
        _row("aleaf", "[stage2 40/40] WORKDIR /workspace", "arun"),
    ]
    return {row["ID"]: row for row in rows}


@pytest.fixture
def site(tmp_path, monkeypatch):
    root = tmp_path / "site"
    (root / ".deploy").mkdir(parents=True, mode=0o700)
    disk = tmp_path / "docker"
    disk.mkdir()
    facts = {"docker_endpoint": "unix:///var/run/docker.sock", "profile": "test-cpu"}
    config = SimpleNamespace(MYSQL_HOST="127.0.0.1", MYSQL_PORT=3306, MYSQL_DB="numoj_dev_test",
                             MYSQL_USERNAME="oj", MYSQL_PASSWORD="private-password")
    monkeypatch.setattr(cache.development, "reserve_facts", lambda *_: dict(facts))
    monkeypatch.setattr(cache.container_client, "_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(cache, "_free_bytes", lambda _: 36 * 1024**3)
    references = [repository + ":deploy-current" for repository in cache.SPECS]
    images = {reference: {"Id": "engine-" + reference.split(":")[0], "RepoTags": [reference],
                          "Config": {"Labels": {cache.MANAGED_LABEL: "true", cache.SOURCE_LABEL: "existing-source-label"}}}
              for reference in references}
    state = SimpleNamespace(root=root, disk=disk, facts=facts, config=config, references=references,
                            images=images, records=_records(), calls=[], before_du=None, du_count=0)

    def run(command, **kwargs):
        state.calls.append(command)
        arguments = command[1:]
        if arguments[:2] == ["image", "inspect"]:
            output = json.dumps([state.images[arguments[2]]])
        elif arguments[0] == "info":
            output = json.dumps({"DockerRootDir": str(disk), "DriverStatus": []})
        elif arguments[:2] == ["buildx", "inspect"]:
            output = json.dumps({"Driver": "docker", "Nodes": [{"Endpoint": facts["docker_endpoint"]}]})
        elif arguments[:2] == ["buildx", "du"]:
            state.du_count += 1
            if state.before_du:
                state.before_du(state)
            output = "\n".join(json.dumps(row) for row in state.records.values())
        elif arguments[:2] == ["buildx", "prune"]:
            assert "--all" not in arguments and "--min-free-space" not in arguments
            assert {"immutable=", "private=", "type=regular"} <= set(arguments)
            selectors = [argument for argument in arguments if argument.startswith("id=")]
            assert len(selectors) == 1 and selectors[0].startswith("id=^") and selectors[0].endswith("$")
            identifiers = [selectors[0][4:-1]]
            assert len(identifiers) == 1 and cache._ID.fullmatch(identifiers[0])
            state.records.pop(identifiers[0], None)
            output = "Total: 1024B"
        else:
            raise AssertionError(f"非预期Docker命令：{command}")
        return subprocess.CompletedProcess(command, 0, output, "")

    state.run = run
    return state


def _reclaim(site):
    return cache.reclaim(site.root, "default", site.references, config=site.config, run=site.run)


def _prunes(site):
    return [command for command in site.calls if command[1:3] == ["buildx", "prune"]]


def test_reclaims_only_closed_private_project_records_leaf_first_and_audits(site):
    result = _reclaim(site)
    assert result["status"] == "completed"
    assert set(result["reclaimed_ids"]) == {_id(name) for name in ("jrun", "jleaf", "lrun", "lleaf", "arun", "aleaf")}
    assert set(site.records) == {_id(name) for name in ("jbase", "lbase", "abase")}
    for prefix in ("j", "l", "a"):
        assert result["reclaimed_ids"].index(_id(prefix + "leaf")) < result["reclaimed_ids"].index(_id(prefix + "run"))
    path = Path(result["audit_path"])
    assert path.stat().st_mode & 0o777 == 0o600
    audit = json.loads(path.read_text())
    assert audit["status"] == "completed" and len(audit["actions"]) == 6
    assert "private-password" not in path.read_text()


@pytest.mark.parametrize("condition", ["ineligible", "enough-disk", "unknown-filesystem", "remote-builder", "missing-source-label"])
def test_unknown_or_unneeded_cleanup_never_prunes_or_writes_audit(site, monkeypatch, condition):
    if condition == "ineligible":
        def reject(*_):
            raise cache.development.DevelopmentReserveError("不是受管测试库")
        monkeypatch.setattr(cache.development, "reserve_facts", reject)
    elif condition == "enough-disk":
        monkeypatch.setattr(cache, "_free_bytes", lambda _: cache.LOW_DISK_BYTES)
    elif condition == "unknown-filesystem":
        monkeypatch.setattr(cache, "_disk_root", lambda *_: (_ for _ in ()).throw(OSError("不可stat")))
    elif condition == "remote-builder":
        site.facts["docker_endpoint"] = "ssh://foreign"
        original = site.run
        def remote(command, **kwargs):
            if command[1:3] == ["buildx", "inspect"]:
                return subprocess.CompletedProcess(command, 0, json.dumps({"Driver": "docker-container", "Nodes": []}), "")
            return original(command, **kwargs)
        site.run = remote
    else:
        site.images[site.references[0]]["Config"]["Labels"].pop(cache.SOURCE_LABEL)
    assert _reclaim(site)["status"] == "skipped"
    assert not _prunes(site)
    assert not (site.root / ".deploy/build-cache").exists()


@pytest.mark.parametrize("field,value", [("Reclaimable", False), ("Shared", True), ("Mutable", True),
                                         ("Reclaimable", "true"), ("Type", "source.local")])
def test_active_shared_mutable_unknown_records_block_their_project_ancestors(field, value):
    rows = _records()
    rows[_id("jleaf")][field] = value
    selected, _ = cache.select_records(rows)
    assert not {_id("jleaf"), _id("jrun")} & set(selected)


def test_chain_outside_child_and_ambiguous_leaf_are_never_selected():
    rows = _records()
    foreign = _row("foreign", "unrelated user image", "jleaf")
    rows[foreign["ID"]] = foreign
    selected, evidence = cache.select_records(rows)
    assert _id("jleaf") not in selected and _id("foreign") not in selected
    assert evidence["blocked_children"][_id("jleaf")] == [_id("foreign")]
    rows.pop(_id("foreign"))
    duplicate = _row("duplicate", "WORKDIR /sandbox", "jrun")
    rows[duplicate["ID"]] = duplicate
    selected, evidence = cache.select_records(rows)
    assert not {_id("jrun"), _id("jleaf"), _id("duplicate")} & set(selected)
    assert len(evidence["chains"]["numericaloj-judger"]["matching_leaves"]) == 2


@pytest.mark.parametrize("damage", ["missing-parent", "cycle"])
def test_unknown_or_cyclic_ancestry_cannot_identify_a_project_chain(damage):
    rows = _records()
    rows[_id("jrun")]["Parents"] = [_id("missing") if damage == "missing-parent" else _id("jleaf")]
    selected, _ = cache.select_records(rows)
    assert not {_id("jrun"), _id("jleaf")} & set(selected)


@pytest.mark.parametrize("bound", [False, True])
def test_lean_image_source_requires_current_candidate_tag_and_engine_identity(bound):
    rows = _records()
    image = {"reference": "numericaloj-lean4:deploy-current", "image_id": "engine-current"}
    description = "pulled from numericaloj-lean4:deploy-current@" + ("engine-current" if bound else "engine-foreign")
    source = _row("leansource", description, "lleaf")
    rows[source["ID"]] = source
    selected, evidence = cache.select_records(rows, {"numericaloj-lean4": image})
    expected = {_id("lrun"), _id("lleaf"), _id("leansource")}
    assert expected <= set(selected) if bound else not expected & set(selected)
    assert evidence["bound_lean_source_ids"] == ([_id("leansource")] if bound else [])


def test_refresh_detects_new_external_child_before_any_affected_record_prune(site):
    def add_child(state):
        if state.du_count == 2:
            foreign = _row("foreign", "active foreign build", "aleaf", Reclaimable=False)
            state.records[foreign["ID"]] = foreign
    site.before_du = add_child
    result = _reclaim(site)
    assert _id("aleaf") not in result["reclaimed_ids"] and _id("arun") not in result["reclaimed_ids"]
    assert {_id("aleaf"), _id("arun"), _id("foreign")} <= set(site.records)


def test_candidate_identity_change_fails_closed_and_preserves_failed_audit(site):
    original = site.run
    inspections = 0
    def changed(command, **kwargs):
        nonlocal inspections
        if command[1:3] == ["image", "inspect"]:
            inspections += 1
            if inspections == 4:
                site.images[command[3]]["Id"] = "different-engine-id"
        return original(command, **kwargs)
    site.run = changed
    with pytest.raises(cache.CacheReclamationError, match="身份发生变化"):
        _reclaim(site)
    assert not _prunes(site)
    audit = next((site.root / ".deploy/build-cache").glob("*.json"))
    assert json.loads(audit.read_text())["status"] == "failed"


def test_no_known_reclaimable_chain_below_two_gib_stops_deployment(site, monkeypatch):
    for row in site.records.values():
        row["Reclaimable"] = False
    monkeypatch.setattr(cache, "_free_bytes", lambda _: 1024**3)
    with pytest.raises(cache.CacheReclamationError, match="不足2GiB"):
        _reclaim(site)
    assert not _prunes(site)


def test_audit_symlink_prevents_all_cache_mutations(site, tmp_path):
    (site.root / ".deploy/build-cache").symlink_to(tmp_path)
    with pytest.raises(RuntimeError, match="符号链接"):
        _reclaim(site)
    assert not _prunes(site)


def test_invalid_or_duplicate_record_ids_fail_closed(site):
    original = site.run
    def duplicated(command, **kwargs):
        if command[1:3] == ["buildx", "du"]:
            row = next(iter(site.records.values()))
            return subprocess.CompletedProcess(command, 0, json.dumps(row) + "\n" + json.dumps(row), "")
        return original(command, **kwargs)
    site.run = duplicated
    assert _reclaim(site)["status"] == "skipped"
    assert not _prunes(site)


def test_native_prune_renewed_lease_is_retained_and_not_reported_as_reclaimed(site):
    original = site.run
    def retained(command, **kwargs):
        if command[1:3] == ["buildx", "prune"]:
            site.calls.append(command)
            return subprocess.CompletedProcess(command, 0, "Total: 0B", "")
        return original(command, **kwargs)
    site.run = retained
    result = _reclaim(site)
    assert result["status"] == "skipped" and result["reclaimed_ids"] == []
    # 叶子仍存在时，其祖先不能被后续命令选中。
    assert len(_prunes(site)) == 3
    audit = json.loads(Path(result["audit_path"]).read_text())
    assert sum(action["status"] == "retained" for action in audit["actions"]) == 3


def test_prune_failure_stops_remaining_commands_and_keeps_audit(site):
    original = site.run
    def failed(command, **kwargs):
        if command[1:3] == ["buildx", "prune"]:
            site.calls.append(command)
            return subprocess.CompletedProcess(command, 1, "", "secret diagnostic never printed")
        return original(command, **kwargs)
    site.run = failed
    with pytest.raises(cache.CacheReclamationError, match="退出码 1"):
        _reclaim(site)
    assert len(_prunes(site)) == 1
    audit = next((site.root / ".deploy/build-cache").glob("*.json"))
    value = json.loads(audit.read_text())
    assert value["status"] == "failed" and len(value["actions"]) == 1
    assert "secret diagnostic" not in audit.read_text()


@pytest.mark.parametrize("same_filesystem", [False, True])
def test_containerd_capacity_requires_stat_same_filesystem_without_directory_reads(site, monkeypatch, same_filesystem):
    docker_root = SimpleNamespace(is_dir=lambda: True, stat=lambda: SimpleNamespace(st_dev=1))
    containerd = SimpleNamespace(is_dir=lambda: True, stat=lambda: SimpleNamespace(st_dev=1 if same_filesystem else 2))
    paths = []
    def checked_path(path, **_kwargs):
        paths.append(path)
        return containerd if str(path) == "/var/lib/containerd" else docker_root
    monkeypatch.setattr(cache, "assert_no_symlink_components", checked_path)
    original = site.run
    def info(command, **kwargs):
        if command[1] == "info":
            return subprocess.CompletedProcess(command, 0, json.dumps({"DockerRootDir": str(site.disk),
                "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]]}), "")
        return original(command, **kwargs)
    if same_filesystem:
        assert cache._disk_root("default", site.facts, info) is docker_root
    else:
        with pytest.raises(cache.CacheReclamationError, match="同一可确认文件系统"):
            cache._disk_root("default", site.facts, info)
    assert paths == [str(site.disk), "/var/lib/containerd"]
