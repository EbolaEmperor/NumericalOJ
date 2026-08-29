"""黑盒数据结构示例的算法、会话与 Unix Socket 契约。"""

from contextlib import contextmanager
import http.client
import importlib.util
import json
from pathlib import Path
import random
import re
import socket
import sys
import tempfile
import threading

import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "vibehub_examples" / "guess-who"
SPEC = importlib.util.spec_from_file_location(
    "vibehub_guess_who_example",
    PACKAGE / "app.py",
)
assert SPEC is not None and SPEC.loader is not None
guess_app = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guess_app
SPEC.loader.exec_module(guess_app)


EXPECTED_KINDS = (
    "unordered_array",
    "sorted_array",
    "linked_list",
    "binary_heap",
    "bst",
    "avl",
    "linear_probing_hash",
)


def test_frontend_uses_custom_viewport_safe_structure_controls():
    html = (PACKAGE / "static" / "index.html").read_text(encoding="utf-8")
    lowered = html.lower()

    assert "<select" not in lowered
    assert 'type="number"' not in lowered
    assert 'type="text"' in lowered
    assert 'role="combobox"' in lowered
    assert 'role="listbox"' in lowered
    assert 'id="integerSignButton"' in html
    assert 'aria-invalid="false"' in html
    assert 'aria-required="true"' in html

    icon_options = re.findall(
        r'<div class="answer-option"[^>]*data-value="([^"]+)"[\s\S]*?'
        r'<span class="answer-option-icon"[\s\S]*?<svg\b',
        html,
    )
    assert tuple(icon_options) == EXPECTED_KINDS

    assert "window.visualViewport" in html
    assert 'answerPopover.dataset.direction = "overlay"' in html
    assert "answerPopover.dataset.compact" in html
    assert ".answer-popover[data-compact=\"true\"]" in html
    assert ".number-piece::before" in html
    assert "@keyframes piece-appear" in html
    assert 'id="operationHistory"' in html
    assert 'role="log"' in html
    assert "operationHistory.parentElement.scrollTop" in html


@pytest.fixture(autouse=True)
def _clear_sessions():
    with guess_app._sessions_lock:
        guess_app._sessions.clear()
    yield
    with guess_app._sessions_lock:
        guess_app._sessions.clear()


@pytest.mark.parametrize(
    "kind,factory",
    tuple(guess_app.STRUCTURE_FACTORIES.items()),
)
def test_all_structures_match_set_semantics_over_deterministic_trace(kind, factory):
    structure = factory()
    reference = set()
    randomizer = random.Random(20260830)

    for _index in range(800):
        operation = randomizer.choice(("insert", "erase", "contains", "minimum"))
        value = randomizer.randint(-40, 40)
        if operation == "insert":
            expected = value not in reference
            result, steps = structure.insert(value)
            reference.add(value)
        elif operation == "erase":
            expected = value in reference
            result, steps = structure.erase(value)
            reference.discard(value)
        elif operation == "contains":
            expected = value in reference
            result, steps = structure.contains(value)
        else:
            expected = min(reference) if reference else None
            result, steps = structure.minimum()

        assert result == expected, kind
        assert type(steps) is int and steps >= 0, kind
        assert sorted(structure.items()) == sorted(reference), kind
        assert len(structure) == len(reference), kind


def _assert_bst(node, low=None, high=None):
    if node is None:
        return 0
    if low is not None:
        assert node.value > low
    if high is not None:
        assert node.value < high
    left_height = _assert_bst(node.left, low, node.value)
    right_height = _assert_bst(node.right, node.value, high)
    return 1 + max(left_height, right_height)


def _assert_avl(node, low=None, high=None):
    if node is None:
        return 0
    if low is not None:
        assert node.value > low
    if high is not None:
        assert node.value < high
    left_height = _assert_avl(node.left, low, node.value)
    right_height = _assert_avl(node.right, node.value, high)
    assert abs(left_height - right_height) <= 1
    assert node.height == 1 + max(left_height, right_height)
    return node.height


def test_each_structure_preserves_its_own_representation_invariants():
    values = (32, 8, 56, 4, 16, 40, 72, 2, 6, 12, 24, 36, 48, 64, 80)

    unordered = guess_app.UnorderedArray()
    linked = guess_app.LinkedList()
    sorted_array = guess_app.SortedArray()
    heap = guess_app.BinaryMinHeap()
    bst = guess_app.BinarySearchTree()
    avl = guess_app.AVLTree()
    table = guess_app.LinearProbingHash()
    structures = (unordered, linked, sorted_array, heap, bst, avl, table)
    for structure in structures:
        for value in values:
            assert structure.insert(value)[0] is True
        for value in (8, 56, 2, 72):
            assert structure.erase(value)[0] is True

    assert len(set(unordered._data)) == len(unordered._data)
    assert sorted_array._data == sorted(sorted_array._data)

    linked_values = []
    seen_nodes = set()
    node = linked._head
    while node is not None:
        assert id(node) not in seen_nodes
        seen_nodes.add(id(node))
        linked_values.append(node.value)
        node = node.next
    assert len(linked_values) == linked._size

    for index, value in enumerate(heap._heap):
        left = index * 2 + 1
        right = left + 1
        if left < len(heap._heap):
            assert value <= heap._heap[left]
        if right < len(heap._heap):
            assert value <= heap._heap[right]

    _assert_bst(bst._root)
    _assert_avl(avl._root)

    active_hash_slots = [
        slot
        for slot in table._slots
        if slot is not guess_app._EMPTY and slot is not guess_app._DELETED
    ]
    assert len(active_hash_slots) == table._size
    assert len(set(active_hash_slots)) == table._size
    for value in active_hash_slots:
        assert table.contains(value)[0] is True


def _run_hash_tombstone_churn():
    table = guess_app.LinearProbingHash()
    reference = set()
    steps = []

    # 先达到游戏允许的最大元素数，迫使表扩到与 MAX_ITEMS 匹配的上限。
    for value in range(guess_app.MAX_ITEMS):
        inserted, operation_steps = table.insert(value)
        assert inserted is True
        reference.add(value)
        steps.append(operation_steps)
    assert table.items() == list(range(guess_app.MAX_ITEMS))
    assert len(table._slots) == table.MAX_CAPACITY

    # 删除全部元素留下大量墓碑，再用不同 home slot 高频 churn。旧实现会
    # 在这里持续 2 倍扩容；修复后只能同容量清墓碑。
    for value in range(guess_app.MAX_ITEMS):
        removed, operation_steps = table.erase(value)
        assert removed is True
        reference.remove(value)
        steps.append(operation_steps)
    for offset in range(4_000):
        value = 10_000 + offset
        inserted, insert_steps = table.insert(value)
        assert inserted is True
        reference.add(value)
        removed, erase_steps = table.erase(value)
        assert removed is True
        reference.remove(value)
        steps.extend((insert_steps, erase_steps))
        assert len(table._slots) <= table.MAX_CAPACITY
        assert table._size == len(reference)
        assert table._size <= table._used <= len(table._slots)

    minimum, minimum_steps = table.minimum()
    assert minimum is None
    assert reference == set()
    assert table.items() == []
    assert minimum_steps == len(table._slots)
    return (
        len(table._slots),
        table._used,
        tuple(steps),
        minimum_steps,
    )


def test_linear_probing_hash_tombstone_churn_is_bounded_and_deterministic():
    first = _run_hash_tombstone_churn()
    second = _run_hash_tombstone_churn()

    assert first == second
    capacity, _used, operation_steps, minimum_steps = first
    assert capacity == guess_app.LinearProbingHash.MAX_CAPACITY == 256
    assert minimum_steps == capacity
    assert max(operation_steps) <= capacity * 3


def _step_fingerprint(factory):
    structure = factory()
    operations = [
        *(("insert", value) for value in (0, 8, 16, 24, 32, 40, 48, 3, 2, 1)),
        ("contains", 0),
        ("contains", 48),
        ("contains", 17),
        ("minimum", None),
        ("erase", 16),
        ("erase", 3),
        ("contains", 32),
        ("minimum", None),
    ]
    fingerprint = []
    for operation, value in operations:
        if value is None:
            _result, steps = getattr(structure, operation)()
        else:
            _result, steps = getattr(structure, operation)(value)
        fingerprint.append(steps)
    return tuple(fingerprint)


def test_step_counts_are_deterministic_and_make_all_seven_structures_distinguishable():
    first = {
        kind: _step_fingerprint(factory)
        for kind, factory in guess_app.STRUCTURE_FACTORIES.items()
    }
    second = {
        kind: _step_fingerprint(factory)
        for kind, factory in guess_app.STRUCTURE_FACTORIES.items()
    }

    assert first == second
    assert len(set(first.values())) == len(EXPECTED_KINDS)
    assert first["binary_heap"][-1] == 1
    assert first["sorted_array"][-1] == 1
    assert first["linear_probing_hash"][-1] == 16
    assert first["bst"] != first["avl"]


def test_every_game_samples_independently_from_all_seven_kinds(
    monkeypatch,
):
    candidate_sets = []

    def choose(candidates):
        candidates = tuple(candidates)
        candidate_sets.append(candidates)
        return candidates[-1]

    monkeypatch.setattr(guess_app, "_choose_structure", choose)
    initial = guess_app._fresh_session()
    replacement = guess_app._fresh_session()

    assert candidate_sets[0] == EXPECTED_KINDS
    assert candidate_sets[1] == EXPECTED_KINDS
    assert initial.kind == replacement.kind == EXPECTED_KINDS[-1]


def test_session_store_is_bounded_and_does_not_evict_a_locked_session(monkeypatch):
    monkeypatch.setattr(guess_app, "MAX_ACTIVE_SESSIONS", 2)
    monkeypatch.setattr(guess_app, "_choose_structure", lambda candidates: candidates[0])
    first = "a" * 24
    second = "b" * 24
    third = "c" * 24

    with guess_app._locked_session(first):
        with guess_app._locked_session(second):
            with pytest.raises(guess_app.GameError) as caught:
                with guess_app._locked_session(third):
                    pass
            assert caught.value.status == 503

    with guess_app._locked_session(third):
        pass
    assert len(guess_app._sessions) == 2
    assert third in guess_app._sessions

    with guess_app._locked_session(third):
        with pytest.raises(guess_app.GameError) as caught:
            with guess_app._locked_session(third):
                pass
        assert caught.value.status == 409


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__("vibehub.internal", timeout=3)
        self.socket_path = str(socket_path)

    def connect(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self.socket_path)
        self.sock = connection


@contextmanager
def _running_server(socket_path):
    try:
        server = guess_app.UnixHTTPServer(str(socket_path), guess_app.Handler)
    except PermissionError:
        pytest.skip("当前沙箱不允许创建 Unix socket")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(socket_path, method, path, payload=None, *, session_id=None, raw=None):
    if raw is not None:
        body = raw
    elif payload is None:
        body = None
    else:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if session_id is not None:
        headers["X-VibeHub-Session-Id"] = session_id
    connection = _UnixHTTPConnection(socket_path)
    try:
        try:
            connection.request(method, path, body=body, headers=headers)
        except BrokenPipeError:
            # 服务端可仅凭 Content-Length 提前拒绝超限请求并关闭写方向；
            # 响应此时已经在 socket 中，仍应读取并断言其状态。
            pass
        response = connection.getresponse()
        data = response.read()
        return response.status, json.loads(data.decode("utf-8"))
    finally:
        connection.close()


@pytest.fixture
def running_api(monkeypatch):
    selections = iter((
        "unordered_array",
        "sorted_array",
        "bst",
        "avl",
        "linear_probing_hash",
    ))

    def choose(candidates):
        candidates = tuple(candidates)
        for desired in selections:
            if desired in candidates:
                return desired
        return candidates[0]

    monkeypatch.setattr(guess_app, "_choose_structure", choose)
    with tempfile.TemporaryDirectory(prefix="vhgw-", dir="/tmp") as temp_dir:
        socket_path = Path(temp_dir) / "app.sock"
        with _running_server(socket_path):
            yield socket_path


def test_unix_socket_api_keeps_sessions_isolated_and_hides_answer_until_guess(
    running_api,
):
    player_a = "A" * 24
    player_b = "B" * 24
    required = {"success", "items", "steps", "result", "finished"}

    status, state_a = _request(
        running_api, "GET", "/api/state", session_id=player_a,
    )
    assert status == 200
    assert required <= state_a.keys()
    assert state_a["items"] == []
    assert state_a["finished"] is False
    assert "guess" not in state_a
    assert "unordered_array" not in json.dumps(state_a, ensure_ascii=False)

    for value in (9, -2, 5):
        status, inserted = _request(
            running_api,
            "POST",
            "/api/action",
            {"operation": "insert", "value": value},
            session_id=player_a,
        )
        assert status == 200
        assert inserted["result"] is True
    assert inserted["items"] == [-2, 5, 9]

    status, state_b = _request(
        running_api, "GET", "/api/state", session_id=player_b,
    )
    assert status == 200
    assert state_b["items"] == []

    status, contained = _request(
        running_api,
        "POST",
        "/api/action",
        {"operation": "contains", "value": -2},
        session_id=player_a,
    )
    assert status == 200
    assert contained["result"] is True
    assert contained["items"] == [-2, 5, 9]

    original_kind = guess_app._sessions[player_a].kind
    status, reset = _request(
        running_api, "POST", "/api/reset", {}, session_id=player_a,
    )
    assert status == 200
    assert reset["items"] == [] and reset["finished"] is False
    assert guess_app._sessions[player_a].kind == original_kind

    status, new_game = _request(
        running_api, "POST", "/api/new", {}, session_id=player_a,
    )
    assert status == 200
    assert new_game["items"] == [] and "guess" not in new_game
    new_kind = guess_app._sessions[player_a].kind
    assert new_kind in EXPECTED_KINDS

    status, guessed = _request(
        running_api,
        "POST",
        "/api/guess",
        {"answer": "avl"},
        session_id=player_a,
    )
    assert status == 200
    assert guessed["finished"] is True
    assert guessed["result"] is (new_kind == "avl")
    assert guessed["guess"] == {
        "answer": new_kind,
        "label": guess_app.STRUCTURE_LABELS[new_kind],
        "correct": new_kind == "avl",
        "selected": "avl",
    }

    status, after_finish = _request(
        running_api,
        "POST",
        "/api/action",
        {"operation": "min"},
        session_id=player_a,
    )
    assert status == 409
    assert after_finish["finished"] is True
    assert after_finish["guess"]["answer"] == new_kind


@pytest.mark.parametrize(
    "payload",
    (
        {"operation": "insert", "value": True},
        {"operation": "erase", "value": 1.5},
        {"operation": "contains", "value": "1"},
        {"operation": "insert", "value": guess_app.MIN_INTEGER - 1},
        {"operation": "insert", "value": guess_app.MAX_INTEGER + 1},
        {"operation": "unknown", "value": 1},
        {"operation": [], "value": 1},
    ),
)
def test_action_api_rejects_invalid_operations_and_integers(running_api, payload):
    status, response = _request(
        running_api,
        "POST",
        "/api/action",
        payload,
        session_id="V" * 24,
    )
    assert status == 400
    assert response["success"] is False
    assert response["items"] == []
    assert response["finished"] is False


def test_api_validates_session_json_size_routes_and_health(running_api):
    status, health = _request(running_api, "GET", "/healthz")
    assert (status, health) == (200, {"status": "ok"})

    status, missing_session = _request(running_api, "GET", "/api/state")
    assert status == 400
    assert missing_session["success"] is False

    status, bad_session = _request(
        running_api, "GET", "/api/state", session_id="short",
    )
    assert status == 400
    assert bad_session["success"] is False

    status, malformed = _request(
        running_api,
        "POST",
        "/api/action",
        session_id="J" * 24,
        raw=b"{",
    )
    assert status == 400
    assert malformed["success"] is False

    status, oversized = _request(
        running_api,
        "POST",
        "/api/action",
        session_id="L" * 24,
        raw=b"x" * (guess_app.MAX_REQUEST_BYTES + 1),
    )
    assert status == 413
    assert oversized["success"] is False

    status, missing_route = _request(
        running_api,
        "POST",
        "/api/not-found",
        {},
        session_id="R" * 24,
    )
    assert status == 404
    assert missing_route["success"] is False


def test_minimum_and_capacity_limit_have_bounded_normal_responses(monkeypatch):
    monkeypatch.setattr(guess_app, "MAX_ITEMS", 2)
    session = guess_app.GameSession(
        kind="sorted_array",
        structure=guess_app.SortedArray(),
    )
    empty = guess_app._perform_action(session, {"operation": "min"})
    assert empty["result"] is None and empty["steps"] == 0

    assert guess_app._perform_action(
        session, {"operation": "insert", "value": 2},
    )["result"] is True
    assert guess_app._perform_action(
        session, {"operation": "insert", "value": 1},
    )["result"] is True
    duplicate = guess_app._perform_action(
        session, {"operation": "insert", "value": 1},
    )
    assert duplicate["result"] is False
    with pytest.raises(guess_app.GameError) as caught:
        guess_app._perform_action(
            session, {"operation": "insert", "value": 3},
        )
    assert caught.value.status == 409
    assert caught.value.steps > 0
