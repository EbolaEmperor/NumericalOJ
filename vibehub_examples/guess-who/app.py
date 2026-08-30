"""“猜猜我是谁：黑盒数据结构”的独立 VibeHub 服务。"""

from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import SimpleHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import threading
from urllib.parse import urlsplit


APP_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = APP_ROOT / "static"
SOCKET_PATH = Path(os.environ.get("VIBEHUB_SOCKET", "/run/vibehub/app.sock"))
HEALTH_PATH = os.environ.get("VIBEHUB_HEALTH_PATH", "/healthz")

MAX_REQUEST_BYTES = 4 * 1024
MAX_ACTIVE_SESSIONS = 256
MAX_ITEMS = 128
MIN_INTEGER = -1_000_000
MAX_INTEGER = 1_000_000
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")


class GameError(RuntimeError):
    """可安全返回给作品前端的错误。"""

    def __init__(self, message, status=400, *, steps=0):
        super().__init__(str(message))
        self.status = int(status)
        self.steps = max(0, int(steps))


class UnorderedArray:
    """以连续数组保存、删除时依次左移后续元素的无序多重集合。"""

    def __init__(self):
        self._data = []

    def __len__(self):
        return len(self._data)

    def items(self):
        return list(self._data)

    def contains(self, value):
        steps = 0
        for item in self._data:
            steps += 1
            if item == value:
                return True, steps
        return False, steps

    def insert(self, value):
        self._data.append(value)
        return True, 1

    def erase(self, value):
        steps = 0
        for index, item in enumerate(self._data):
            steps += 1
            if item == value:
                for shift_index in range(index, len(self._data) - 1):
                    self._data[shift_index] = self._data[shift_index + 1]
                    steps += 1
                self._data.pop()
                return True, steps + 1
        return False, steps

    def minimum(self):
        if not self._data:
            return None, 0
        result = self._data[0]
        steps = 0
        for item in self._data:
            steps += 1
            if item < result:
                result = item
        return result, steps


class SortedArray:
    """用二分定位、移动尾部元素维持有序的连续数组多重集合。"""

    def __init__(self):
        self._data = []

    def __len__(self):
        return len(self._data)

    def items(self):
        return list(self._data)

    def _lower_bound(self, value):
        low = 0
        high = len(self._data)
        steps = 0
        while low < high:
            middle = (low + high) // 2
            steps += 1
            if self._data[middle] < value:
                low = middle + 1
            else:
                high = middle
        return low, steps

    def _locate(self, value):
        low, steps = self._lower_bound(value)
        found = False
        if low < len(self._data):
            steps += 1
            found = self._data[low] == value
        return low, found, steps

    def contains(self, value):
        _index, found, steps = self._locate(value)
        return found, steps

    def insert(self, value):
        index, steps = self._lower_bound(value)
        # Python 的 list.insert 完成了这些移动；计数显式反映实际算法工作量。
        steps += len(self._data) - index
        self._data.insert(index, value)
        return True, steps + 1

    def erase(self, value):
        index, found, steps = self._locate(value)
        if not found:
            return False, steps
        steps += len(self._data) - index - 1
        self._data.pop(index)
        return True, steps + 1

    def minimum(self):
        return (self._data[0], 1) if self._data else (None, 0)


@dataclass(slots=True)
class _ListNode:
    value: int
    next: _ListNode | None = None


class LinkedList:
    """维护 head/tail 指针、总在尾部插入的单向链表多重集合。"""

    def __init__(self):
        self._head = None
        self._tail = None
        self._size = 0

    def __len__(self):
        return self._size

    def items(self):
        result = []
        node = self._head
        while node is not None:
            result.append(node.value)
            node = node.next
        return result

    def contains(self, value):
        node = self._head
        steps = 0
        while node is not None:
            steps += 1
            if node.value == value:
                return True, steps
            node = node.next
        return False, steps

    def insert(self, value):
        node = _ListNode(value)
        if self._tail is None:
            self._head = node
        else:
            self._tail.next = node
        self._tail = node
        self._size += 1
        return True, 1

    def erase(self, value):
        previous = None
        node = self._head
        steps = 0
        while node is not None:
            steps += 1
            if node.value == value:
                if previous is None:
                    self._head = node.next
                else:
                    previous.next = node.next
                if self._tail is node:
                    self._tail = previous
                self._size -= 1
                return True, steps + 1
            previous = node
            node = node.next
        return False, steps

    def minimum(self):
        if self._head is None:
            return None, 0
        result = self._head.value
        node = self._head
        steps = 0
        while node is not None:
            steps += 1
            if node.value < result:
                result = node.value
            node = node.next
        return result, steps


class BinaryMinHeap:
    """数组实现的二叉最小堆；查找仍需线性扫描。"""

    def __init__(self):
        self._heap = []

    def __len__(self):
        return len(self._heap)

    def items(self):
        return list(self._heap)

    def contains(self, value):
        steps = 0
        for item in self._heap:
            steps += 1
            if item == value:
                return True, steps
        return False, steps

    def _sift_up(self, index):
        steps = 0
        while index > 0:
            parent = (index - 1) // 2
            steps += 1
            if self._heap[parent] <= self._heap[index]:
                break
            self._heap[parent], self._heap[index] = (
                self._heap[index],
                self._heap[parent],
            )
            steps += 1
            index = parent
        return steps

    def _sift_down(self, index):
        steps = 0
        size = len(self._heap)
        while True:
            left = index * 2 + 1
            if left >= size:
                break
            right = left + 1
            smallest = left
            steps += 1
            if right < size:
                steps += 1
                if self._heap[right] < self._heap[left]:
                    smallest = right
            steps += 1
            if self._heap[index] <= self._heap[smallest]:
                break
            self._heap[index], self._heap[smallest] = (
                self._heap[smallest],
                self._heap[index],
            )
            steps += 1
            index = smallest
        return steps

    def insert(self, value):
        self._heap.append(value)
        steps = 1
        steps += self._sift_up(len(self._heap) - 1)
        return True, steps

    def erase(self, value):
        steps = 0
        index = None
        for offset, item in enumerate(self._heap):
            steps += 1
            if item == value:
                index = offset
                break
        if index is None:
            return False, steps

        last_index = len(self._heap) - 1
        if index == last_index:
            self._heap.pop()
            return True, steps + 1

        replacement = self._heap.pop()
        self._heap[index] = replacement
        steps += 2
        if index > 0:
            parent = (index - 1) // 2
            steps += 1
            if self._heap[index] < self._heap[parent]:
                steps += self._sift_up(index)
                return True, steps
        steps += self._sift_down(index)
        return True, steps

    def minimum(self):
        return (self._heap[0], 1) if self._heap else (None, 0)


@dataclass(slots=True)
class _BSTNode:
    value: int
    left: _BSTNode | None = None
    right: _BSTNode | None = None


class BinarySearchTree:
    """不做平衡调整、相等值向右插入的普通 BST 多重集合。"""

    def __init__(self):
        self._root = None
        self._size = 0

    def __len__(self):
        return self._size

    def items(self):
        result = []
        stack = []
        node = self._root
        while stack or node is not None:
            while node is not None:
                stack.append(node)
                node = node.left
            node = stack.pop()
            result.append(node.value)
            node = node.right
        return result

    def contains(self, value):
        node = self._root
        steps = 0
        while node is not None:
            steps += 1
            if value == node.value:
                return True, steps
            node = node.left if value < node.value else node.right
        # 查找沿指针走到空位置也算一步。
        return False, steps + 1

    def insert(self, value):
        steps = 0
        if self._root is None:
            # 到达根部空位置 + 新建节点。
            self._root = _BSTNode(value)
            self._size = 1
            return True, 2
        node = self._root
        while True:
            # 访问一个已有节点。
            steps += 1
            if value < node.value:
                if node.left is None:
                    # 到达空位置 + 新建节点。
                    steps += 2
                    node.left = _BSTNode(value)
                    self._size += 1
                    return True, steps
                node = node.left
            else:
                if node.right is None:
                    # 到达空位置 + 新建节点。
                    steps += 2
                    node.right = _BSTNode(value)
                    self._size += 1
                    return True, steps
                node = node.right

    def erase(self, value):
        parent = None
        node = self._root
        steps = 0
        while node is not None:
            steps += 1
            if value == node.value:
                break
            parent = node
            node = node.left if value < node.value else node.right
        if node is None:
            # 搜索沿指针走到空位置。
            return False, steps + 1

        if node.left is not None and node.right is not None:
            successor_parent = node
            successor = node.right
            steps += 1
            while successor.left is not None:
                successor_parent = successor
                successor = successor.left
                steps += 1
            # 将后继值复制到待删除节点。
            node.value = successor.value
            steps += 1
            parent = successor_parent
            node = successor

        child = node.left if node.left is not None else node.right
        if parent is None:
            self._root = child
        elif parent.left is node:
            parent.left = child
        else:
            parent.right = child
        self._size -= 1
        # 实际摘除一个节点。
        return True, steps + 1

    def minimum(self):
        node = self._root
        steps = 0
        if node is None:
            return None, steps
        while node is not None:
            steps += 1
            if node.left is None:
                return node.value, steps
            node = node.left
        raise AssertionError("unreachable")


@dataclass(slots=True)
class _AVLNode:
    value: int
    left: _AVLNode | None = None
    right: _AVLNode | None = None
    height: int = 1


@dataclass(slots=True)
class _StepCounter:
    value: int = 0

    def add(self, amount=1):
        self.value += int(amount)


class AVLTree:
    """维护节点高度并在更新后旋转的 AVL 多重集合。"""

    def __init__(self):
        self._root = None
        self._size = 0

    def __len__(self):
        return self._size

    @staticmethod
    def _height(node):
        return node.height if node is not None else 0

    @classmethod
    def _balance(cls, node):
        return cls._height(node.left) - cls._height(node.right)

    @classmethod
    def _update_height(cls, node):
        node.height = 1 + max(cls._height(node.left), cls._height(node.right))

    @classmethod
    def _rotate_left(cls, node):
        pivot = node.right
        if pivot is None:
            raise AssertionError("left rotation without right child")
        transfer = pivot.left
        pivot.left = node
        node.right = transfer
        cls._update_height(node)
        cls._update_height(pivot)
        return pivot

    @classmethod
    def _rotate_right(cls, node):
        pivot = node.left
        if pivot is None:
            raise AssertionError("right rotation without left child")
        transfer = pivot.right
        pivot.right = node
        node.left = transfer
        cls._update_height(node)
        cls._update_height(pivot)
        return pivot

    @classmethod
    def _rebalance(cls, node, counter):
        cls._update_height(node)
        balance = cls._balance(node)
        if balance > 1:
            if cls._balance(node.left) < 0:
                node.left = cls._rotate_left(node.left)
                counter.add(2)
                return cls._rotate_right(node)
            counter.add()
            return cls._rotate_right(node)
        if balance < -1:
            if cls._balance(node.right) > 0:
                node.right = cls._rotate_right(node.right)
                counter.add(2)
                return cls._rotate_left(node)
            counter.add()
            return cls._rotate_left(node)
        return node

    @classmethod
    def _insert(cls, node, value, counter):
        if node is None:
            # 到达空位置 + 新建节点。
            counter.add(2)
            return _AVLNode(value), True
        # 访问一个已有节点。
        counter.add()
        if value < node.value:
            node.left, inserted = cls._insert(node.left, value, counter)
        else:
            node.right, inserted = cls._insert(node.right, value, counter)
        if not inserted:
            return node, False
        return cls._rebalance(node, counter), True

    @classmethod
    def _extract_min(cls, node, counter):
        """一次遍历提取子树最小节点，并在回溯时维持 AVL 性质。"""

        if node is None:
            raise AssertionError("extracting minimum from an empty subtree")
        # 访问一个已有节点。
        counter.add()
        if node.left is None:
            # 实际删除最小节点。
            counter.add()
            return node.right, node.value
        node.left, value = cls._extract_min(node.left, counter)
        return cls._rebalance(node, counter), value

    @classmethod
    def _delete(cls, node, value, counter):
        if node is None:
            # 搜索沿指针走到空位置。
            counter.add()
            return None, False
        # 访问一个已有节点。
        counter.add()
        if value < node.value:
            node.left, removed = cls._delete(node.left, value, counter)
        elif value > node.value:
            node.right, removed = cls._delete(node.right, value, counter)
        else:
            removed = True
            if node.left is None:
                # 实际删除一个节点。
                counter.add()
                return node.right, True
            if node.right is None:
                # 实际删除一个节点。
                counter.add()
                return node.left, True
            node.right, successor_value = cls._extract_min(node.right, counter)
            # 将后继值复制到待删除节点。
            node.value = successor_value
            counter.add()
        if not removed:
            return node, False
        return cls._rebalance(node, counter), True

    def items(self):
        result = []
        stack = []
        node = self._root
        while stack or node is not None:
            while node is not None:
                stack.append(node)
                node = node.left
            node = stack.pop()
            result.append(node.value)
            node = node.right
        return result

    def contains(self, value):
        node = self._root
        steps = 0
        while node is not None:
            steps += 1
            if value == node.value:
                return True, steps
            node = node.left if value < node.value else node.right
        # 查找沿指针走到空位置也算一步。
        return False, steps + 1

    def insert(self, value):
        counter = _StepCounter()
        self._root, inserted = self._insert(self._root, value, counter)
        if inserted:
            self._size += 1
        return inserted, counter.value

    def erase(self, value):
        counter = _StepCounter()
        self._root, removed = self._delete(self._root, value, counter)
        if removed:
            self._size -= 1
        return removed, counter.value

    def minimum(self):
        node = self._root
        steps = 0
        if node is None:
            return None, steps
        while node is not None:
            steps += 1
            if node.left is None:
                return node.value, steps
            node = node.left
        raise AssertionError("unreachable")


_EMPTY = object()
_DELETED = object()


class LinearProbingHash:
    """开放寻址、线性探测并用墓碑删除的整数哈希多重集合。"""

    INITIAL_CAPACITY = 8
    LOAD_NUMERATOR = 7
    LOAD_DENOMINATOR = 10
    _REQUIRED_CAPACITY = (
        MAX_ITEMS * LOAD_DENOMINATOR + LOAD_NUMERATOR - 1
    ) // LOAD_NUMERATOR
    MAX_CAPACITY = 1 << (_REQUIRED_CAPACITY - 1).bit_length()

    def __init__(self):
        self._slots = [_EMPTY] * self.INITIAL_CAPACITY
        self._size = 0
        self._used = 0

    def __len__(self):
        return self._size

    @staticmethod
    def _home(value, capacity):
        return value % capacity

    def items(self):
        return [
            slot
            for slot in self._slots
            if slot is not _EMPTY and slot is not _DELETED
        ]

    def _locate(self, value):
        capacity = len(self._slots)
        start = self._home(value, capacity)
        steps = 0
        for offset in range(capacity):
            index = (start + offset) % capacity
            slot = self._slots[index]
            steps += 1
            if slot is _EMPTY:
                return None, False, steps
            if slot is _DELETED:
                continue
            if slot == value:
                return index, True, steps
        return None, False, steps

    def _insertion_slot(self, value):
        capacity = len(self._slots)
        start = self._home(value, capacity)
        steps = 0
        for offset in range(capacity):
            index = (start + offset) % capacity
            steps += 1
            if self._slots[index] is _EMPTY or self._slots[index] is _DELETED:
                return index, steps
        return None, steps

    def _resize(self, capacity):
        if (
            capacity < self.INITIAL_CAPACITY
            or capacity > self.MAX_CAPACITY
            or capacity & (capacity - 1)
            or self._size * self.LOAD_DENOMINATOR
            > capacity * self.LOAD_NUMERATOR
        ):
            raise AssertionError("linear probing hash capacity invariant violated")
        old_slots = self._slots
        self._slots = [_EMPTY] * capacity
        self._size = 0
        self._used = 0
        steps = 0
        for slot in old_slots:
            steps += 1
            if slot is _EMPTY or slot is _DELETED:
                continue
            index = self._home(slot, capacity)
            while self._slots[index] is not _EMPTY:
                steps += 1
                index = (index + 1) % capacity
            steps += 1
            self._slots[index] = slot
            self._size += 1
            self._used += 1
        return steps

    def contains(self, value):
        _index, found, steps = self._locate(value)
        return found, steps

    def insert(self, value):
        index, steps = self._insertion_slot(value)

        capacity = len(self._slots)
        projected_size = self._size + 1
        uses_empty_slot = index is None or self._slots[index] is _EMPTY
        projected_used = self._used + (1 if uses_empty_slot else 0)
        active_pressure = (
            projected_size * self.LOAD_DENOMINATOR
            > capacity * self.LOAD_NUMERATOR
        )
        tombstone_pressure = (
            projected_used * self.LOAD_DENOMINATOR
            > capacity * self.LOAD_NUMERATOR
        )

        if active_pressure:
            if capacity >= self.MAX_CAPACITY:
                # MAX_CAPACITY 按 MAX_ITEMS 与负载阈值推导；正常游戏永远
                # 不会触达这里，断言可防未来调整常量时静默突破硬上限。
                if projected_size <= MAX_ITEMS:
                    raise AssertionError("hash capacity is too small for MAX_ITEMS")
                raise OverflowError("linear probing hash capacity limit reached")
            steps += self._resize(min(capacity * 2, self.MAX_CAPACITY))
            index, located_steps = self._insertion_slot(value)
            steps += located_steps
        elif tombstone_pressure:
            # 有效元素负载尚低，只需在相同容量中清除墓碑；绝不能因为
            # insert/erase churn 扩容。
            steps += self._resize(capacity)
            index, located_steps = self._insertion_slot(value)
            steps += located_steps
        if index is None:
            raise AssertionError("linear probing hash has no insertion slot")
        if self._slots[index] is _EMPTY:
            self._used += 1
        self._slots[index] = value
        self._size += 1
        return True, steps + 1

    def erase(self, value):
        index, found, steps = self._locate(value)
        if not found:
            return False, steps
        self._slots[index] = _DELETED
        self._size -= 1
        return True, steps + 1

    def minimum(self):
        result = None
        steps = 0
        for slot in self._slots:
            steps += 1
            if slot is _EMPTY or slot is _DELETED:
                continue
            if result is None or slot < result:
                result = slot
        return result, steps


STRUCTURE_FACTORIES = OrderedDict(
    (
        ("unordered_array", UnorderedArray),
        ("sorted_array", SortedArray),
        ("linked_list", LinkedList),
        ("binary_heap", BinaryMinHeap),
        ("bst", BinarySearchTree),
        ("avl", AVLTree),
        ("linear_probing_hash", LinearProbingHash),
    )
)

STRUCTURE_LABELS = {
    "unordered_array": "无序数组",
    "sorted_array": "有序数组",
    "linked_list": "链表",
    "binary_heap": "二叉堆",
    "bst": "普通 BST",
    "avl": "AVL",
    "linear_probing_hash": "线性探测哈希",
}


@dataclass(slots=True)
class GameSession:
    kind: str
    structure: object
    finished: bool = False
    submitted_guess: str | None = None
    guess_correct: bool | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


_sessions = OrderedDict()
_sessions_lock = threading.Lock()


def _choose_structure(candidates):
    """独立封装安全随机选择，便于契约测试注入确定性选择器。"""

    return secrets.choice(tuple(candidates))


def _fresh_session():
    # 每局都对完整候选集独立均匀采样；上一局答案不影响下一局分布。
    candidates = tuple(STRUCTURE_FACTORIES)
    kind = _choose_structure(candidates)
    return GameSession(kind=kind, structure=STRUCTURE_FACTORIES[kind]())


def _evict_one_unlocked_session():
    for session_id, session in tuple(_sessions.items()):
        if not session.lock.acquire(blocking=False):
            continue
        try:
            if _sessions.get(session_id) is session:
                del _sessions[session_id]
                return True
        finally:
            session.lock.release()
    return False


@contextmanager
def _locked_session(session_id):
    """原子取得玩家会话；活跃会话不会被 LRU 淘汰。"""

    with _sessions_lock:
        session = _sessions.get(session_id)
        if session is None:
            while len(_sessions) >= MAX_ACTIVE_SESSIONS:
                if not _evict_one_unlocked_session():
                    raise GameError("会话繁忙，请稍后重试。", 503)
            session = _fresh_session()
            _sessions[session_id] = session
        if not session.lock.acquire(blocking=False):
            raise GameError("上一个操作仍在处理中。", 409)
        _sessions.move_to_end(session_id)
    try:
        yield session
    finally:
        session.lock.release()


def _validate_integer(value):
    if type(value) is not int or not MIN_INTEGER <= value <= MAX_INTEGER:
        raise GameError(
            f"整数必须在 {MIN_INTEGER} 到 {MAX_INTEGER} 之间。",
            400,
        )
    return value


def _state_payload(session, *, success=True, steps=0, result=None, message=None):
    payload = {
        "success": bool(success),
        "items": sorted(session.structure.items()),
        "steps": max(0, int(steps)),
        "result": result,
        "finished": bool(session.finished),
    }
    if message:
        payload["message"] = str(message)
    if session.finished:
        payload["guess"] = {
            "answer": session.kind,
            "label": STRUCTURE_LABELS[session.kind],
            "correct": bool(session.guess_correct),
            "selected": session.submitted_guess,
        }
    return payload


def _blank_error_payload(error):
    return {
        "success": False,
        "items": [],
        "steps": error.steps,
        "result": None,
        "finished": False,
        "message": str(error),
    }


def _perform_action(session, payload):
    if session.finished:
        raise GameError("本局已经结束，请清空或开始新一局。", 409)
    operation = payload.get("operation", payload.get("action", payload.get("op")))
    if not isinstance(operation, str) or operation not in {
        "insert", "erase", "contains", "min",
    }:
        raise GameError("操作不存在。")
    if operation == "min":
        result, steps = session.structure.minimum()
        return _state_payload(session, steps=steps, result=result)

    value = _validate_integer(payload.get("value"))
    if operation == "insert" and len(session.structure) >= MAX_ITEMS:
        raise GameError("黑盒已经装满。", 409)
    result, steps = getattr(session.structure, operation)(value)
    return _state_payload(session, steps=steps, result=result)


def _reset_session(session):
    session.structure = STRUCTURE_FACTORIES[session.kind]()
    session.finished = False
    session.submitted_guess = None
    session.guess_correct = None
    return _state_payload(session, result=True)


def _new_game(session):
    replacement = _fresh_session()
    session.kind = replacement.kind
    session.structure = replacement.structure
    session.finished = False
    session.submitted_guess = None
    session.guess_correct = None
    return _state_payload(session, result=True)


def _submit_guess(session, payload):
    if session.finished:
        return _state_payload(
            session,
            success=False,
            result=session.guess_correct,
            message="本局已经完成。",
        ), 409
    answer = payload.get("answer")
    if not isinstance(answer, str) or answer not in STRUCTURE_FACTORIES:
        raise GameError("答案不存在。")
    session.submitted_guess = answer
    session.guess_correct = answer == session.kind
    session.finished = True
    return _state_payload(
        session,
        result=session.guess_correct,
    ), 200


class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def _send(self, body, content_type, status=200, *, include_body=True):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_json(self, payload, status=200):
        body = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        self._send(body, "application/json; charset=utf-8", status)

    def _session_id(self):
        value = str(self.headers.get("X-VibeHub-Session-Id") or "")
        if not SESSION_ID_RE.fullmatch(value):
            raise GameError("玩家会话无效。", 400)
        return value

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except (TypeError, ValueError) as exc:
            raise GameError("请求体长度无效。") from exc
        if length < 0:
            raise GameError("请求体长度无效。")
        if length > MAX_REQUEST_BYTES:
            # 不读取超限 body；关闭 HTTP/1.1 连接，避免剩余字节被误认作下一请求。
            self.close_connection = True
            raise GameError("请求体过大。", 413)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GameError("请求 JSON 无效。") from exc
        if not isinstance(payload, dict):
            raise GameError("请求 JSON 必须是对象。")
        return payload

    def _with_session(self, callback, *, session_id=None):
        try:
            if session_id is None:
                session_id = self._session_id()
            with _locked_session(session_id) as session:
                try:
                    payload, status = callback(session)
                except GameError as exc:
                    payload = _state_payload(
                        session,
                        success=False,
                        steps=exc.steps,
                        result=None,
                        message=str(exc),
                    )
                    status = exc.status
        except GameError as exc:
            payload = _blank_error_payload(exc)
            status = exc.status
        except Exception:
            error = GameError("黑盒暂时无法响应。", 500)
            payload = _blank_error_payload(error)
            status = error.status
        self._send_json(payload, status)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == HEALTH_PATH:
            self._send_json({"status": "ok"})
            return
        if path == "/api/state":
            self._with_session(
                lambda session: (_state_payload(session), 200)
            )
            return
        super().do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path
        routes = {"/api/action", "/api/reset", "/api/guess", "/api/new"}
        if path not in routes:
            # 小请求先排空 body，避免服务端抢先关闭时让客户端写入遭遇 EPIPE；
            # 超限或非法长度仍直接关闭连接，绝不为未知接口无界读取。
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except (TypeError, ValueError):
                length = -1
            if 0 <= length <= MAX_REQUEST_BYTES:
                self.rfile.read(length)
            else:
                self.close_connection = True
            self._send_json(
                {
                    "success": False,
                    "items": [],
                    "steps": 0,
                    "result": None,
                    "finished": False,
                    "message": "接口不存在。",
                },
                404,
            )
            return
        try:
            # 在解析 body 前先验证平台注入的匿名会话标识。
            session_id = self._session_id()
            payload = self._read_json()
        except GameError as exc:
            # 会话校验可能先于 body 读取失败；关闭连接可安全丢弃未读请求体。
            self.close_connection = True
            self._send_json(_blank_error_payload(exc), exc.status)
            return

        def dispatch(session):
            if path == "/api/action":
                return _perform_action(session, payload), 200
            if path == "/api/reset":
                return _reset_session(session), 200
            if path == "/api/new":
                return _new_game(session), 200
            return _submit_guess(session, payload)

        self._with_session(dispatch, session_id=session_id)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, _format, *_args):
        return


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SOCKET_PATH.unlink(missing_ok=True)
    previous_umask = os.umask(0)
    try:
        server = UnixHTTPServer(str(SOCKET_PATH), Handler)
    finally:
        os.umask(previous_umask)
    try:
        os.chmod(SOCKET_PATH, 0o600)
    except OSError:
        pass
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
