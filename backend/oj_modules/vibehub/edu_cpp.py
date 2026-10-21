"""动态平衡术的 C++ 执行器：不可信编译与运行均复用普通判题 Docker 沙箱。

C++ 只输出返回值和堆 API 调用记录。Python 根据可信输入独立重放记录，
重建两棵堆、检查多重集与平衡条件，并重新计算中位数，不接收程序自报的成绩。
"""

from __future__ import annotations

from collections import Counter
import heapq
import os
from pathlib import Path
import tempfile

from backend.oj_modules.judging import sandbox


MAX_SOURCE_BYTES = 64 * 1024
MAX_INPUTS = 512
MAX_OPERATIONS = 32768
MAX_ROUND_OPERATIONS = 4096
MAX_INTEGER = 1_000_000_000

_API_HEADER = """#pragma once
class NumOJHeap final {
public:
    void insert(int value);
    void pop();
    int top();
};
extern NumOJHeap A;
extern NumOJHeap B;
int step(int x);
"""

# 用户代码与驱动分开编译；学生的预处理宏不能改变驱动入口或堆实现。
_HARNESS = r'''#include "heap_api.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <functional>
NumOJHeap A, B;
namespace {
struct Operation { char heap; char type; int value; };
struct Data {
    std::vector<int> left, right;
    std::vector<Operation> operations;
    unsigned total = 0;
};
Data& data() { static Data value; return value; }
bool is_left(const NumOJHeap* heap) {
    if (heap == &A) return true;
    if (heap == &B) return false;
    throw std::runtime_error("只能使用 A 和 B 两棵堆");
}
void record(bool left, char type, int value) {
    Data& d = data();
    if (++d.total > 32768 || d.operations.size() >= 4096)
        throw std::runtime_error("堆操作次数超过限制");
    d.operations.push_back({left ? 'A' : 'B', type, value});
}
void dump_operations() {
    for (const auto& op : data().operations)
        std::cout << op.heap << ' ' << op.type << ' ' << op.value << '\n';
    std::cout.flush();
}
void dump_error(int index) {
    std::cout << "ERROR " << index << ' ' << data().operations.size() << '\n';
    dump_operations();
}
}
void NumOJHeap::insert(int value) {
    const bool left = is_left(this);
    Data& d = data();
    auto& heap = left ? d.left : d.right;
    if (heap.size() >= 1024) throw std::runtime_error("堆容量超过限制");
    heap.push_back(value);
    if (left) std::push_heap(heap.begin(), heap.end());
    else std::push_heap(heap.begin(), heap.end(), std::greater<int>());
    record(left, 'I', value);
}
void NumOJHeap::pop() {
    const bool left = is_left(this);
    Data& d = data();
    auto& heap = left ? d.left : d.right;
    if (heap.empty()) throw std::runtime_error(left ? "A.pop()：不能删除空堆的堆顶" : "B.pop()：不能删除空堆的堆顶");
    const int value = heap.front();
    if (left) std::pop_heap(heap.begin(), heap.end());
    else std::pop_heap(heap.begin(), heap.end(), std::greater<int>());
    heap.pop_back();
    record(left, 'P', value);
}
int NumOJHeap::top() {
    const bool left = is_left(this);
    Data& d = data();
    auto& heap = left ? d.left : d.right;
    if (heap.empty()) throw std::runtime_error(left ? "A.top()：不能读取空堆的堆顶" : "B.top()：不能读取空堆的堆顶");
    record(left, 'T', heap.front());
    return heap.front();
}
int main() {
    int count;
    if (!(std::cin >> count) || count < 1 || count > 512) return 2;
    for (int index = 0; index < count; ++index) {
        int x;
        if (!(std::cin >> x)) return 2;
        data().operations.clear();
        try {
            const int returned = step(x);
            std::cout << "ROUND " << index << ' ' << returned << ' '
                      << data().operations.size() << '\n';
            dump_operations();
        } catch (const std::exception& e) {
            dump_error(index);
            std::cerr << e.what();
            return 3;
        } catch (...) { dump_error(index); std::cerr << "运行时发生异常"; return 3; }
    }
    return 0;
}
'''


def _failure(total, message, *, compiled=False, rounds=None):
    rounds = list(rounds or [])
    return {
        "compiled": compiled,
        "error": str(message)[:6000],
        "rounds": rounds,
        "passed": next((index for index, item in enumerate(rounds) if not item.get("passed")), len(rounds)),
        "total": total,
    }


def _integer(value):
    parsed = int(value)
    if not -2_147_483_648 <= parsed <= 2_147_483_647:
        raise ValueError("运行记录包含超出 int 范围的数值")
    return parsed


def _replay(stdout: str, inputs: list[int], *, runtime_error: str = "") -> list[dict]:
    """所有展示数据与通过状态都来自 Python 重放，不信任 C++ 自报快照。"""
    lines = iter(stdout.splitlines())
    left, right, rounds, seen = [], [], [], []
    operation_count = 0
    for index, x in enumerate(inputs):
        try:
            header = next(lines).split()
        except StopIteration as exc:
            if not runtime_error:
                raise ValueError("程序未返回完整的逐轮运行记录") from exc
            # 超时、信号退出或 exit() 不一定经过 C++ catch。保留完整前缀，
            # 在尚未得到返回值的这一轮追加失败现场。
            header = ["ERROR", str(index), "0"]
        failed = len(header) == 3 and header[0] == "ERROR" and bool(runtime_error)
        if (not failed and (len(header) != 4 or header[0] != "ROUND")) or header[1] != str(index):
            raise ValueError("程序输出与堆操作协议不一致，请勿自行输出内容")
        returned = None if failed else _integer(header[2])
        count = int(header[2] if failed else header[3])
        operation_count += count
        if not 0 <= count <= MAX_ROUND_OPERATIONS or operation_count > MAX_OPERATIONS:
            raise ValueError("堆操作次数超过限制")
        operations = []
        for _ in range(count):
            try:
                fields = next(lines).split()
            except StopIteration as exc:
                raise ValueError("堆操作记录不完整") from exc
            if len(fields) != 3 or fields[0] not in {"A", "B"} or fields[1] not in {"I", "P", "T"}:
                raise ValueError("堆操作记录格式无效")
            heap_name, kind, raw_value = fields
            value = _integer(raw_value)
            heap = left if heap_name == "A" else right
            factor = -1 if heap_name == "A" else 1
            if kind == "I":
                if len(heap) >= 1024:
                    raise ValueError("堆容量超过限制")
                heapq.heappush(heap, factor * value)
                operation_type = "insert"
            else:
                if not heap:
                    raise ValueError("不能对空堆调用 pop() 或 top()")
                actual = factor * heap[0]
                if value != actual:
                    raise ValueError("堆操作记录与实际堆顶不一致")
                if kind == "P":
                    heapq.heappop(heap)
                operation_type = "pop" if kind == "P" else "top"
            operations.append({"heap": heap_name, "type": operation_type, "value": value})
        seen.append(x)
        left_values = [-item for item in left]
        right_values = list(right)
        expected = sorted(seen)[(len(seen) - 1) // 2]
        conserved = Counter(left_values + right_values) == Counter(seen)
        balanced = len(left) in {len(right), len(right) + 1}
        ordered = not left or not right or -left[0] <= right[0]
        valid = conserved and balanced and ordered and not failed
        reasons = [runtime_error] if failed else []
        if not conserved:
            reasons.append("两堆必须恰好保存所有已经输入的数")
        if not balanced:
            reasons.append("A 的元素数应等于 B，或比 B 多一个")
        if not ordered:
            reasons.append("A 中的数应全部不大于 B 中的数")
        if not failed and returned != expected:
            reasons.append("返回的中位数不正确")
        rounds.append({
            "x": x,
            "returned": returned,
            "expected": expected,
            "left_heap": left_values,
            "right_heap": right_values,
            "operations": operations,
            "valid": valid,
            "passed": valid and returned == expected,
            "error": failed,
            "feedback": "；".join(reasons) if reasons else "两堆平衡，中位数正确",
        })
        if failed:
            break
    if any(line.strip() for line in lines):
        raise ValueError("程序输出包含多余内容，请勿自行输出内容")
    return rounds


def run_code(source: str, inputs: list[int], *, timeout_seconds: int = 5) -> dict:
    """执行 ``int step(int x)``，仅接受平台选择的输入和有界资源参数。"""
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= MAX_INPUTS:
        raise ValueError("输入序列长度应在 1 到 512 之间")
    if any(type(value) is not int or abs(value) > MAX_INTEGER for value in inputs):
        raise ValueError("输入必须为 -10^9 到 10^9 之间的整数")
    if not isinstance(source, str) or not source.strip():
        return _failure(len(inputs), "请先填写 int step(int x) 函数")
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES or "\x00" in source:
        return _failure(len(inputs), "代码超过 64 KiB 或包含无效字符")
    timeout_seconds = max(1, min(10, int(timeout_seconds)))
    with tempfile.TemporaryDirectory(prefix="numoj-edu-cpp-") as directory:
        os.chmod(directory, 0o755)
        root = Path(directory)
        for name, text in {
            "heap_api.hpp": _API_HEADER,
            "student.cpp": '#include "heap_api.hpp"\n' + source,
            "harness.cpp": _HARNESS,
        }.items():
            path = root / name
            path.write_text(text, encoding="utf-8")
            path.chmod(0o644)
        compiled = sandbox.run_case_in_container(
            ["timeout", "-k", "1s", "25s", "g++", "-std=c++20", "-O2", "-pipe",
             "-I", "/sandbox", "/sandbox/student.cpp", "/sandbox/harness.cpp", "-o", "a.out"],
            run_dir=directory,
            timeout_sec=30,
            executable_name="a.out",
            executable_max_bytes=16 * 1024 * 1024,
        )
        if compiled.returncode == -1:
            # 沙箱 -1 表示基础设施未能执行命令；不能记作学生编译错误。
            # 抛出异常由平台保留提交并重试，学生程序 exit(-1) 的状态为 255。
            raise RuntimeError("C++ 编译沙箱暂时不可用，请稍后重试")
        if compiled.returncode != 0 or "a.out" not in compiled.artifacts:
            return _failure(len(inputs), compiled.stderr or "编译失败，未生成可执行程序")
        executable = root / "a.out"
        executable.write_bytes(compiled.artifacts["a.out"])
        executable.chmod(0o755)
        result = sandbox.run_case_in_container(
            ["timeout", "-k", "1s", f"{timeout_seconds}s", "/sandbox/a.out"],
            run_dir=directory,
            input_text=str(len(inputs)) + "\n" + "\n".join(map(str, inputs)) + "\n",
            timeout_sec=timeout_seconds + 5,
        )
        if result.returncode == -1:
            raise RuntimeError("C++ 运行沙箱暂时不可用，请稍后重试")
        if result.stdout_truncated or result.stderr_truncated:
            return _failure(len(inputs), "程序输出超过限制", compiled=True)
        runtime_error = ""
        if result.returncode != 0:
            runtime_error = "运行超时" if result.returncode in {124, 137} else (result.stderr or "程序运行异常")
            runtime_error = str(runtime_error)[:6000]
        try:
            rounds = _replay(result.stdout, inputs, runtime_error=runtime_error)
        except (ValueError, OverflowError) as exc:
            return _failure(len(inputs), str(exc), compiled=True)
        if runtime_error:
            if rounds and all(item["passed"] for item in rounds):
                rounds[-1].update(passed=False, valid=False, error=True, feedback=runtime_error)
            return _failure(len(inputs), runtime_error, compiled=True, rounds=rounds)
        return {
            "compiled": True,
            "rounds": rounds,
            "passed": next((index for index, item in enumerate(rounds) if not item["passed"]), len(rounds)),
            "total": len(inputs),
        }
