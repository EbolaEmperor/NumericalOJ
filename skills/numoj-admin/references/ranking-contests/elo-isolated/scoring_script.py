#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""镜像迷踪 ELO 评分脚本 · 隔离运行时版（elo_runtime_mode = isolated）。

运行环境：
    本脚本在裁判容器内运行（保持联网，但看不到任何作品文件）；两份作品的
    被测进程各自在独立的断网工作容器中，由可信运行器看管。脚本通过同目录的
    ``elo_host_api`` 模块，经宿主仲裁者用通用原语（``spawn``/``interact``）
    启动并驱动双方 bot。

计时约定：
    每回合 1 秒的思考时限由工作容器内部强制执行（单调时钟只覆盖 bot 本身），
    宿主↔容器的通信开销不占用该预算；``interact`` 返回的 ``elapsed_ms`` 即
    容器内测得的真实思考耗时，直接用于对战详情。

参赛者契约（见 description.md）：作品根目录 ``bot.py``、``{"ready": true}``
握手、换行 JSON 回合。本脚本用原语显式实现这一约定。

对局规则、记录结构与详情页回放模板与单容器运行时的脚本保持一致。
"""

import json
import random
import secrets
import time

import elo_host_api


MIN_N = 7
MAX_N = 20
OBSTACLE_RATIO = 0.10
TURN_TIMEOUT_MS = 1000

MOVES = {
    "U": (-1, 0),
    "D": (1, 0),
    "L": (0, -1),
    "R": (0, 1),
}

ERROR_TEXTS = {
    "timeout": "单轮思考超时（>1.000 秒）",
    "oversize": "协议输出超过 16 KiB",
    "bad_output": "决策输出不是合法 JSON 对象",
    "bot_exited": "Bot 进程提前退出",
    "bot_not_running": "Bot 未在运行",
    "worker_unavailable": "评测工作容器不可用",
    "worker_unresponsive": "评测工作容器无响应",
    "bad_payload": "局面下发失败",
}


class BotFault(RuntimeError):
    pass


def _fault_text(reply):
    error = str(reply.get("error") or "")
    text = ERROR_TEXTS.get(error, error or "未知错误")
    message = reply.get("message")
    if message:
        text = f"{text}：{message}"
    exit_code = reply.get("exit_code")
    if error == "bot_exited" and exit_code is not None:
        text = f"Bot 进程提前退出（退出码 {exit_code}）"
    return text


class RemoteBot:
    """经仲裁者调用工作容器中 bot 的薄封装（通用原语版）。"""

    def __init__(self, side):
        self.side = side
        self.handshake_ms = None
        self._ready = False

    def wait_ready(self):
        check = elo_host_api.fetch_files(self.side, ["bot.py"], timeout_ms=12000)
        if not check.get("ok"):
            raise BotFault(check.get("message") or check.get("error") or "工作容器不可用")
        if "bot.py" not in (check.get("files") or {}):
            raise BotFault("作品包根目录缺少 bot.py")
        started = time.monotonic()
        spawned = elo_host_api.spawn(
            self.side, ["python3", "-u", "bot.py"], timeout_ms=12000)
        if not spawned.get("ok"):
            raise BotFault(spawned.get("message") or "无法启动 bot 进程")
        reply = elo_host_api.interact(self.side, data=None, timeout_ms=12000,
                                      until="newline")
        if not reply.get("ok"):
            if reply.get("error") == "timeout":
                raise BotFault("启动握手超时（>12 秒）")
            raise BotFault(_fault_text(reply))
        try:
            payload = json.loads((reply.get("output") or "").strip())
        except ValueError:
            payload = None
        if not isinstance(payload, dict) or payload.get("ready") is not True:
            elo_host_api.kill(self.side)
            raise BotFault('启动握手必须是 {"ready": true}')
        self.handshake_ms = round((time.monotonic() - started) * 1000, 3)
        self._ready = True
        return self.handshake_ms

    def ask(self, state):
        if not self._ready:
            self.wait_ready()
        line = json.dumps(state, ensure_ascii=False, separators=(",", ":")) + "\n"
        reply = elo_host_api.interact(
            self.side, data=line, timeout_ms=TURN_TIMEOUT_MS, until="newline")
        if not reply.get("ok"):
            raise BotFault(_fault_text(reply))
        try:
            response = json.loads((reply.get("output") or "").strip())
        except ValueError:
            response = None
        if not isinstance(response, dict):
            elo_host_api.kill(self.side)
            self._ready = False
            raise BotFault("决策输出不是合法 JSON 对象")
        move = response.get("move")
        if not isinstance(move, str) or move not in MOVES:
            raise BotFault("move 必须是 U、D、L、R 之一")
        legal = {item["move"] for item in state["legal_moves"]}
        if move not in legal:
            raise BotFault(f"非法移动：{move}")
        return move, reply.get("elapsed_ms")


def _inside(n, row, col):
    return 0 <= row < n and 0 <= col < n


def _neighbors(n, cell):
    row, col = cell
    for move, (dr, dc) in MOVES.items():
        nr, nc = row + dr, col + dc
        if _inside(n, nr, nc):
            yield move, (nr, nc)


def _generate_board(seed):
    rng = random.Random(seed)
    n = rng.randint(MIN_N, MAX_N)
    start_a = (n - 1, 0)
    start_b = (0, n - 1)
    protected = {start_a, start_b}
    protected.update(cell for _, cell in _neighbors(n, start_a))
    protected.update(cell for _, cell in _neighbors(n, start_b))

    seen = set()
    orbits = []
    for row in range(n):
        for col in range(n):
            cell = (row, col)
            if cell in seen or cell in protected:
                continue
            mirror = (n - 1 - row, n - 1 - col)
            seen.add(cell)
            seen.add(mirror)
            if mirror in protected:
                continue
            orbit = tuple(sorted({cell, mirror}))
            orbits.append(orbit)
    rng.shuffle(orbits)

    target = round(n * n * OBSTACLE_RATIO)
    obstacles = set()
    for orbit in orbits:
        if len(obstacles) >= target:
            break
        obstacles.update(orbit)

    grid = [["." for _ in range(n)] for _ in range(n)]
    for row, col in obstacles:
        grid[row][col] = "#"
    return n, grid, start_a, start_b, sorted(obstacles)


def _legal_moves(grid, position, opponent):
    n = len(grid)
    result = []
    for move, cell in _neighbors(n, position):
        row, col = cell
        if cell != opponent and grid[row][col] == ".":
            result.append({"move": move, "to": [row, col]})
    return result


def _board_rows(grid, position_a, position_b):
    board = [row[:] for row in grid]
    if position_a == position_b:
        row, col = position_a
        board[row][col] = "X"
    else:
        board[position_a[0]][position_a[1]] = "A"
        board[position_b[0]][position_b[1]] = "B"
    return ["".join(row) for row in board]


def _turn_state(side, round_index, grid, own, opponent, legal):
    return {
        "type": "turn",
        "version": 1,
        "side": side,
        "round": round_index,
        "n": len(grid),
        "board": _board_rows(grid, own, opponent) if side == "A" else _board_rows(grid, opponent, own),
        "you": list(own),
        "opponent": list(opponent),
        "legal_moves": legal,
    }


def _fault_winner(fault_a, fault_b):
    if fault_a and fault_b:
        return 0
    if fault_a:
        return 2
    return 1


def play_match():
    seed = secrets.randbits(64)
    n, grid, position_a, position_b, obstacles = _generate_board(seed)
    start_a = position_a
    start_b = position_b
    turns = []
    runners = {}
    startup = {"a_ms": None, "b_ms": None}
    startup_faults = {}

    for side in ("A", "B"):
        try:
            runner = RemoteBot(side)
            runners[side] = runner
            startup[f"{side.lower()}_ms"] = runner.wait_ready()
        except Exception as exc:
            startup_faults[side] = str(exc)

    try:
        if startup_faults:
            fault_a = startup_faults.get("A")
            fault_b = startup_faults.get("B")
            winner = _fault_winner(fault_a, fault_b)
            reason = (
                f"启动失败：A={fault_a or '正常'}；B={fault_b or '正常'}"
            )
            turns.append({
                "round": 0,
                "event": "fault",
                "message": reason,
                "a_move": None,
                "b_move": None,
                "a_ms": startup["a_ms"],
                "b_ms": startup["b_ms"],
            })
            return _match_record(
                winner, reason, seed, n, obstacles, start_a, start_b,
                turns, startup,
            )

        round_index = 0
        while round_index <= n * n:
            legal_a = _legal_moves(grid, position_a, position_b)
            legal_b = _legal_moves(grid, position_b, position_a)
            if not legal_a or not legal_b:
                if not legal_a and not legal_b:
                    winner = 0
                    reason = f"第 {round_index + 1} 轮开始时双方都无路可走，平局"
                elif not legal_a:
                    winner = 2
                    reason = f"第 {round_index + 1} 轮开始时 A 无合法移动，B 获胜"
                else:
                    winner = 1
                    reason = f"第 {round_index + 1} 轮开始时 B 无合法移动，A 获胜"
                turns.append({
                    "round": round_index,
                    "event": "blocked",
                    "message": reason,
                    "a_move": None,
                    "b_move": None,
                    "a_ms": None,
                    "b_ms": None,
                })
                return _match_record(
                    winner, reason, seed, n, obstacles, start_a, start_b,
                    turns, startup,
                )

            move_a = move_b = None
            elapsed_a = elapsed_b = None
            fault_a = fault_b = None
            try:
                move_a, elapsed_a = runners["A"].ask(
                    _turn_state("A", round_index, grid, position_a, position_b, legal_a),
                )
            except Exception as exc:
                fault_a = str(exc)
            try:
                move_b, elapsed_b = runners["B"].ask(
                    _turn_state("B", round_index, grid, position_b, position_a, legal_b),
                )
            except Exception as exc:
                fault_b = str(exc)

            if fault_a or fault_b:
                winner = _fault_winner(fault_a, fault_b)
                reason = (
                    f"第 {round_index + 1} 轮决策失败："
                    f"A={fault_a or '正常'}；B={fault_b or '正常'}"
                )
                turns.append({
                    "round": round_index,
                    "event": "fault",
                    "message": reason,
                    "a_move": move_a,
                    "b_move": move_b,
                    "a_ms": elapsed_a,
                    "b_ms": elapsed_b,
                })
                return _match_record(
                    winner, reason, seed, n, obstacles, start_a, start_b,
                    turns, startup,
                )

            target_a = next(tuple(item["to"]) for item in legal_a if item["move"] == move_a)
            target_b = next(tuple(item["to"]) for item in legal_b if item["move"] == move_b)
            old_a = position_a
            old_b = position_b
            grid[old_a[0]][old_a[1]] = "#"
            grid[old_b[0]][old_b[1]] = "#"

            if target_a == target_b:
                position_a = target_a
                position_b = target_b
                reason = f"第 {round_index + 1} 轮双方同时进入 {list(target_a)}，碰撞平局"
                turns.append({
                    "round": round_index,
                    "event": "collision",
                    "message": reason,
                    "a_from": list(old_a),
                    "b_from": list(old_b),
                    "a_to": list(target_a),
                    "b_to": list(target_b),
                    "a_move": move_a,
                    "b_move": move_b,
                    "a_ms": elapsed_a,
                    "b_ms": elapsed_b,
                })
                return _match_record(
                    0, reason, seed, n, obstacles, start_a, start_b,
                    turns, startup,
                )

            position_a = target_a
            position_b = target_b
            turns.append({
                "round": round_index,
                "event": "move",
                "message": f"第 {round_index + 1} 轮：A {move_a} · B {move_b}",
                "a_from": list(old_a),
                "b_from": list(old_b),
                "a_to": list(target_a),
                "b_to": list(target_b),
                "a_move": move_a,
                "b_move": move_b,
                "a_ms": elapsed_a,
                "b_ms": elapsed_b,
            })
            round_index += 1

        reason = "达到理论回合上限，按平局处理"
        return _match_record(
            0, reason, seed, n, obstacles, start_a, start_b, turns, startup,
        )
    finally:
        # bot 进程由工作容器内的可信运行器负责清理，这里无需额外操作。
        pass


def _match_record(winner, reason, seed, n, obstacles, start_a, start_b, turns, startup):
    return {
        "winner": winner,
        "reason": reason,
        "seed": str(seed),
        "n": n,
        "obstacle_count": len(obstacles),
        "obstacles": [list(cell) for cell in obstacles],
        "start_a": list(start_a),
        "start_b": list(start_b),
        "turns": turns,
        "startup": startup,
    }


HTML_TEMPLATE = r"""
<style>
  :root {
    color-scheme: light;
    --page: #f4f6f8;
    --panel: #ffffff;
    --line: #d7dce2;
    --ink: #28313b;
    --muted: #6b7280;
    --white-cell: #ffffff;
    --obstacle: #303740;
    --trail: #c9ced5;
    --a: #2b78d0;
    --b: #df7041;
    --draw: #d39c27;
  }
  * { box-sizing: border-box; }
  html, body { width: 100%; height: 100%; }
  body {
    margin: 0;
    padding: 0;
    background: var(--page);
    color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif;
    overflow: hidden;
  }
  .replay {
    --control-height: 44px;
    --layout-gap: 8px;
    --board-size: min(100vw, calc(100vh - var(--control-height) - var(--layout-gap)));
    width: 100vw; height: 100vh; margin: 0;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: var(--layout-gap); overflow: hidden;
  }
  @supports (height: 100dvh) {
    .replay {
      --board-size: min(100vw, calc(100dvh - var(--control-height) - var(--layout-gap)));
      height: 100dvh;
    }
  }
  .board-wrap {
    width: var(--board-size); height: var(--board-size); flex: 0 0 var(--board-size);
    min-width: 0; min-height: 0;
    display: grid; place-items: center;
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 0;
  }
  .board {
    display: grid; width: 100%; height: 100%; gap: 1px; padding: 1px;
    background: #aeb5be; border: 1px solid #aeb5be; overflow: hidden;
  }
  .cell { position: relative; min-width: 0; background: var(--white-cell); }
  .cell.obstacle { background: var(--obstacle); }
  .cell.trail { background: var(--trail); }
  .cell.a::after,.cell.b::after,.cell.collision::after {
    position: absolute; inset: 14%; display: grid; place-items: center; border-radius: 50%;
    color: #fff; font: 700 clamp(8px, 2vw, 18px) ui-monospace, monospace;
  }
  .cell.a::after { content: "A"; background: var(--a); }
  .cell.b::after { content: "B"; background: var(--b); }
  .cell.collision::after { content: "×"; background: var(--draw); }
  .controls {
    width: var(--board-size); height: var(--control-height); flex: 0 0 var(--control-height);
    padding: 5px 6px; border: 1px solid var(--line); border-radius: 10px; background: var(--panel);
  }
  .control-row {
    display: grid; height: 100%; grid-template-columns: 34px minmax(0, 1fr) repeat(3, 34px);
    align-items: center; gap: 6px;
  }
  button {
    appearance: none; border: 1px solid #c5cbd3; color: var(--ink); background: #fff;
    width: 100%; height: 32px; padding: 0; border-radius: 7px;
    cursor: pointer; font: 600 12px inherit;
  }
  button:hover { border-color: #87909b; background: #f6f7f9; }
  button:disabled { opacity: .4; cursor: not-allowed; }
  button.primary { color: #fff; background: var(--a); border-color: var(--a); }
  .control-icon { display: block; width: 15px; height: 15px; margin: auto; fill: currentColor; }
  .play-icon--pause { display: none; }
  #playToggle.is-playing .play-icon--play { display: none; }
  #playToggle.is-playing .play-icon--pause { display: block; }
  input[type="range"] {
    width: 100%; min-width: 0; margin: 0; accent-color: var(--a); cursor: pointer;
  }
</style>

<main class="replay">
  <section class="board-wrap">
    <div class="board" id="board" aria-label="对战棋盘"></div>
  </section>
    <section class="controls" aria-label="动画控制器">
      <div class="control-row">
        <button type="button" id="prev" title="上一帧" aria-label="上一帧">
          <svg class="control-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M5 5h2v14H5zM19 5.5v13L8.5 12z"></path>
          </svg>
        </button>
        <input id="progress" type="range" min="0" step="1" value="0" aria-label="对战进度">
        <button type="button" id="playToggle" class="primary" title="播放" aria-label="播放">
          <svg class="control-icon play-icon--play" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M7.5 5v14L19 12z"></path>
          </svg>
          <svg class="control-icon play-icon--pause" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M7 5h4v14H7zM13 5h4v14h-4z"></path>
          </svg>
        </button>
        <button type="button" id="next" title="下一帧" aria-label="下一帧">
          <svg class="control-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M17 5h2v14h-2zM5 5.5v13L15.5 12z"></path>
          </svg>
        </button>
        <button type="button" id="speedToggle" title="播放速度 1 倍" aria-label="播放速度 1 倍">1x</button>
      </div>
    </section>
</main>
<script id="matchData" type="application/json">__MATCH_DATA__</script>
<script>
(() => {
  const data = JSON.parse(document.getElementById('matchData').textContent);
  const obstacleSet = new Set(data.obstacles.map(([r,c]) => `${r},${c}`));
  const maxFrame = data.turns.length;
  const speeds = [1, 2, 0.5];
  let frame = 0, speedIndex = 0, timer = null;
  const $ = id => document.getElementById(id);
  const board = $('board'), cells = [];
  $('progress').max = String(maxFrame);

  board.style.gridTemplateColumns = `repeat(${data.n}, 1fr)`;
  for (let r = 0; r < data.n; r++) for (let c = 0; c < data.n; c++) {
    const cell = document.createElement('div');
    cell.className = 'cell';
    cell.setAttribute('aria-label', `[${r},${c}]`);
    board.appendChild(cell);
    cells.push(cell);
  }

  function key(cell) { return `${cell[0]},${cell[1]}`; }
  function stateAt(targetFrame) {
    const blocked = new Set(obstacleSet);
    let a = [...data.start_a], b = [...data.start_b], collision = false;
    for (let i = 0; i < targetFrame; i++) {
      const turn = data.turns[i];
      if (turn.event === 'move' || turn.event === 'collision') {
        blocked.add(key(turn.a_from)); blocked.add(key(turn.b_from));
        a = [...turn.a_to]; b = [...turn.b_to];
        collision = turn.event === 'collision';
      }
    }
    return {blocked, a, b, collision};
  }
  function render() {
    const state = stateAt(frame);
    for (let r = 0; r < data.n; r++) for (let c = 0; c < data.n; c++) {
      const cell = cells[r * data.n + c], cellKey = `${r},${c}`;
      cell.className = 'cell';
      if (obstacleSet.has(cellKey)) cell.classList.add('obstacle');
      else if (state.blocked.has(cellKey)) cell.classList.add('trail');
      if (state.collision && key(state.a) === cellKey) cell.classList.add('collision');
      else {
        if (key(state.a) === cellKey) cell.classList.add('a');
        if (key(state.b) === cellKey) cell.classList.add('b');
      }
    }
    $('progress').value = String(frame);
    $('progress').setAttribute('aria-valuetext', `${frame} / ${maxFrame}`);
    $('prev').disabled = frame === 0; $('next').disabled = frame === maxFrame;
  }
  function clearTimer() { if (timer) clearTimeout(timer); timer = null; }
  function stop() {
    clearTimer();
    $('playToggle').classList.remove('is-playing');
    $('playToggle').title = '播放';
    $('playToggle').setAttribute('aria-label', '播放');
  }
  function schedule() {
    clearTimer();
    if (frame >= maxFrame) { stop(); return; }
    $('playToggle').classList.add('is-playing');
    $('playToggle').title = '暂停';
    $('playToggle').setAttribute('aria-label', '暂停');
    timer = setTimeout(() => { frame += 1; render(); schedule(); }, Math.max(80, 180 / speeds[speedIndex]));
  }
  $('playToggle').addEventListener('click', () => {
    if (timer) { stop(); return; }
    if (frame >= maxFrame) frame = 0;
    render(); schedule();
  });
  $('prev').addEventListener('click', () => { stop(); frame = Math.max(0, frame - 1); render(); });
  $('next').addEventListener('click', () => { stop(); frame = Math.min(maxFrame, frame + 1); render(); });
  $('progress').addEventListener('input', event => { stop(); frame = Number(event.target.value); render(); });
  $('speedToggle').addEventListener('click', () => {
    speedIndex = (speedIndex + 1) % speeds.length;
    const speed = speeds[speedIndex];
    $('speedToggle').textContent = `${speed}x`;
    $('speedToggle').title = `播放速度 ${speed} 倍`;
    $('speedToggle').setAttribute('aria-label', `播放速度 ${speed} 倍`);
    if (timer) schedule();
  });
  window.addEventListener('keydown', event => {
    if (event.key === 'ArrowLeft') $('prev').click();
    if (event.key === 'ArrowRight') $('next').click();
    if (event.key === ' ') { event.preventDefault(); $('playToggle').click(); }
  });
  render();
})();
</script>
"""


def render_html(record):
    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    encoded = encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return HTML_TEMPLATE.replace("__MATCH_DATA__", encoded)


def detail_height_for_board(n):
    if n >= 17:
        return 540
    if n >= 13:
        return 580
    return 620


def main():
    record = play_match()
    print(json.dumps({
        "winner": record["winner"],
        "details": {
            "format": "html",
            "content": render_html(record),
            "height": detail_height_for_board(record["n"]),
        },
    }, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
