#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ARC-AGI-3 本地游戏加载与短期会话管理。

每个对局持有独立游戏对象和锁。不同用户、不同标签页之间不会共享游戏状态，也不会
因为某个对局正在计算动画帧而阻塞其他对局。
"""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib.util
import inspect
import secrets
import threading
import time
from typing import Any

from arcengine import ARCBaseGame, ActionInput, FrameDataRaw, GameAction

from oj_modules.arc_agi_3.catalog import ArcGameSpec, get_arc_game


_SESSION_TTL_SECONDS = 45 * 60
_MAX_ACTIVE_SESSIONS = 160
_MAX_SESSIONS_PER_USER = 8
_MAX_RESPONSE_FRAMES = 180


class ArcGameError(Exception):
    """ARC 游戏服务对外的基础异常。"""


class ArcGameNotFound(ArcGameError):
    pass


class ArcSessionNotFound(ArcGameError):
    pass


class ArcSessionBusy(ArcGameError):
    pass


class ArcInvalidAction(ArcGameError):
    pass


@dataclass
class _ActiveSession:
    session_id: str
    username: str
    game_spec: ArcGameSpec
    game: ARCBaseGame
    available_actions: tuple[int, ...]
    updated_at: float
    action_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


_class_cache: dict[str, type[ARCBaseGame]] = {}
_class_cache_lock = threading.Lock()
_sessions: dict[str, _ActiveSession] = {}
_sessions_lock = threading.RLock()


def _load_game_class(game_spec):
    cache_key = game_spec.full_id
    cached = _class_cache.get(cache_key)
    if cached is not None:
        return cached

    with _class_cache_lock:
        cached = _class_cache.get(cache_key)
        if cached is not None:
            return cached

        source_path = game_spec.source_path
        if not source_path.is_file():
            raise ArcGameNotFound('游戏文件不存在。')

        module_name = f'numoj_arc_agi_3_{game_spec.slug}_{game_spec.version}'
        module_spec = importlib.util.spec_from_file_location(module_name, source_path)
        if module_spec is None or module_spec.loader is None:
            raise ArcGameError('游戏模块无法加载。')

        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        game_class = getattr(module, game_spec.class_name, None)
        if not isinstance(game_class, type) or not issubclass(game_class, ARCBaseGame):
            raise ArcGameError('游戏模块格式不正确。')

        _class_cache[cache_key] = game_class
        return game_class


def _new_game_instance(game_spec):
    game_class = _load_game_class(game_spec)
    signature = inspect.signature(game_class)
    kwargs = {'seed': 0} if 'seed' in signature.parameters else {}
    return game_class(**kwargs)


def _sample_frames(frames):
    frame_count = len(frames)
    if frame_count <= _MAX_RESPONSE_FRAMES:
        selected = frames
    else:
        last_index = frame_count - 1
        selected_indices = {
            round(index * last_index / (_MAX_RESPONSE_FRAMES - 1))
            for index in range(_MAX_RESPONSE_FRAMES)
        }
        selected = [frames[index] for index in sorted(selected_indices)]

    return [frame.tolist() for frame in selected], max(0, frame_count - len(selected))


def _serialize_frame_data(frame_data, active_session):
    frames, skipped_frames = _sample_frames(frame_data.frame)
    return {
        'game_id': active_session.game_spec.slug,
        'state': frame_data.state.value,
        'levels_completed': int(frame_data.levels_completed),
        'win_levels': int(frame_data.win_levels),
        'available_actions': [int(action) for action in frame_data.available_actions],
        'frames': frames,
        'skipped_frames': skipped_frames,
        'action_count': active_session.action_count,
        'default_fps': active_session.game_spec.default_fps,
    }


def _prune_sessions_locked(now):
    expired_ids = [
        session_id
        for session_id, active_session in _sessions.items()
        if now - active_session.updated_at > _SESSION_TTL_SECONDS
    ]
    for session_id in expired_ids:
        _sessions.pop(session_id, None)

    overflow = len(_sessions) - _MAX_ACTIVE_SESSIONS
    if overflow > 0:
        oldest = sorted(_sessions.values(), key=lambda item: item.updated_at)
        for active_session in oldest[:overflow]:
            _sessions.pop(active_session.session_id, None)


def _limit_user_sessions_locked(username):
    user_sessions = sorted(
        (
            active_session
            for active_session in _sessions.values()
            if active_session.username == username
        ),
        key=lambda item: item.updated_at,
    )
    overflow = len(user_sessions) - _MAX_SESSIONS_PER_USER + 1
    for active_session in user_sessions[:max(0, overflow)]:
        _sessions.pop(active_session.session_id, None)


def start_arc_game(username, game_id):
    game_spec = get_arc_game(game_id)
    if game_spec is None:
        raise ArcGameNotFound('游戏不存在。')

    try:
        game = _new_game_instance(game_spec)
        frame_data = game.perform_action(ActionInput(id=GameAction.RESET), raw=True)
    except ArcGameError:
        raise
    except Exception as exc:
        raise ArcGameError('游戏启动失败。') from exc

    if not isinstance(frame_data, FrameDataRaw):
        raise ArcGameError('游戏返回了无效画面。')

    now = time.monotonic()
    active_session = _ActiveSession(
        session_id=secrets.token_urlsafe(24),
        username=username,
        game_spec=game_spec,
        game=game,
        available_actions=tuple(int(action) for action in frame_data.available_actions),
        updated_at=now,
    )
    with _sessions_lock:
        _prune_sessions_locked(now)
        _limit_user_sessions_locked(username)
        _sessions[active_session.session_id] = active_session

    return active_session.session_id, _serialize_frame_data(frame_data, active_session)


def _get_owned_session(username, session_id):
    now = time.monotonic()
    with _sessions_lock:
        _prune_sessions_locked(now)
        active_session = _sessions.get(session_id)
        if active_session is None or active_session.username != username:
            raise ArcSessionNotFound('对局已失效，请重新开始。')
        active_session.updated_at = now
        return active_session


def _parse_action(active_session, action_id, action_data):
    try:
        parsed_action_id = int(action_id)
        action = GameAction.from_id(parsed_action_id)
    except (TypeError, ValueError) as exc:
        raise ArcInvalidAction('无效操作。') from exc

    if parsed_action_id != GameAction.RESET.value and parsed_action_id not in active_session.available_actions:
        raise ArcInvalidAction('当前游戏不支持这个操作。')

    if action.is_complex():
        try:
            x = int((action_data or {}).get('x'))
            y = int((action_data or {}).get('y'))
        except (TypeError, ValueError) as exc:
            raise ArcInvalidAction('点击坐标无效。') from exc
        if not (0 <= x <= 63 and 0 <= y <= 63):
            raise ArcInvalidAction('点击坐标超出棋盘。')
        return action, {'x': x, 'y': y}

    return action, {}


def perform_arc_action(username, session_id, action_id, action_data=None):
    active_session = _get_owned_session(username, session_id)
    if not active_session.lock.acquire(blocking=False):
        raise ArcSessionBusy('上一个操作仍在处理中。')

    try:
        action, parsed_data = _parse_action(active_session, action_id, action_data)
        try:
            frame_data = active_session.game.perform_action(
                ActionInput(id=action, data=parsed_data),
                raw=True,
            )
        except Exception as exc:
            raise ArcGameError('操作执行失败。') from exc

        if not isinstance(frame_data, FrameDataRaw):
            raise ArcGameError('游戏返回了无效画面。')
        if action != GameAction.RESET:
            active_session.action_count += 1
        active_session.available_actions = tuple(
            int(available_action) for available_action in frame_data.available_actions
        )
        active_session.updated_at = time.monotonic()
        return _serialize_frame_data(frame_data, active_session)
    finally:
        active_session.lock.release()


def _clear_arc_sessions_for_tests():
    with _sessions_lock:
        _sessions.clear()
