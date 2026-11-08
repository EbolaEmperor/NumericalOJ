"""隔离的 Harbor 官方 CLI 适配进程；不导入 NumericalOJ 站点配置。"""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from backend.oj_modules.integrations.harbor_results import normalize_harbor_rewards, write_harbor_result

_WIRE_PREFIX = 'NUMOJ_HARBOR '
_MAX_LOG_BYTES = 2 * 1024 * 1024
_AGENTS = {'claude-code': ('CachedClaudeCode', '2.1.205'), 'codex': ('CachedCodex', '0.144.5'),
           'opencode': ('CachedOpenCode', '1.18.3'), 'pi': ('CachedPi', '0.82.1')}


def _emit(value):
    print(_WIRE_PREFIX + json.dumps(value, ensure_ascii=False), flush=True)


def _clean(value, secret):
    return str(value or '').replace(secret, '[REDACTED]') if secret else str(value or '')


def _read_output(path):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_LOG_BYTES:
            return ''
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def _write_private(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        stream.write(text)


def _trial_config(payload, event_path):
    from harbor.models.trial.config import AgentConfig, EnvironmentConfig, TaskConfig, TrialConfig, VerifierConfig
    trial_dir = Path(payload['trial_dir'])
    endpoint = payload.get('endpoint') or {}
    agent_name = payload['agent']
    timeout = int(payload['agent_timeout_seconds'])
    agent = AgentConfig(name='oracle', override_timeout_sec=timeout, override_setup_timeout_sec=600)
    if agent_name != 'oracle':
        class_name, version = _AGENTS[agent_name]
        kwargs = {'version': version}
        effort = payload.get('reasoning_effort')
        if effort not in (None, '', 'default'):
            kwargs['reasoning_effort'] = effort
        if agent_name == 'pi':
            kwargs.update({key: endpoint[key] for key in ('context_window_tokens', 'max_output_tokens')
                           if isinstance(endpoint.get(key), int) and endpoint[key] > 0})
        api_format = ('anthropic_messages' if endpoint['protocol'] == 'anthropic' else
                      'openai_responses' if agent_name == 'codex' else 'openai_chat_completions')
        agent = AgentConfig(import_path='backend.oj_modules.integrations.harbor_agents:' + class_name,
            model_name=endpoint['model'], base_url=endpoint['base_url'],
            model_api_key_name='NUMOJ_HARBOR_API_KEY', model_api_format=api_format,
            skip_model_parsing=True, env={'NUMOJ_HARBOR_API_KEY': endpoint['api_key']},
            override_timeout_sec=timeout, override_setup_timeout_sec=600, kwargs=kwargs)
    overlay = trial_dir / '.platform-compose.json'
    _write_private(overlay, json.dumps({'services': {'main': {
        'image': '${PREBUILT_IMAGE_NAME:-${MAIN_IMAGE_NAME}}',
        'extra_hosts': ['host.docker.internal:host-gateway'],
        'security_opt': ['no-new-privileges:true'], 'pids_limit': 512,
    }}}))
    return TrialConfig(task=TaskConfig(path=Path(payload['task_path'])),
        trial_name=payload['trial_name'], trials_dir=trial_dir, agent=agent,
        environment=EnvironmentConfig(
            import_path='backend.oj_modules.integrations.harbor_environment:PlatformDockerEnvironment',
            delete=True, stream=False, override_cpus=2, override_memory_mb=4096, override_gpus=0,
            kwargs={'platform_overlay': str(overlay),
                    'platform_cache_path': str(trial_dir.parent / 'environment_runtime.json'),
                    'platform_event_path': str(event_path),
                    'auto_mounting': True}),
        verifier=VerifierConfig(override_timeout_sec=payload['verifier_timeout_seconds']))


def _project_official_result(payload, returncode, *, native_session_id=''):
    from harbor.models.trial.paths import TrialPaths
    from harbor.models.trial.result import TrialResult
    trial_root = Path(payload['trial_dir']) / payload['trial_name']
    paths = TrialPaths(trial_dir=trial_root)
    path = paths.result_path
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_LOG_BYTES:
        detail = _read_output(Path(payload['trial_dir']) / '.harbor-cli.log')[-4000:]
        raise RuntimeError('Harbor CLI 未生成有效的官方 result.json：' + detail)
    result = TrialResult.model_validate_json(path.read_text(encoding='utf-8'))
    exception = result.exception_info
    rewards = result.verifier_result.rewards if result.verifier_result is not None else None
    failure = ''
    normalized = None
    oracle = payload['agent'] == 'oracle'
    exit_path = paths.agent_dir / 'exit-code.txt'
    if returncode:
        failure = f'Harbor CLI 异常退出，退出码：{returncode}'
    elif oracle and exit_path.exists():
        failure = 'Harbor 标准答案执行失败，退出码：' + _read_output(exit_path).strip()
    elif not result.reward_valid or oracle and exception is not None:
        failure = str(exception.exception_message) if exception else 'Harbor 验证未生成有效 reward'
    else:
        try:
            normalized = normalize_harbor_rewards(rewards)
        except ValueError as exc:
            failure = str(exc)
    secret = str((payload.get('endpoint') or {}).get('api_key') or '')
    return {'ok': not failure, 'error': _clean(failure, secret), 'result': normalized,
        'stdout': _clean((_read_output(paths.agent_dir / 'oracle.txt') if oracle else '')
                         + _read_output(paths.test_stdout_path), secret),
        'stderr': _clean(_read_output(paths.test_stderr_path), secret),
        'official_trial_dir': str(trial_root), 'artifacts_dir': str(paths.artifacts_dir),
        'native_session_id': native_session_id,
        'agent_timed_out': bool(exception and exception.exception_type == 'AgentTimeoutError')}


def _run(payload):
    trial_dir = Path(payload['trial_dir'])
    secret = str((payload.get('endpoint') or {}).get('api_key') or '')
    event_path = trial_dir / '.platform-events.jsonl'
    config_path = trial_dir / '.harbor-cli.json'
    cli_log = trial_dir / '.harbor-cli.log'
    for path in (event_path, config_path, cli_log, trial_dir / '.platform-compose.json'):
        if path.is_symlink():
            raise ValueError('Harbor CLI 私有文件不能是符号链接')
        path.unlink(missing_ok=True)
    _write_private(event_path, '')
    configuration = _trial_config(payload, event_path)
    _write_private(config_path, configuration.model_dump_json(indent=2, context={'redact_sensitive_env': False}))
    cli = Path(sys.executable).with_name('harbor')
    if not cli.is_file():
        raise RuntimeError('当前 Python 环境未安装 Harbor 官方 CLI')
    environment = dict(os.environ)
    environment['PYTHONPATH'] = str(Path(__file__).resolve().parents[3])
    process = None
    cancelled = False
    def cancel(_signum, _frame):
        nonlocal cancelled
        if not cancelled and process is not None and process.poll() is None:
            # 官方 asyncio.run 处理 SIGINT，执行 Trial 的 finally 清理。
            process.send_signal(signal.SIGINT)
        cancelled = True
    previous = signal.signal(signal.SIGTERM, cancel)
    native_id = ''
    def preview_emit(event):
        nonlocal native_id
        if event.get('type') == 'native':
            native_id = str(event.get('session_id') or '')
        _emit(event)
    from backend.oj_modules.integrations.harbor_trace import HarborTraceImporter
    preview = HarborTraceImporter(trial_dir / payload['trial_name'] / 'agent', secrets=(secret,), emit=preview_emit)
    try:
        descriptor = os.open(cli_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output, event_path.open(encoding='utf-8') as events:
            if cancelled:
                raise InterruptedError('Harbor CLI 启动前已取消')
            process = subprocess.Popen([str(cli), 'trial', 'start', '-c', str(config_path)],
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, env=environment)
            if cancelled:
                process.send_signal(signal.SIGINT)
            while True:
                position = events.tell()
                line = events.readline(1024 * 1024)
                if line and not line.endswith('\n'):
                    if process.poll() is not None:
                        raise RuntimeError('Harbor 构建事件通道未完整写入')
                    events.seek(position)
                    time.sleep(0.1)
                    continue
                if line:
                    event = json.loads(line)
                    # 此文件只由宿主环境扩展写入，不解析 CLI 或学生进程 stdout。
                    if event.get('type') != 'build' or event.get('event') not in {'start', 'output', 'complete'}:
                        raise RuntimeError('Harbor 构建事件通道内容无效')
                    if 'text' in event:
                        event['text'] = _clean(event['text'], secret)
                    _emit(event)
                elif process.poll() is not None:
                    break
                else:
                    preview.sync(final=False)
                    time.sleep(0.2)
            process.wait()
        if cancelled:
            raise InterruptedError('Harbor CLI 执行已取消')
        result = _project_official_result(payload, process.returncode, native_session_id=native_id)
        write_harbor_result(trial_dir, result)
        _emit({'type': 'result', 'ok': result['ok']})
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        signal.signal(signal.SIGTERM, previous)
        config_path.unlink(missing_ok=True)


def main():
    payload = json.loads(sys.stdin.readline())
    try:
        _run(payload)
    except BaseException as exc:
        secret = str((payload.get('endpoint') or {}).get('api_key') or '')
        write_harbor_result(payload['trial_dir'], {'ok': False,
            'error': 'Harbor CLI 执行失败：' + _clean(exc, secret), 'result': None, 'stdout': '', 'stderr': ''})
        _emit({'type': 'result', 'ok': False})
    finally:
        (Path(payload['trial_dir']) / '.harbor-cli.json').unlink(missing_ok=True)


if __name__ == '__main__':
    main()
