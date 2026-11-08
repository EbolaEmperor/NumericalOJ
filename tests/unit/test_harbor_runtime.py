import asyncio
from contextlib import contextmanager
import gzip
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from backend.oj_modules.integrations.harbor_results import normalize_harbor_rewards
from backend.oj_modules.integrations import harbor_runtime as runtime


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -0.01, 1.01, True, "1"])
def test_reward_rejects_invalid_scores(value):
    with pytest.raises(ValueError):
        normalize_harbor_rewards({"reward": value})


def test_rewards_select_primary_or_average_without_clamping():
    assert normalize_harbor_rewards({"reward": 0.25, "accuracy": 1})["score"] == 0.25
    result = normalize_harbor_rewards({"a": 0.5, "b": 1})
    assert result["score"] == 0.75
    assert result["test_points"]["a"]["max_score"] == 1


def test_rewards_preserve_finite_auxiliary_metrics_without_treating_them_as_points():
    rewards = {"reward": 0.375, "seconds": 12, "loss": -2, "accuracy": 0.5}
    result = normalize_harbor_rewards(rewards)
    assert result["score"] == 0.375
    assert result["rewards"] == rewards
    assert isinstance(result["rewards"]["seconds"], int)
    large_count = 2 ** 100
    assert normalize_harbor_rewards({"reward": 0.375, "count": large_count})["rewards"]["count"] == large_count
    assert set(result["test_points"]) == {"reward", "accuracy"}
    assert normalize_harbor_rewards({"score": 0.25, "seconds": 12})["score"] == 0.25
    assert normalize_harbor_rewards({"reward": 0, "score": 12})["score"] == 0


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), True, "12"])
def test_rewards_reject_invalid_auxiliary_metrics(value):
    with pytest.raises(ValueError):
        normalize_harbor_rewards({"reward": 0.375, "seconds": value})


@pytest.mark.parametrize("rewards", [{"seconds": 12}, {"accuracy": 0.5, "loss": -2}])
def test_rewards_without_primary_reject_non_normalized_metrics(rewards):
    with pytest.raises(ValueError, match="不能推测指标量纲"):
        normalize_harbor_rewards(rewards)


def test_runtime_rejects_symlink_escape_and_unknown_fields(tmp_path, monkeypatch):
    root = tmp_path / "reverse"
    task = root / "attempt" / "task"
    task.mkdir(parents=True)
    monkeypatch.setattr(runtime.config, "REVERSE_JUDGE_WORKSPACE_ROOT", str(root))
    value = {"task_path": str(task), "trial_dir": str(task.parent / "trial")}
    assert runtime.normalize_harbor_runtime(value)["verifier_timeout_seconds"] == 300
    alias = root / "alias"
    alias.symlink_to(task, target_is_directory=True)
    with pytest.raises(ValueError, match="符号链接"):
        runtime.normalize_harbor_runtime(dict(value, task_path=str(alias)))
    with pytest.raises(ValueError, match="字段"):
        runtime.normalize_harbor_runtime(dict(value, arbitrary_path="/etc"))


def test_worker_environment_cannot_expand_site_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "private-database-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "private-model-secret")
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/development.sock")
    env = runtime._child_environment(tmp_path)
    assert "DB_PASSWORD" not in env
    assert "OPENAI_API_KEY" not in env
    assert Path(env["HOME"]).is_relative_to(tmp_path)
    assert env["DOCKER_HOST"] == "unix:///tmp/development.sock"
    assert "DOCKER_CONFIG" in env


def test_stale_success_cannot_survive_worker_start_failure(tmp_path, monkeypatch):
    trial_dir = tmp_path / "trial"
    trial_dir.mkdir()
    stale = trial_dir / runtime.RESULT_FILENAME
    stale.write_text(json.dumps({"ok": True, "result": {"rewards": {"reward": 1}}}))
    monkeypatch.setattr(runtime, "_cleanup_containers", lambda name: None)
    def fail(*args, **kwargs):
        raise OSError("worker spawn failed")
    monkeypatch.setattr(subprocess, "Popen", fail)
    with pytest.raises(OSError, match="spawn failed"):
        runtime._execute({"trial_dir": str(trial_dir), "agent_timeout_seconds": 1,
                          "verifier_timeout_seconds": 1})
    assert not stale.exists()
    assert not (trial_dir / ".runner-active").exists()


def test_cancel_before_start_prevents_future_container_creation(tmp_path, monkeypatch):
    root = tmp_path / "reverse"
    task = root / "attempt" / "task"
    task.mkdir(parents=True)
    monkeypatch.setattr(runtime.config, "REVERSE_JUDGE_WORKSPACE_ROOT", str(root))
    description = {"task_path": str(task), "trial_dir": str(task.parent / "trial")}
    runtime.stop_harbor_trial(description)
    def unexpected(*args, **kwargs):
        pytest.fail("cancelled execution must not start Docker or a worker")
    monkeypatch.setattr(runtime, "_cleanup_containers", unexpected)
    result = runtime._execute(dict(description, agent_timeout_seconds=1, verifier_timeout_seconds=1))
    assert result["canceled"]


def test_official_trial_timeout_collects_artifacts_verifies_then_stops_shared_environment(tmp_path):
    from harbor.models.task.config import TaskConfig
    from harbor.trial.errors import AgentTimeoutError
    from harbor.trial.single_step import SingleStepTrial
    trial = SingleStepTrial.__new__(SingleStepTrial)
    trial.task = SimpleNamespace(instruction="原始题面", config=TaskConfig())
    trial._agent_timeout_sec = 0.01
    trial._load_trajectory = None
    trial._result = SimpleNamespace(agent_result=None, exception_info=None)
    trial.paths = SimpleNamespace(exception_message_path=tmp_path / 'exception.txt')
    calls = []
    async def execute(**kwargs):
        assert kwargs['instruction'] == '原始题面'
        calls.append('agent')
        raise AgentTimeoutError('official timeout')
    async def record(name, **kwargs):
        calls.append(name)
    trial._run_agent_phase = execute
    trial._sync_agent_output = lambda target: record('logs')
    trial._upload_agent_logs = lambda: record('upload')
    trial._collect_artifacts = lambda **kwargs: record('artifacts')
    trial._stop_agent_environment = lambda: record('stop')
    trial._run_verifier = lambda: record('verifier')

    asyncio.run(trial._run())

    assert calls == ['agent', 'logs', 'upload', 'artifacts', 'verifier', 'stop']
    assert trial.result.exception_info.exception_type == 'AgentTimeoutError'
    assert trial.result.exception_info.policy.reward_valid


def test_legacy_finalization_does_not_extend_official_execution_budget():
    assert runtime.harbor_execution_timeout_seconds(30, 20, 7200) == runtime.harbor_execution_timeout_seconds(30, 20)


def test_official_cli_config_keeps_execution_builtin_and_credentials_private(tmp_path):
    from backend.oj_modules.integrations import harbor_agents, harbor_worker
    from harbor.agents.installed.pi import Pi
    payload = {'trial_dir': str(tmp_path), 'task_path': str(tmp_path / 'task'),
               'trial_name': 'official-case', 'agent': 'pi', 'agent_timeout_seconds': 30,
               'verifier_timeout_seconds': 20, 'finalize_timeout_seconds': 600,
               'endpoint': {'model': 'custom', 'protocol': 'openai', 'api_key': 'temporary-relay-key',
                            'base_url': 'http://relay', 'context_window_tokens': 128000, 'max_output_tokens': 16000}}
    config = harbor_worker._trial_config(payload, tmp_path / 'events.jsonl')
    assert config.agent.import_path.endswith(':CachedPi')
    assert config.agent.override_timeout_sec == 30
    assert config.agent.kwargs['context_window_tokens'] == 128000
    assert config.environment.kwargs['auto_mounting'] is True
    assert config.environment.mounts is None
    assert config.environment.override_cpus == 2
    assert config.environment.override_memory_mb == 4096
    assert config.environment.override_gpus == 0
    assert config.extra_instructions == [] and config.extra_instruction_paths == []
    assert harbor_agents.CachedPi.run is Pi.run
    assert harbor_agents.CachedPi.resume is Pi.resume
    assert 'exec' not in harbor_agents.CachedPi.__dict__
    path = tmp_path / 'cli.json'
    harbor_worker._write_private(path, config.model_dump_json(context={'redact_sensitive_env': False}))
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())['agent']['env']['NUMOJ_HARBOR_API_KEY'] == 'temporary-relay-key'


def test_worker_invokes_official_cli_and_never_uses_stdout_as_control(tmp_path, monkeypatch):
    from backend.oj_modules.integrations import harbor_worker
    captured = []
    class Process:
        returncode = 0
        def __init__(self, command, **kwargs):
            assert Path(command[0]).name == 'harbor'
            assert command[1:4] == ['trial', 'start', '-c']
            path = Path(command[4])
            assert path.stat().st_mode & 0o777 == 0o600
            assert 'temporary-key' not in str(command)
            assert kwargs['stdin'] is subprocess.DEVNULL
            kwargs['stdout'].write('NUMOJ_HARBOR {"type":"build","event":"complete"}\n')
        def poll(self):
            return 0
        def wait(self, **kwargs):
            return 0
    monkeypatch.setattr(harbor_worker.subprocess, 'Popen', Process)
    monkeypatch.setattr(harbor_worker, '_project_official_result', lambda *a, **k: {'ok': True, 'result': {'score': 0.375}})
    monkeypatch.setattr(harbor_worker, '_emit', captured.append)
    harbor_worker._run({'trial_dir': str(tmp_path), 'trial_name': 'cli-case',
        'task_path': str(tmp_path / 'task'), 'agent': 'oracle', 'agent_timeout_seconds': 20,
        'verifier_timeout_seconds': 20, 'endpoint': {'api_key': 'temporary-key'}})
    assert captured == [{'type': 'result', 'ok': True}]
    assert not (tmp_path / '.harbor-cli.json').exists()


@pytest.mark.parametrize('error,valid', [(None, True), ('AgentTimeoutError', True), ('ApiConnectionError', False)])
def test_cli_result_preserves_fractional_rewards_and_official_failure_policy(tmp_path, error, valid):
    from backend.oj_modules.integrations import harbor_worker
    from harbor.models.task.id import LocalTaskId
    from harbor.models.trial.config import TrialConfig, TaskConfig
    from harbor.models.trial.result import TrialResult, AgentInfo, ExceptionInfo
    from harbor.models.verifier.result import VerifierResult
    from datetime import datetime, timezone
    config = TrialConfig(task=TaskConfig(path=tmp_path / 'task'))
    result = TrialResult(task_name='task', trial_name='official-case', trial_uri=tmp_path.as_uri(),
                        task_id=LocalTaskId(path=tmp_path / 'task'), task_checksum='', config=config,
                        agent_info=AgentInfo(name='pi', version='0.82.1'),
                        verifier_result=VerifierResult(rewards={'reward': 0.375, 'accuracy': 0.5}))
    if error:
        result.exception_info = ExceptionInfo(exception_type=error, exception_message='原生异常',
            exception_traceback='', occurred_at=datetime.now(timezone.utc))
    directory = tmp_path / 'official-case'
    directory.mkdir()
    (directory / 'result.json').write_text(result.model_dump_json())
    projected = harbor_worker._project_official_result(
        {'trial_dir': str(tmp_path), 'trial_name': 'official-case', 'agent': 'pi'}, 0)
    assert projected['ok'] is valid
    if valid:
        assert projected['result']['score'] == 0.375
        assert projected['result']['rewards'] == {'reward': 0.375, 'accuracy': 0.5}
    else:
        assert projected['result'] is None


def test_native_session_preservation_redacts_json_fields_and_both_key_sources(tmp_path, monkeypatch):
    from backend.oj_modules.agents import workspace
    trial = tmp_path / 'trial'
    trial.mkdir()
    agent = trial / runtime._trial_name(trial) / 'agent'
    agent.mkdir(parents=True)
    (agent / 'session.jsonl').write_text(json.dumps({
        'api_key': 'unlisted-provider-secret', 'content': 'long-lived-key temporary-key',
        'usage': {'input_tokens': 17},
    }) + '\n')
    captured = {}
    monkeypatch.setattr(workspace, 'write_agent_workspace_file',
                        lambda session, name, data: captured.update({name: data}))
    runtime._preserve_native_logs('session', {'trial_dir': str(trial)},
                                  secrets=('long-lived-key', 'temporary-key'))
    payload = json.loads(captured['.runtime/harbor/agent/session.jsonl'])
    assert payload['api_key'] == '[REDACTED]'
    assert payload['content'] == '[REDACTED] [REDACTED]'
    assert payload['usage']['input_tokens'] == 17


def test_archive_retains_original_cot_replies_and_tools(tmp_path, monkeypatch):
    from backend.oj_modules.agents import workspace
    trial = tmp_path / 'trial'
    trial.mkdir()
    agent = trial / runtime._trial_name(trial) / 'agent'
    sessions = agent / 'pi/sessions'
    sessions.mkdir(parents=True)
    reply = '面向用户的中间回复' * 10000
    tool_output = '完整工具输出' * 10000
    arguments = {'type': 'thinking', 'reasoning_content': '工具的合法任务参数'}
    assistant = {'type': 'message', 'id': 'assistant-1', 'message': {
        'role': 'assistant', 'content': [
            {'type': 'thinking', 'thinking': 'PRIVATE_COT_MARKER'},
            {'type': 'text', 'text': reply},
            {'type': 'toolCall', 'id': 'call-1', 'name': 'bash', 'arguments': arguments},
        ], 'usage': {'input': 10, 'output': 20, 'reasoning_tokens': 7},
    }}
    result = {'type': 'message', 'id': 'result-1', 'message': {
        'role': 'toolResult', 'toolCallId': 'call-1', 'content': [{'type': 'text', 'text': tool_output}],
    }}
    native = [assistant, result]
    (sessions / 'native.jsonl').write_text(''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in native))
    (agent / 'pi.txt').write_text(''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in [
        {'type': 'thinking_delta', 'delta': 'PRIVATE_COT_MARKER'}, *native,
    ]))
    (agent / 'trajectory.json').write_text(json.dumps({'session_id': 'native', 'steps': [{
        'step_id': 1, 'source': 'agent', 'message': reply,
        'reasoning_content': 'PRIVATE_COT_MARKER',
        'tool_calls': [{'tool_call_id': 'call-1', 'arguments': arguments}],
    }]}, ensure_ascii=False))
    captured = {}
    monkeypatch.setattr(workspace, 'write_agent_workspace_file',
                        lambda _sid, name, data: captured.update({name: data}))
    runtime._preserve_native_logs('session', {'trial_dir': str(trial)})
    restored = gzip.decompress(captured['.runtime/harbor/agent/pi.txt.gz'])
    assert b'PRIVATE_COT_MARKER' in restored
    records = [json.loads(line) for line in restored.splitlines()]
    assert len(records) == 3
    assert records[0] == {'type': 'thinking_delta', 'delta': 'PRIVATE_COT_MARKER'}
    assert records[1] == assistant
    assert records[2] == result
    archived_native = [json.loads(line) for line in captured['.runtime/harbor/agent/pi/sessions/native.jsonl'].splitlines()]
    assert archived_native == native
    trajectory = json.loads(captured['.runtime/harbor/agent/trajectory.json'])
    assert trajectory['steps'][0]['message'] == reply
    assert trajectory['steps'][0]['reasoning_content'] == 'PRIVATE_COT_MARKER'
    assert trajectory['steps'][0]['tool_calls'][0]['arguments'] == arguments


def test_large_pi_stdout_is_fully_preserved_as_streamed_redacted_gzip(tmp_path, monkeypatch):
    from backend.oj_modules.agents import workspace
    trial = tmp_path / 'trial'
    trial.mkdir()
    agent = trial / runtime._trial_name(trial) / 'agent'
    agent.mkdir(parents=True)
    secret = b'long-lived-relay-secret'
    # 密钥横跨 64 KiB 的底层读取块；总原始输出 128 MiB，超过旧保留上限。
    prefix = b'A' * (64 * 1024 - 3)
    line = prefix + secret + b'B' * (128 * 1024 - len(prefix) - len(secret) - 1) + b'\n'
    raw = agent / 'pi.txt'
    with raw.open('wb') as output:
        for _ in range(1024):
            output.write(line)
        output.write(b'{"api_key":"other-secret","usage":{"input_tokens":17}}\n')
        output.write(b'{"type":"done"}\n')
    (agent / 'trajectory.json').write_text('{"session_id":"native","steps":[]}')
    sessions = agent / 'pi/sessions'
    sessions.mkdir(parents=True)
    (sessions / 'native.jsonl').write_text('{"type":"session","id":"native"}\n')
    captured = {}
    monkeypatch.setattr(workspace, 'write_agent_workspace_file',
                        lambda _sid, name, data: captured.update({name: data}))
    original_read = Path.read_bytes
    def bounded_read(path):
        assert path != raw, '不能把大型原始 stdout 整体读入内存'
        return original_read(path)
    monkeypatch.setattr(Path, 'read_bytes', bounded_read)

    runtime._preserve_native_logs('session', {'trial_dir': str(trial)}, secrets=(secret.decode(),))

    compressed = captured['.runtime/harbor/agent/pi.txt.gz']
    assert len(compressed) < 1024 * 1024
    from io import BytesIO
    with gzip.GzipFile(fileobj=BytesIO(compressed)) as restored:
        expected = line.replace(secret, b'[REDACTED]')
        for _ in range(1024):
            assert restored.readline() == expected
        last = json.loads(restored.readline())
        assert last == {'api_key': '[REDACTED]', 'usage': {'input_tokens': 17}}
        assert json.loads(restored.readline()) == {'type': 'done'}
        assert restored.read() == b''
    assert json.loads(captured['.runtime/harbor/agent/trajectory.json'])['steps'] == []
    assert json.loads(captured['.runtime/harbor/agent/pi/sessions/native.jsonl'])['id'] == 'native'
    assert raw.stat().st_size > 128 * 1024 * 1024
    assert '.runtime/harbor/agent/pi.txt' not in captured


@pytest.mark.parametrize('limit', ['expanded', 'line', 'compressed'])
def test_pi_log_over_limit_fails_without_publishing_partial_archive(tmp_path, monkeypatch, limit):
    from backend.oj_modules.agents import workspace
    trial = tmp_path / 'trial'
    trial.mkdir()
    agent = trial / runtime._trial_name(trial) / 'agent'
    agent.mkdir(parents=True)
    raw = agent / 'pi.txt'
    if limit == 'expanded':
        monkeypatch.setattr(runtime, 'HARBOR_RAW_LOG_MAX_BYTES', 64)
        raw.write_bytes(b'x' * 65)
    elif limit == 'line':
        monkeypatch.setattr(runtime, 'HARBOR_RAW_LOG_MAX_LINE_BYTES', 64)
        raw.write_bytes(b'x' * 65)
    else:
        monkeypatch.setattr(runtime, 'HARBOR_NATIVE_STORED_MAX_BYTES', 128)
        raw.write_bytes(os.urandom(4096))
    monkeypatch.setattr(workspace, 'write_agent_workspace_file', lambda *_a: pytest.fail('不能发布不完整压缩日志'))
    with pytest.raises(ValueError, match='限制'):
        runtime._preserve_native_logs('session', {'trial_dir': str(trial)})
    assert raw.is_file()


@pytest.mark.parametrize('activity', ['', 'worker', 'cli'])
def test_physical_stop_check_ignores_preservation_marker_but_refuses_orphan_processes(tmp_path, monkeypatch, activity):
    task = tmp_path / 'task'
    task.mkdir()
    trial = tmp_path / 'trial'
    trial.mkdir()
    name = runtime._trial_name(trial)
    (trial / '.preservation-failed').touch()
    monkeypatch.setattr(runtime.config, 'REVERSE_JUDGE_WORKSPACE_ROOT', str(tmp_path))
    description = {'task_path': str(task), 'trial_dir': str(trial)}
    def inspect(command, **kwargs):
        stdout = ''
        if command[0] == 'ps' and activity:
            stdout = ('123 python -m backend.oj_modules.integrations.harbor_worker --run-id=' + name
                      if activity == 'worker' else '123 harbor trial start -c ' + str(trial / '.harbor-cli.json'))
        return SimpleNamespace(returncode=0, stdout=stdout)
    monkeypatch.setattr(subprocess, 'run', inspect)
    assert runtime.harbor_trial_running(description) is None
    assert runtime.harbor_trial_physically_stopped(description) is (not bool(activity))
    assert (trial / '.preservation-failed').exists()


def test_host_finalize_reuses_evidence_without_execution_or_mutating_result(tmp_path, monkeypatch):
    task = tmp_path / 'task'
    task.mkdir()
    trial = tmp_path / 'trial'
    trial.mkdir()
    monkeypatch.setattr(runtime.config, 'REVERSE_JUDGE_WORKSPACE_ROOT', str(tmp_path))
    monkeypatch.setattr(runtime, 'harbor_trial_physically_stopped', lambda _: True)
    calls = []
    monkeypatch.setattr(runtime, '_import_official_trace', lambda *_a, **_k: calls.append('trace'))
    monkeypatch.setattr(runtime, '_preserve_native_logs', lambda *_a, **_k: calls.append('logs'))
    monkeypatch.setattr(runtime, 'import_harbor_artifacts', lambda *_a, **_k: calls.append('artifacts'))
    monkeypatch.setattr(runtime, '_execute', lambda *_a, **_k: pytest.fail('恢复不得重跑 CLI 或模型'))
    result = {'ok': True, 'result': {'score': 0.375}}
    runtime.finalize_harbor_trial_outputs(runtime={'task_path': str(task), 'trial_dir': str(trial)},
        session_id='judge-session', result=result, secrets=(), emit=lambda _event: None)
    assert calls == ['trace', 'logs', 'artifacts']
    assert result == {'ok': True, 'result': {'score': 0.375}}
    monkeypatch.setattr(runtime, 'harbor_trial_physically_stopped', lambda _: False)
    with pytest.raises(ValueError, match='拒绝恢复'):
        runtime.finalize_harbor_trial_outputs(runtime={'task_path': str(task), 'trial_dir': str(trial)},
            session_id='judge-session', result=result, secrets=(), emit=lambda _event: None)
    assert calls == ['trace', 'logs', 'artifacts']


@pytest.mark.parametrize('remove_failure', [1, 'timeout'])
def test_cleanup_verifies_absence_after_concurrent_official_removal(monkeypatch, remove_failure):
    queries = iter(['container-id\n', '', '', ''])
    def run(command, **kwargs):
        if command[1] == 'rm':
            if remove_failure == 'timeout':
                raise subprocess.TimeoutExpired(command, 30)
            return SimpleNamespace(returncode=remove_failure, stdout='', stderr='No such container')
        return SimpleNamespace(returncode=0, stdout=next(queries), stderr='')
    monkeypatch.setattr(subprocess, 'run', run)
    runtime._cleanup_containers('numoj-harbor-test')


def test_cleanup_keeps_slot_when_removal_does_not_remove_container(monkeypatch):
    from backend.oj_modules.tasks.agent.harness_runtime import AgentHarnessCleanupError
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs: SimpleNamespace(
        returncode=1 if command[1] == 'rm' else 0, stdout='container-id\n', stderr='',
    ))
    with pytest.raises(AgentHarnessCleanupError, match='评测环境异常，请联系管理员处理'):
        runtime._cleanup_containers('numoj-harbor-test')


def test_stop_and_poll_are_idempotent_after_task_source_is_removed(tmp_path, monkeypatch):
    root = tmp_path / 'reverse'
    trial = root / 'attempt/trial'
    trial.mkdir(parents=True)
    monkeypatch.setattr(runtime.config, 'REVERSE_JUDGE_WORKSPACE_ROOT', str(root))
    description = {'task_path': str(root / 'attempt/deleted-source'), 'trial_dir': str(trial)}
    with pytest.raises(ValueError, match='任务目录不存在'):
        runtime.normalize_harbor_runtime(description)
    runtime._trial_name(trial)
    monkeypatch.setattr(subprocess, 'run', lambda *_a, **_k: SimpleNamespace(returncode=0, stdout=''))
    runtime.stop_harbor_trial(description)
    runtime.stop_harbor_trial(description)
    assert runtime.harbor_trial_running(description) is False


@pytest.mark.parametrize('declaration,manifest_only', [('', False), ('artifacts = []\n', True), ('artifacts = ["/app"]\n', False)])
def test_optional_artifacts_preserve_grading_but_declared_output_must_exist(tmp_path, monkeypatch, declaration, manifest_only):
    from backend.oj_modules.agents import workspace
    task = tmp_path / 'task'
    (task / 'environment').mkdir(parents=True)
    (task / 'solution').mkdir()
    (task / 'tests').mkdir()
    (task / 'task.toml').write_text(declaration)
    (task / 'instruction.md').write_text('任务目标')
    (task / 'environment/Dockerfile').write_text('FROM scratch\n')
    (task / 'solution/solve.sh').write_text('#!/bin/bash\ntrue\n')
    (task / 'tests/test.sh').write_text('#!/bin/bash\necho 1 > /logs/verifier/reward.txt\n')
    assert bool(runtime.validate_harbor_task(task).config.artifacts) == bool('/app' in declaration)
    trial = tmp_path / 'trial'
    trial.mkdir()
    artifacts = trial / 'artifacts'
    if manifest_only:
        artifacts.mkdir()
        (artifacts / 'manifest.json').write_text('[]')
    monkeypatch.setattr(runtime.config, 'REVERSE_JUDGE_WORKSPACE_ROOT', str(tmp_path))
    @contextmanager
    def relay(*args, **kwargs):
        yield SimpleNamespace(endpoint_base_url='http://relay', endpoint_api_key='temporary',
                              temporary_secrets=('temporary',), wait_for_endpoint_usage=lambda: None,
                              raise_if_usage_failed=lambda: None)
    histories = []
    def merge_history(session_id, candidates):
        histories.append((session_id, candidates))
        return ('previous-temporary', *candidates)
    monkeypatch.setattr(workspace, 'merge_agent_temporary_redaction_candidates', merge_history)
    monkeypatch.setattr(runtime, '_secret_relay', relay)
    monkeypatch.setattr(runtime, '_import_official_trace', lambda *_a, **_k: None)
    monkeypatch.setattr(runtime, '_execute', lambda *args, **kwargs: {'ok': True, 'artifacts_dir': str(artifacts)})
    monkeypatch.setattr(workspace, 'inject_agent_workspace_files', lambda *_a: pytest.fail('无答案不能创建下载归档'))
    options = dict(harbor_runtime={'task_path': str(task), 'trial_dir': str(trial)},
                   task_id='optional-artifacts', requested_by='test', harness='pi',
                   endpoint={'model': 'test', 'api_key': 'long-term-key'})
    if '/app' in declaration:
        with pytest.raises(ValueError, match='交付物目录'):
            runtime.run_harbor_agent(**options)
    else:
        assert runtime.run_harbor_agent(**options).returncode == 0
    assert histories == [('optional-artifacts', ('temporary',))]


def test_legacy_and_host_expansion_are_rejected_before_official_execution(tmp_path):
    with pytest.raises(ValueError, match="旧反向评测格式已弃用"):
        runtime.validate_harbor_task(tmp_path)
    (tmp_path / "task.toml").write_text('[environment]\nenv = { PASSWORD = "${DB_PASSWORD}" }\n')
    with pytest.raises(ValueError, match="宿主环境变量"):
        runtime.validate_harbor_task(tmp_path)


@pytest.mark.parametrize('declaration', ['', '[verifier]\ntimeout_sec = 15\n'])
def test_task_uses_official_shared_verifier_default_without_environment_control(tmp_path, declaration):
    from harbor.models.task.verifier_mode import VerifierEnvironmentMode, resolve_task_verifier_mode
    (tmp_path / 'solution').mkdir()
    (tmp_path / 'environment').mkdir()
    (tmp_path / 'tests').mkdir()
    (tmp_path / 'task.toml').write_text(declaration)
    (tmp_path / 'instruction.md').write_text('任务目标')
    (tmp_path / 'solution/solve.sh').write_text('#!/bin/bash\ntrue\n')
    (tmp_path / 'tests/test.sh').write_text('#!/bin/bash\necho 1 > /logs/verifier/reward.txt\n')
    (tmp_path / 'environment/Dockerfile').write_text('FROM scratch\n')
    task = runtime.validate_harbor_task(tmp_path)
    assert task.config.verifier.environment_mode is None
    assert task.config.verifier.environment is None
    assert resolve_task_verifier_mode(task.config) == VerifierEnvironmentMode.SHARED


@pytest.mark.parametrize('verifier', [
    {'environment_mode': 'shared'}, {'environment_mode': 'separate'},
    {'environment_mode': None}, {'environment_mode': 'null'},
    {'environment': {}}, {'environment': {'docker_image': 'private-image'}},
])
def test_task_cannot_choose_verifier_environment_even_with_null_or_default(tmp_path, monkeypatch, verifier):
    # TOML 不支持 null；直接覆盖解析结果同时验证显式 null 也不能绕过字段存在检查。
    (tmp_path / 'task.toml').write_text('[verifier]\n')
    monkeypatch.setattr(runtime.tomllib, 'loads', lambda _payload: {'verifier': verifier})
    with pytest.raises(ValueError, match='^验证器运行环境由平台统一配置$'):
        runtime.validate_harbor_task(tmp_path)


@pytest.mark.parametrize('declaration', [
    '[verifier]\nenvironment_mode = "shared"\n',
    '[verifier]\nenvironment_mode = "separate"\n',
    '[verifier]\nenvironment_mode = "null"\n',
    '[verifier.environment]\n',
    '[verifier]\nenvironment = {}\n',
])
def test_explicit_toml_verifier_environment_is_rejected_before_execution(tmp_path, declaration):
    (tmp_path / 'task.toml').write_text(declaration)
    with pytest.raises(ValueError, match='^验证器运行环境由平台统一配置$'):
        runtime.validate_harbor_task(tmp_path)


def test_task_configuration_size_is_bounded_before_toml_parsing(tmp_path, monkeypatch):
    (tmp_path / "task.toml").write_bytes(b"x" * (runtime.HARBOR_TASK_CONFIG_MAX_BYTES + 1))
    monkeypatch.setattr(runtime.tomllib, "loads", lambda *a: pytest.fail("oversized configuration must not be parsed"))
    with pytest.raises(ValueError, match="不能超过 1 MiB"):
        runtime.validate_harbor_task(tmp_path)


def test_task_configuration_symlink_is_rejected_before_reading(tmp_path, monkeypatch):
    outside = tmp_path / "outside.toml"
    outside.write_text("environment = {}\n")
    task = tmp_path / "task"
    task.mkdir()
    (task / "task.toml").symlink_to(outside)
    monkeypatch.setattr(runtime.tomllib, "loads", lambda *a: pytest.fail("configuration symlink must not be parsed"))
    with pytest.raises(ValueError, match="符号链接"):
        runtime.validate_harbor_task(task)


@pytest.mark.parametrize("failure,expected", [
    ("AgentSecretRelayCleanupError", "AgentHarnessCleanupError"),
    ("AgentSecretRelayUsageHardStopError", "AgentUsageHardStopError"),
])
def test_relay_failures_keep_generic_cleanup_and_quota_semantics(monkeypatch, failure, expected):
    from backend.oj_modules.tasks.agent import secret_relay, harness_runtime
    @contextmanager
    def fake(*args, **kwargs):
        yield object()
    monkeypatch.setattr(secret_relay, "run_agent_secret_relays", fake)
    with pytest.raises(getattr(harness_runtime, expected)):
        with runtime._secret_relay({}):
            raise getattr(secret_relay, failure)("relay stopped")


@pytest.mark.parametrize("cpus,memory,expected", [
    (0.5, 1024, (0.5, 1024)), (0.01, 128, (0.01, 128)),
    (8, 16384, (2, 4096)), (None, None, (2, 4096)),
])
def test_environment_keeps_task_limits_within_platform_ceiling(tmp_path, monkeypatch, cpus, memory, expected):
    from harbor.models.task.config import EnvironmentConfig
    from backend.oj_modules.integrations.harbor_environment import PlatformDockerEnvironment, DockerEnvironment
    captured = {}
    def init(self, *args, **kwargs):
        captured.update(kwargs)
        self.task_env_config = kwargs["task_env_config"]
    monkeypatch.setattr(DockerEnvironment, "__init__", init)
    monkeypatch.setattr(PlatformDockerEnvironment, "_image_available", classmethod(lambda cls, image: False))
    overlay = tmp_path / "overlay.json"
    overlay.write_text("{}")
    PlatformDockerEnvironment(
        platform_overlay=str(overlay), environment_dir=tmp_path,
        task_env_config=EnvironmentConfig(docker_image="prebuilt:1", cpus=cpus, memory_mb=memory, gpus=8,
                                         env={"NVIDIA_VISIBLE_DEVICES": "all", "CUDA_VISIBLE_DEVICES": "0"}),
        override_cpus=2, override_memory_mb=4096,
    )
    assert (captured["override_cpus"], captured["override_memory_mb"]) == expected
    assert captured["override_gpus"] == 0
    assert captured["task_env_config"].env["NVIDIA_VISIBLE_DEVICES"] == "void"
    assert captured["task_env_config"].env["CUDA_VISIBLE_DEVICES"] == ""


@pytest.mark.parametrize("cpus,memory", [(0, 1024), (-1, 1024), (1, 0), (1, -1)])
def test_environment_rejects_unlimited_task_resource_values_before_docker(tmp_path, monkeypatch, cpus, memory):
    from harbor.models.task.config import EnvironmentConfig
    from backend.oj_modules.integrations.harbor_environment import PlatformDockerEnvironment
    overlay = tmp_path / "overlay.json"
    overlay.write_text("{}")
    def unexpected(*args):
        pytest.fail("无效资源值必须在访问 Docker 前拒绝")
    monkeypatch.setattr(PlatformDockerEnvironment, "_image_available", classmethod(unexpected))
    with pytest.raises(ValueError, match="大于 0"):
        PlatformDockerEnvironment(
            platform_overlay=str(overlay), environment_dir=tmp_path,
            task_env_config=EnvironmentConfig(docker_image="prebuilt:1", cpus=cpus, memory_mb=memory),
            override_cpus=2, override_memory_mb=4096,
        )


@pytest.mark.parametrize("cpus", [1e-9, 1e-20])
def test_environment_rejects_tiny_cpu_that_would_round_to_unlimited(tmp_path, monkeypatch, cpus):
    from harbor.models.task.config import EnvironmentConfig
    from backend.oj_modules.integrations.harbor_environment import PlatformDockerEnvironment
    overlay = tmp_path / "overlay.json"
    overlay.write_text("{}")
    def unexpected(*args):
        pytest.fail("无法安全表达的 CPU 配额必须在访问 Docker 前拒绝")
    monkeypatch.setattr(PlatformDockerEnvironment, "_image_available", classmethod(unexpected))
    with pytest.raises(ValueError, match="至少为 0.01"):
        PlatformDockerEnvironment(
            platform_overlay=str(overlay), environment_dir=tmp_path,
            task_env_config=EnvironmentConfig(docker_image="prebuilt:1", cpus=cpus),
            override_cpus=2, override_memory_mb=4096,
        )
