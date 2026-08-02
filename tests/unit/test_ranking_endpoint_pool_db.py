# -*- coding: utf-8 -*-
"""反向评测质量门禁端点池的数据隔离与比赛配置 SQL 单测。"""

import pytest

from oj_modules.ranking.agent_judge import db as endpoint_db
from oj_modules.ranking import db as ranking_db


class _FakeCursor:
    def __init__(self, *, rows=None, one_values=None, lastrowid=91):
        self.calls = []
        self.rows = list(rows or [])
        self.one_values = list(one_values or [])
        self.lastrowid = lastrowid
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        if self.one_values:
            return self.one_values.pop(0)
        return None


class _FakeConnection:
    def __init__(self, cursor=None):
        self.fake_cursor = cursor or _FakeCursor()
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def _endpoint_row(endpoint_id, pool_kind):
    return {
        'id': endpoint_id,
        'competition_id': 17,
        'pool_kind': pool_kind,
        'harness': 'codex',
        'base_url': f'https://{pool_kind}.example/v1',
        'api_key': f'{pool_kind}-key',
        'model': 'gpt-test',
        'context_window_tokens': 128_000,
        'max_output_tokens': 16_000,
        'thinking_compatibility': 0,
        'concurrency_limit': 2,
        'enabled': 1,
        'status': 'enabled',
        'ordering': 0,
    }


def test_begin_reverse_attempt_switches_attempt_and_clears_steps_in_one_transaction(monkeypatch):
    cursor = _FakeCursor()
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(ranking_db.uuid, 'uuid4', lambda: 'attempt-new')

    attempt_id = ranking_db.begin_agent_judge_attempt(
        31,
        status='Queued',
        reset_result=True,
        clear_reverse_steps=True,
    )

    assert attempt_id == 'attempt-new'
    assert 'UPDATE ranking_submissions' in cursor.calls[0][0]
    assert cursor.calls[0][1] == ('Queued', 'attempt-new', 31)
    assert 'DELETE FROM ranking_reverse_judge_steps' in cursor.calls[1][0]
    assert cursor.calls[1][1] == (31,)
    assert conn.committed is True
    assert conn.rolled_back is False


def test_begin_reverse_attempt_rolls_back_attempt_when_step_clear_fails(monkeypatch):
    class FailingCursor(_FakeCursor):
        def execute(self, sql, params=None):
            super().execute(sql, params)
            if 'DELETE FROM ranking_reverse_judge_steps' in sql:
                raise RuntimeError('delete failed')

    conn = _FakeConnection(FailingCursor())
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    with pytest.raises(RuntimeError, match='delete failed'):
        ranking_db.begin_agent_judge_attempt(
            31,
            reset_result=True,
            clear_reverse_steps=True,
        )

    assert conn.committed is False
    assert conn.rolled_back is True


def test_delete_competition_removes_reverse_steps_and_endpoint_secrets(monkeypatch):
    cursor = _FakeCursor()
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    ranking_db.delete_competition(17)

    sqls = [' '.join(sql.split()) for sql, _params in cursor.calls]
    assert 'DELETE steps FROM ranking_reverse_judge_steps' in sqls[0]
    assert sqls[1].startswith('DELETE FROM ranking_agent_judge_endpoints')
    assert all(params == (17,) for _sql, params in cursor.calls)
    assert conn.committed is True


def test_list_endpoint_pools_use_distinct_pool_predicates(monkeypatch):
    primary_conn = _FakeConnection(_FakeCursor(rows=[_endpoint_row(1, 'primary')]))
    quality_conn = _FakeConnection(_FakeCursor(rows=[_endpoint_row(2, 'quality_gate')]))
    connections = iter([primary_conn, quality_conn])
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: next(connections))

    primary = endpoint_db.list_agent_judge_endpoints(17, enabled_only=True)
    quality = endpoint_db.list_quality_gate_endpoints(17, enabled_only=True)

    assert primary[0]['pool_kind'] == endpoint_db.ENDPOINT_POOL_PRIMARY
    assert quality[0]['pool_kind'] == endpoint_db.ENDPOINT_POOL_QUALITY_GATE
    assert primary[0]['context_window_tokens'] == 128_000
    assert primary[0]['max_output_tokens'] == 16_000
    assert primary[0]['thinking_compatibility'] is False
    for conn, expected_kind in (
        (primary_conn, endpoint_db.ENDPOINT_POOL_PRIMARY),
        (quality_conn, endpoint_db.ENDPOINT_POOL_QUALITY_GATE),
    ):
        sql, params = conn.fake_cursor.calls[0]
        assert "pool_kind = %s" in sql
        assert "status = 'enabled'" in sql
        assert params == (17, expected_kind)
        assert conn.closed is True


def test_list_paused_endpoints_preserves_pool_kind(monkeypatch):
    conn = _FakeConnection(_FakeCursor(rows=[_endpoint_row(9, 'quality_gate')]))
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: conn)

    rows = endpoint_db.list_paused_agent_judge_endpoints()

    assert rows[0]['pool_kind'] == endpoint_db.ENDPOINT_POOL_QUALITY_GATE
    sql, params = conn.fake_cursor.calls[0]
    assert 'pool_kind' in sql
    assert "status = 'paused'" in sql
    assert params is None


def test_save_primary_pool_scopes_key_inheritance_delete_and_update(monkeypatch):
    seen_pools = []

    def fake_list(competition_id, pool_kind, enabled_only=False):
        seen_pools.append((competition_id, pool_kind, enabled_only))
        return [{'id': 7, 'api_key': 'kept-secret', 'status': 'paused'}]

    conn = _FakeConnection()
    monkeypatch.setattr(endpoint_db, '_list_endpoints', fake_list)
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: conn)

    saved = endpoint_db.save_agent_judge_endpoints(17, [{
        'id': 7,
        'harness': 'codex',
        'base_url': 'https://primary.example/v1',
        'api_key': '',
        'model': 'gpt-test',
        'concurrency_limit': 3,
    }])

    assert seen_pools == [(17, endpoint_db.ENDPOINT_POOL_PRIMARY, False)]
    assert saved[0]['api_key'] == 'kept-secret'
    assert saved[0]['pool_kind'] == endpoint_db.ENDPOINT_POOL_PRIMARY
    delete_sql, delete_params = conn.fake_cursor.calls[0]
    update_sql, update_params = conn.fake_cursor.calls[1]
    assert 'pool_kind = %s' in delete_sql
    assert delete_params == (17, endpoint_db.ENDPOINT_POOL_PRIMARY, 7)
    assert 'pool_kind = %s' in update_sql
    assert 'context_window_tokens = %s' in update_sql
    assert 'max_output_tokens = %s' in update_sql
    assert 'thinking_compatibility = %s' in update_sql
    assert update_params[5:8] == (
        endpoint_db.DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS,
        endpoint_db.DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS,
        1,
    )
    assert update_params[-3:] == (7, 17, endpoint_db.ENDPOINT_POOL_PRIMARY)
    assert conn.committed is True


def test_save_primary_configuration_rolls_back_settings_when_endpoint_invalid(
        monkeypatch):
    cursor = _FakeCursor(one_values=[{'id': 17}])
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: conn)

    with pytest.raises(ValueError, match='不能超过上下文窗口'):
        endpoint_db.save_agent_judge_configuration(
            17,
            [{
                'harness': 'pi',
                'protocol': 'openai',
                'base_url': 'https://primary.example/v1',
                'api_key': 'secret',
                'model': 'model',
                'context_window_tokens': 10,
                'max_output_tokens': 11,
            }],
            timeout_seconds=7200,
            reverse_finalize_timeout_seconds=600,
            orchestration_mode='topology',
        )

    assert not any(
        'UPDATE ranking_competitions SET' in sql
        for sql, _params in cursor.calls
    )
    assert conn.committed is False
    assert conn.rolled_back is True


def test_save_primary_configuration_commits_endpoints_and_settings_together(
        monkeypatch):
    cursor = _FakeCursor(one_values=[{'id': 17}])
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: conn)

    saved = endpoint_db.save_agent_judge_configuration(
        17,
        [{
            'harness': 'pi',
            'protocol': 'anthropic',
            'base_url': 'https://primary.example/v1',
            'api_key': 'secret',
            'model': 'model',
        }],
        timeout_seconds=7200,
        reverse_finalize_timeout_seconds=600,
        orchestration_mode='topology',
    )

    assert saved[0]['harness'] == 'pi'
    assert saved[0]['protocol'] == 'anthropic'
    settings_sql, settings_params = next(
        (sql, params)
        for sql, params in cursor.calls
        if 'UPDATE ranking_competitions SET' in sql
    )
    assert 'agent_judge_timeout_seconds = %s' in settings_sql
    assert 'reverse_judge_finalize_timeout_seconds = %s' in settings_sql
    assert 'agent_judge_orchestration_mode = %s' in settings_sql
    assert settings_params == (7200, 600, 'topological', 17)
    assert conn.committed is True
    assert conn.rolled_back is False


def test_save_quality_gate_pool_scopes_delete_and_insert(monkeypatch):
    monkeypatch.setattr(endpoint_db, '_list_endpoints', lambda *_args, **_kwargs: [])
    conn = _FakeConnection()
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: conn)

    saved = endpoint_db.save_quality_gate_endpoints(17, [{
        'harness': 'codex',
        'base_url': 'https://quality.example/v1',
        'api_key': 'quality-secret',
        'model': 'gpt-test',
        'concurrency_limit': 4,
        'status': 'enabled',
    }])

    assert saved[0]['pool_kind'] == endpoint_db.ENDPOINT_POOL_QUALITY_GATE
    delete_sql, delete_params = conn.fake_cursor.calls[0]
    insert_sql, insert_params = conn.fake_cursor.calls[1]
    assert 'pool_kind = %s' in delete_sql
    assert delete_params == (17, endpoint_db.ENDPOINT_POOL_QUALITY_GATE)
    assert '(competition_id, pool_kind,' in insert_sql
    assert insert_params[:2] == (17, endpoint_db.ENDPOINT_POOL_QUALITY_GATE)
    assert insert_params[7:10] == (
        endpoint_db.DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS,
        endpoint_db.DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS,
        1,
    )


def test_endpoint_model_capability_defaults_and_existing_values_are_stable():
    assert endpoint_db.normalize_endpoint_model_capabilities({}) == {
        'context_window_tokens': 1_000_000,
        'max_output_tokens': 384_000,
        'thinking_compatibility': True,
    }
    existing = {
        'context_window_tokens': 262_144,
        'max_output_tokens': 65_536,
        'thinking_compatibility': False,
    }
    assert endpoint_db.normalize_endpoint_model_capabilities({}, existing) == existing


@pytest.mark.parametrize(
    'value, expected',
    [(True, True), (False, False), (1, True), (0, False),
     ('true', True), ('TRUE', True), ('1', True),
     ('false', False), ('FALSE', False), ('0', False)],
)
def test_endpoint_thinking_compatibility_strict_valid_values(value, expected):
    normalized = endpoint_db.normalize_endpoint_model_capabilities({
        'thinking_compatibility': value,
    })
    assert normalized['thinking_compatibility'] is expected


@pytest.mark.parametrize('value', [None, '', 'yes', 'off', 2, -1, 1.0, [], {}])
def test_endpoint_thinking_compatibility_rejects_ambiguous_values(value):
    with pytest.raises(ValueError, match='布尔值'):
        endpoint_db.normalize_endpoint_model_capabilities({
            'thinking_compatibility': value,
        })


@pytest.mark.parametrize(
    'field, value',
    [('context_window_tokens', 0), ('context_window_tokens', -1),
     ('context_window_tokens', True), ('context_window_tokens', '1.5'),
     ('max_output_tokens', 0), ('max_output_tokens', -1),
     ('max_output_tokens', False), ('max_output_tokens', None)],
)
def test_endpoint_model_token_limits_require_positive_integers(field, value):
    with pytest.raises(ValueError, match='正整数'):
        endpoint_db.normalize_endpoint_model_capabilities({field: value})


@pytest.mark.parametrize(
    'field', ['context_window_tokens', 'max_output_tokens'],
)
def test_endpoint_model_token_limits_reject_values_above_supported_contract(field):
    payload = {
        'context_window_tokens': endpoint_db.MAX_ENDPOINT_TOKEN_COUNT,
        'max_output_tokens': 1,
    }
    payload[field] = endpoint_db.MAX_ENDPOINT_TOKEN_COUNT + 1
    with pytest.raises(ValueError, match=str(endpoint_db.MAX_ENDPOINT_TOKEN_COUNT)):
        endpoint_db.normalize_endpoint_model_capabilities(payload)


def test_endpoint_max_output_cannot_exceed_context_window():
    with pytest.raises(ValueError, match='不能超过'):
        endpoint_db.normalize_endpoint_model_capabilities({
            'context_window_tokens': 8192,
            'max_output_tokens': 8193,
        })


@pytest.mark.parametrize('harness', ['claude_code', 'codex', 'pi', 'opencode'])
def test_endpoint_pool_rejects_context_above_global_harness_contract(harness):
    with pytest.raises(ValueError, match='1000000'):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_PRIMARY,
            [{
                'harness': harness,
                **({'protocol': 'openai'} if harness == 'pi' else {}),
                'base_url': 'https://model.example/v1',
                'api_key': 'secret',
                'model': 'model',
                'context_window_tokens': 1_000_001,
                'max_output_tokens': 384_000,
            }],
            [],
        )


def test_existing_endpoint_omitted_capabilities_survive_normalization():
    existing = _endpoint_row(7, endpoint_db.ENDPOINT_POOL_PRIMARY)
    normalized = endpoint_db._normalize_endpoint_items(
        endpoint_db.ENDPOINT_POOL_PRIMARY,
        [{
            'id': 7,
            'harness': 'codex',
            'base_url': 'https://primary.example/v1',
            'api_key': '',
            'model': 'gpt-test',
        }],
        [endpoint_db._endpoint_row(existing)],
    )

    assert normalized[0]['context_window_tokens'] == 128_000
    assert normalized[0]['max_output_tokens'] == 16_000
    assert normalized[0]['thinking_compatibility'] is False


def test_quality_gate_configuration_and_pool_share_one_transaction(monkeypatch):
    cursor = _FakeCursor(
        one_values=[{
            'reverse_quality_gate_enabled': 0,
            'reverse_quality_gate_prompt': '',
        }],
        rows=[_endpoint_row(7, endpoint_db.ENDPOINT_POOL_QUALITY_GATE)],
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: conn)

    result = endpoint_db.save_reverse_quality_gate_configuration(
        17,
        enabled=True,
        prompt='不得隐藏私有协议',
        endpoints=[{
            'id': 7,
            'harness': 'opencode',
            'base_url': 'https://quality.example/v1',
            'api_key': '',
            'model': 'gate-model',
            'concurrency_limit': 3,
            'status': 'enabled',
        }],
    )

    assert result == {
        'enabled': True,
        'prompt': '不得隐藏私有协议',
        'enabled_endpoint_count': 1,
    }
    assert conn.committed is True
    assert conn.rolled_back is False
    endpoint_update = next(
        (sql, params) for sql, params in cursor.calls
        if 'UPDATE ranking_agent_judge_endpoints' in sql
    )
    assert endpoint_update[1][3] == 'quality_gate-key'
    config_update = next(
        (sql, params) for sql, params in cursor.calls
        if 'UPDATE ranking_competitions SET' in sql
    )
    assert config_update[1] == (1, '不得隐藏私有协议', 17)
    assert sum('FOR UPDATE' in sql for sql, _params in cursor.calls) == 2
    locked_endpoint_select = next(
        sql for sql, _params in cursor.calls
        if 'FROM ranking_agent_judge_endpoints' in sql and 'FOR UPDATE' in sql
    )
    assert 'context_window_tokens' in locked_endpoint_select
    assert 'max_output_tokens' in locked_endpoint_select
    assert 'thinking_compatibility' in locked_endpoint_select


@pytest.mark.parametrize("endpoint, message", [
    ({
        "harness": "opencode",
        "base_url": "",
        "api_key": "secret",
        "model": "gate-model",
    }, "URL"),
    ({
        "harness": "claude_code",
        "base_url": "https://quality.example/anthropic",
        "api_key": "secret",
        "model": "",
    }, "模型"),
])
def test_quality_gate_pool_requires_explicit_url_and_model(endpoint, message):
    with pytest.raises(ValueError, match=message):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_QUALITY_GATE,
            [endpoint],
            [],
        )


def test_primary_opencode_pool_keeps_legacy_default_url_and_model():
    normalized = endpoint_db._normalize_endpoint_items(
        endpoint_db.ENDPOINT_POOL_PRIMARY,
        [{"harness": "opencode", "api_key": "secret"}],
        [],
    )

    assert normalized[0]["base_url"] == endpoint_db.DEFAULT_OPENCODE_GO_BASE_URL
    assert normalized[0]["model"] == endpoint_db.DEFAULT_OPENCODE_GO_MODEL


@pytest.mark.parametrize("value", ["pi", "pi-agent", "pi_agent", " PI-Agent "])
def test_pi_harness_aliases_normalize_to_canonical_value(value):
    assert endpoint_db.normalize_agent_harness(value) == endpoint_db.HARNESS_PI


def test_pi_endpoint_requires_explicit_model():
    with pytest.raises(ValueError, match='Pi 端点模型不能为空'):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_PRIMARY,
            [{
                'harness': 'pi',
                'protocol': 'openai',
                'base_url': 'https://pi.example/v1',
                'api_key': 'secret',
            }],
            [],
        )


def test_new_pi_endpoint_requires_explicit_protocol():
    with pytest.raises(ValueError, match='必须明确选择'):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_PRIMARY,
            [{
                'harness': 'pi',
                'base_url': 'https://pi.example/v1',
                'api_key': 'secret',
                'model': 'mimo-v2.5-pro',
            }],
            [],
        )


@pytest.mark.parametrize(
    'harness, expected',
    [
        ('claude_code', ('anthropic',)),
        ('codex', ('openai',)),
        ('opencode', ('openai',)),
        ('pi', ('openai', 'anthropic')),
    ],
)
def test_harness_protocol_matrix(harness, expected):
    assert endpoint_db.allowed_agent_endpoint_protocols(harness) == expected


@pytest.mark.parametrize(
    'harness, expected',
    [
        ('claude_code', 'anthropic'),
        ('codex', 'openai'),
        ('opencode', 'openai'),
        ('pi', 'openai'),
    ],
)
def test_legacy_null_protocol_inference(harness, expected):
    assert endpoint_db.infer_agent_endpoint_protocol(harness, None) == expected


def test_editing_legacy_endpoint_preserves_null_protocol():
    existing = endpoint_db._endpoint_row({
        **_endpoint_row(7, endpoint_db.ENDPOINT_POOL_PRIMARY),
        'harness': 'pi',
        'protocol': None,
    })
    normalized = endpoint_db._normalize_endpoint_items(
        endpoint_db.ENDPOINT_POOL_PRIMARY,
        [{
            'id': 7,
            'harness': 'pi',
            'base_url': 'https://primary.example/v1',
            'api_key': '',
            'model': 'legacy-model',
        }],
        [existing],
    )

    assert normalized[0]['protocol'] is None
    assert normalized[0]['effective_protocol'] == 'openai'


def test_existing_explicit_protocol_cannot_be_reused_by_incompatible_harness():
    existing = endpoint_db._endpoint_row({
        **_endpoint_row(7, endpoint_db.ENDPOINT_POOL_PRIMARY),
        'harness': 'pi',
        'protocol': 'anthropic',
    })
    with pytest.raises(ValueError, match='codex 不支持 anthropic'):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_PRIMARY,
            [{
                'id': 7,
                'harness': 'codex',
                'base_url': 'https://primary.example/v1',
                'api_key': '',
                'model': 'model',
            }],
            [existing],
        )


def test_global_endpoint_copy_uses_server_secret_and_protocol(monkeypatch):
    monkeypatch.setattr(
        endpoint_db,
        '_get_global_endpoint_for_copy',
        lambda endpoint_id: {
            'id': endpoint_id,
            'category': 'text',
            'protocol': 'anthropic',
            'base_url': 'https://global.example/anthropic',
            'api_key': 'server-only-secret',
            'model': 'mimo-v2.5-pro',
            'thinking_enabled': True,
            'thinking_format': 'thinking_type',
        },
    )

    normalized = endpoint_db._normalize_endpoint_items(
        endpoint_db.ENDPOINT_POOL_PRIMARY,
        [{
            'harness': 'pi',
            'global_endpoint_id': 23,
            'concurrency_limit': 2,
        }],
        [],
    )

    assert normalized[0]['protocol'] == 'anthropic'
    assert normalized[0]['base_url'] == 'https://global.example/anthropic'
    assert normalized[0]['api_key'] == 'server-only-secret'
    assert normalized[0]['model'] == 'mimo-v2.5-pro'
    assert normalized[0]['thinking_compatibility'] is True
    assert normalized[0]['thinking_format'] == 'thinking_type'
    assert 'global_endpoint_id' not in normalized[0]


def test_editing_copied_endpoint_preserves_frozen_thinking_format(monkeypatch):
    def should_not_read_global(_endpoint_id):
        raise AssertionError('编辑独立副本不应重新读取全局端点')

    monkeypatch.setattr(
        endpoint_db, '_get_global_endpoint_for_copy', should_not_read_global,
    )
    existing = endpoint_db._endpoint_row({
        **_endpoint_row(7, endpoint_db.ENDPOINT_POOL_PRIMARY),
        'harness': 'pi',
        'protocol': 'openai',
        'thinking_compatibility': 1,
        'thinking_format': 'enable_thinking',
    })

    normalized = endpoint_db._normalize_endpoint_items(
        endpoint_db.ENDPOINT_POOL_PRIMARY,
        [{
            'id': 7,
            'harness': 'pi',
            'protocol': 'openai',
            'base_url': 'https://independent.example/v1',
            'api_key': '',
            'model': 'independent-model',
        }],
        [existing],
    )

    assert normalized[0]['thinking_format'] == 'enable_thinking'


def test_editing_copied_endpoint_rejects_protocol_incompatible_frozen_thinking():
    existing = endpoint_db._endpoint_row({
        **_endpoint_row(7, endpoint_db.ENDPOINT_POOL_PRIMARY),
        'harness': 'pi',
        'protocol': 'openai',
        'thinking_compatibility': 1,
        'thinking_format': 'enable_thinking',
    })

    with pytest.raises(ValueError, match='Anthropic.*enable_thinking'):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_PRIMARY,
            [{
                'id': 7,
                'harness': 'claude_code',
                'protocol': 'anthropic',
                'base_url': 'https://independent.example/anthropic',
                'api_key': '',
                'model': 'independent-model',
            }],
            [existing],
        )


def test_legacy_endpoint_row_keeps_null_thinking_format():
    endpoint = endpoint_db._endpoint_row({
        **_endpoint_row(7, endpoint_db.ENDPOINT_POOL_PRIMARY),
        'thinking_format': None,
    })

    assert endpoint['thinking_format'] is None


def test_global_endpoint_copy_rejects_incompatible_harness(monkeypatch):
    monkeypatch.setattr(
        endpoint_db,
        '_get_global_endpoint_for_copy',
        lambda _endpoint_id: {
            'id': 23,
            'category': 'text',
            'protocol': 'anthropic',
            'base_url': 'https://global.example/anthropic',
            'api_key': 'secret',
            'model': 'model',
        },
    )

    with pytest.raises(ValueError, match='codex 不支持'):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_PRIMARY,
            [{'harness': 'codex', 'global_endpoint_id': 23}],
            [],
        )


def test_global_endpoint_candidates_filter_protocol_category_and_secrets():
    endpoints = [
        {
            'id': 1, 'category': 'text',
            'protocol': 'anthropic', 'base_url': 'https://a.example',
            'api_key': 'must-not-leak', 'model': 'a',
        },
        {
            'id': 2, 'category': 'omni',
            'protocol': 'openai', 'base_url': 'https://o.example',
            'api_key': 'must-not-leak', 'model': 'o',
        },
        {
            'id': 3, 'category': 'vision',
            'protocol': 'openai', 'base_url': 'https://v.example',
            'api_key': 'must-not-leak', 'model': 'v',
        },
    ]

    pi = endpoint_db.list_global_endpoints_for_agent_harness('pi', endpoints=endpoints)
    codex = endpoint_db.list_global_endpoints_for_agent_harness('codex', endpoints=endpoints)
    opencode = endpoint_db.list_global_endpoints_for_agent_harness('opencode', endpoints=endpoints)

    assert [item['id'] for item in pi] == [1, 2]
    assert [item['id'] for item in codex] == [2]
    assert opencode == []
    assert all('api_key' not in item for item in pi + codex)
    assert all('name' not in item for item in pi + codex)


@pytest.mark.parametrize("value", [None, "", "unknown-agent"])
def test_unknown_or_empty_harness_keeps_claude_code_fallback(value):
    assert (
        endpoint_db.normalize_agent_harness(value)
        == endpoint_db.HARNESS_CLAUDE_CODE
    )


def test_endpoint_api_key_rejects_header_control_characters():
    with pytest.raises(ValueError, match="控制字符"):
        endpoint_db._normalize_endpoint_items(
            endpoint_db.ENDPOINT_POOL_QUALITY_GATE,
            [{
                "harness": "codex",
                "base_url": "https://quality.example/v1",
                "api_key": "secret\r\nX-Injected: yes",
                "model": "gate-model",
            }],
            [],
        )


def test_quality_gate_atomic_save_rolls_back_endpoint_writes_when_config_fails(monkeypatch):
    class FailingCursor(_FakeCursor):
        def execute(self, sql, params=None):
            super().execute(sql, params)
            if 'UPDATE ranking_competitions SET' in sql:
                raise RuntimeError('config write failed')

    cursor = FailingCursor(
        one_values=[{
            'reverse_quality_gate_enabled': 0,
            'reverse_quality_gate_prompt': '',
        }],
        rows=[],
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(endpoint_db, 'get_db_connection', lambda: conn)

    with pytest.raises(RuntimeError, match='config write failed'):
        endpoint_db.save_reverse_quality_gate_configuration(
            17,
            enabled=True,
            prompt='审核标准',
            endpoints=[{
                'harness': 'codex',
                'base_url': 'https://quality.example/v1',
                'api_key': 'secret',
                'model': 'gate-model',
                'status': 'enabled',
            }],
        )

    assert any('INSERT INTO ranking_agent_judge_endpoints' in sql for sql, _ in cursor.calls)
    assert conn.committed is False
    assert conn.rolled_back is True


def test_save_primary_pool_cannot_inherit_key_from_another_pool(monkeypatch):
    requested_pools = []

    def fake_list(_competition_id, pool_kind, enabled_only=False):
        requested_pools.append((pool_kind, enabled_only))
        return []

    monkeypatch.setattr(endpoint_db, '_list_endpoints', fake_list)

    with pytest.raises(ValueError, match='新端点必须填写 API Key'):
        endpoint_db.save_agent_judge_endpoints(17, [{
            'id': 88,
            'harness': 'codex',
            'base_url': 'https://primary.example/v1',
            'api_key': '',
            'model': 'gpt-test',
        }])

    assert requested_pools == [(endpoint_db.ENDPOINT_POOL_PRIMARY, False)]


def test_competition_get_and_update_include_quality_gate_fields(monkeypatch):
    get_conn = _FakeConnection(_FakeCursor(one_values=[{
        'id': 17,
        'reverse_quality_gate_enabled': 1,
        'reverse_quality_gate_prompt': '不得隐藏私有协议',
    }]))
    update_conn = _FakeConnection()
    connections = iter([get_conn, update_conn])
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: next(connections))

    comp = ranking_db.get_competition(17)
    ranking_db.update_competition(
        17,
        reverse_quality_gate_enabled=True,
        reverse_quality_gate_prompt='不得隐藏私有协议',
    )

    get_sql, get_params = get_conn.fake_cursor.calls[0]
    assert 'reverse_quality_gate_enabled' in get_sql
    assert 'reverse_quality_gate_prompt' in get_sql
    assert get_params == (17,)
    assert comp['reverse_quality_gate_enabled'] == 1
    update_sql, update_params = update_conn.fake_cursor.calls[0]
    assert 'reverse_quality_gate_enabled = %s' in update_sql
    assert 'reverse_quality_gate_prompt = %s' in update_sql
    assert update_params == (1, '不得隐藏私有协议', 17)
    assert update_conn.committed is True


class _CopyCursor(_FakeCursor):
    def __init__(self):
        super().__init__(lastrowid=101)
        self._current_one = None
        self._current_rows = []

    def execute(self, sql, params=None):
        super().execute(sql, params)
        if 'SELECT * FROM ranking_competitions' in sql:
            self._current_one = {
                'id': 17,
                'title': '源比赛',
                'is_active': 1,
                'created_by': 'old-admin',
                'reverse_quality_gate_enabled': 1,
                'reverse_quality_gate_prompt': '质量标准',
                'created_at': 'old-created',
                'updated_at': 'old-updated',
            }
            self._current_rows = []
        elif 'FROM ranking_judge_rules' in sql or 'FROM ranking_competition_files' in sql:
            self._current_one = None
            self._current_rows = []
        elif 'FROM ranking_agent_judge_endpoints' in sql:
            self._current_one = None
            self._current_rows = [{
                'pool_kind': 'quality_gate',
                'harness': 'codex',
                'protocol': 'openai',
                'base_url': 'https://quality.example/v1',
                'api_key': 'quality-secret',
                'model': 'gpt-test',
                'context_window_tokens': 524288,
                'max_output_tokens': 131072,
                'thinking_compatibility': 0,
                'thinking_format': 'none',
                'concurrency_limit': 2,
                'enabled': 1,
                'status': 'enabled',
                'ordering': 0,
            }]
        else:
            self._current_one = None
            self._current_rows = []

    def fetchone(self):
        return self._current_one

    def fetchall(self):
        return list(self._current_rows)


def test_copy_competition_preserves_quality_config_and_endpoint_pool(monkeypatch):
    conn = _FakeConnection(_CopyCursor())
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    new_id = ranking_db.copy_competition(17, created_by='new-admin')

    assert new_id == 101
    competition_insert = next(
        call for call in conn.fake_cursor.calls
        if 'INSERT INTO ranking_competitions' in call[0]
    )
    competition_sql, competition_params = competition_insert
    assert '`reverse_quality_gate_enabled`' in competition_sql
    assert '`reverse_quality_gate_prompt`' in competition_sql
    assert '质量标准' in competition_params
    endpoint_insert = next(
        call for call in conn.fake_cursor.calls
        if 'INSERT INTO ranking_agent_judge_endpoints' in call[0]
    )
    endpoint_sql, endpoint_params = endpoint_insert
    assert '(competition_id, pool_kind,' in endpoint_sql
    assert endpoint_params[:2] == (101, endpoint_db.ENDPOINT_POOL_QUALITY_GATE)
    assert endpoint_params[3] == 'openai'
    assert endpoint_params[7:11] == (524288, 131072, 0, 'none')
    assert conn.committed is True


def test_submission_endpoint_sql_never_falls_back_to_quality_gate(monkeypatch):
    snapshot_cursor = _FakeCursor(one_values=[{'harness': 'codex', 'model': 'gpt-test'}])
    snapshot = ranking_db._agent_endpoint_snapshot_with_cursor(snapshot_cursor, 17, 8)
    snapshot_sql, snapshot_params = snapshot_cursor.calls[0]
    assert snapshot == ('codex', 'gpt-test')
    assert "pool_kind = 'primary'" in snapshot_sql
    assert snapshot_params == (8, 17)

    invocations = (
        lambda: ranking_db.list_user_submissions(17, 'alice'),
        lambda: ranking_db.list_all_submissions(17),
        lambda: ranking_db.get_leaderboard(17),
    )
    for invoke in invocations:
        conn = _FakeConnection(_FakeCursor(one_values=[{'total': 0}]))
        monkeypatch.setattr(ranking_db, 'get_db_connection', lambda conn=conn: conn)
        invoke()
        endpoint_sql = next(
            sql for sql, _params in conn.fake_cursor.calls
            if 'JOIN ranking_agent_judge_endpoints' in sql
        )
        assert "ep.pool_kind = 'primary'" in endpoint_sql


def test_list_user_submissions_selects_current_attempt_and_returns_labeled_rows(
        monkeypatch):
    row = {
        'id': 31,
        'judge_attempt_id': 'attempt-2',
        'agent_endpoint_harness': 'codex',
        'agent_endpoint_model': 'deepseek-v4-flash',
    }
    cursor = _FakeCursor(rows=[row])
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    rows = ranking_db.list_user_submissions(17, 'alice')

    sql, params = cursor.calls[0]
    normalized_sql = ' '.join(sql.split())
    assert 's.judge_attempt_id' in normalized_sql
    assert "ep.pool_kind = 'primary'" in normalized_sql
    assert params == (17, 'alice')
    assert rows[0]['judge_attempt_id'] == 'attempt-2'
    assert rows[0]['agent_endpoint_label'] == 'Codex (deepseek-v4-flash)'
    assert conn.closed is True


def test_list_all_submissions_paginated_search_selects_current_attempt(
        monkeypatch):
    row = {
        'id': 32,
        'judge_attempt_id': 'attempt-3',
        'agent_endpoint_harness': 'codex',
        'agent_endpoint_model': 'deepseek-v4-flash',
    }
    cursor = _FakeCursor(rows=[row], one_values=[{'total': 3}])
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: conn)

    rows, page, total = ranking_db.list_all_submissions(
        17, page=99, per_page=2, username_q=' alice ',
    )

    assert len(cursor.calls) == 2
    count_sql, count_params = cursor.calls[0]
    select_sql, select_params = cursor.calls[1]
    normalized_select = ' '.join(select_sql.split())
    assert 's.judge_attempt_id' in normalized_select
    assert "ep.pool_kind = 'primary'" in normalized_select
    assert count_params == (17, '%alice%')
    assert select_params == (17, '%alice%', 2, 2)
    assert rows[0]['judge_attempt_id'] == 'attempt-3'
    assert rows[0]['agent_endpoint_label'] == 'Codex (deepseek-v4-flash)'
    assert (page, total) == (2, 3)
    assert conn.closed is True
