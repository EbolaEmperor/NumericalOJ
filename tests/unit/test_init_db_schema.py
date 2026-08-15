# -*- coding: utf-8 -*-

from collections import OrderedDict
from types import SimpleNamespace


def test_problem_test_code_schema_definition_is_longtext():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    assert specs["problems"].columns["test_code"].lower() == "longtext"
    assert init_db_schema._column_needs_type_change("text", "longtext") is True
    assert init_db_schema._column_needs_type_change("longtext", "longtext") is False


def test_class_table_schema_has_persistent_logo_seed():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()

    assert specs["class_table"].columns["logo_seed"].lower() == (
        "char(32) default null"
    )


def test_class_membership_schema_has_no_primary_or_user_snapshot_columns():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()

    assert "class" not in specs["users"].columns
    assert "class_cn" not in specs["users"].columns
    assert "is_primary" not in specs["user_class_map"].columns
    assert "idx_primary" not in specs["user_class_map"].indexes

    bootstrap = init_db_schema.DATABASE_BOOTSTRAP_SQL.read_text(
        encoding="utf-8",
    )
    assert "'Cadmin'" not in bootstrap


def test_plagiarism_records_schema_has_lookup_indexes():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    spec = specs["plagiarism_records"]
    assert spec.columns["comparison_rule"].lower() == "varchar(64) not null"
    assert "idx_plagiarism_username" in spec.indexes
    assert "idx_plagiarism_class" in spec.indexes
    assert "uniq_plagiarism_record" in spec.indexes


def test_forum_identity_and_editing_schema_is_fully_declared():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    anonymous = specs["forum_anonymous_identities"]
    settings = specs["forum_user_identity_settings"]
    threads = specs["forum_threads"]
    replies = specs["forum_replies"]
    thread_revisions = specs["forum_thread_revisions"]
    reply_revisions = specs["forum_reply_revisions"]
    create_receipts = specs["forum_create_operation_receipts"]
    edit_receipts = specs["forum_edit_operation_receipts"]
    identity_receipts = specs["forum_identity_operation_receipts"]

    assert "collate utf8mb4_bin" in anonymous.columns["normalized_name"].lower()
    assert "uq_forum_anonymous_normalized_name" in anonymous.indexes
    assert (
        anonymous.indexes["uq_forum_anonymous_identity_owner"].lower()
        == "unique key `uq_forum_anonymous_identity_owner` (`user_id`,`id`)"
    )
    assert settings.columns["use_anonymous"].lower() == (
        "tinyint(1) not null default '0'"
    )
    assert "current_anonymous_identity_id" in settings.columns
    assert "identity_changed_at" in settings.columns

    for spec in (threads, replies):
        assert spec.columns["anonymous_identity_id"].lower() == "bigint default null"
        assert spec.columns["edit_version"].lower() == "int not null default '1'"
        assert "client_request_id" in spec.columns
        assert spec.columns["content"].lower() == "mediumtext not null"

    assert thread_revisions.columns["content"].lower() == "mediumtext not null"
    assert reply_revisions.columns["content"].lower() == "mediumtext not null"

    assert "uq_forum_threads_user_request" in threads.indexes
    assert "uq_forum_replies_user_request" in replies.indexes
    assert "uq_forum_thread_revision_version" in thread_revisions.indexes
    assert "uq_forum_reply_revision_version" in reply_revisions.indexes
    assert "uq_forum_create_operation_request" in create_receipts.indexes
    assert "request_fingerprint" in create_receipts.columns
    assert "result_id" in create_receipts.columns
    assert "uq_forum_edit_operation_request" in edit_receipts.indexes
    assert "request_fingerprint" in edit_receipts.columns
    assert "result_version" in edit_receipts.columns
    assert "uq_forum_identity_operation_request" in identity_receipts.indexes
    assert "requested_enable" in identity_receipts.columns
    assert (
        threads.indexes["idx_forum_threads_identity_owner"].lower()
        == "key `idx_forum_threads_identity_owner` (`user_id`,`anonymous_identity_id`)"
    )
    assert (
        replies.indexes["idx_forum_replies_identity_owner"].lower()
        == "key `idx_forum_replies_identity_owner` (`user_id`,`anonymous_identity_id`)"
    )
    assert (
        settings.indexes["idx_forum_settings_identity_owner"].lower()
        == "key `idx_forum_settings_identity_owner` (`user_id`,`current_anonymous_identity_id`)"
    )
    assert (
        identity_receipts.indexes["idx_forum_identity_operation_owner"].lower()
        == "key `idx_forum_identity_operation_owner` (`user_id`,`anonymous_identity_id`)"
    )

    bootstrap = init_db_schema.DATABASE_BOOTSTRAP_SQL.read_text(
        encoding="utf-8"
    )
    compact = " ".join(bootstrap.lower().split())
    for constraint in (
        "fk_forum_threads_identity_owner",
        "fk_forum_replies_identity_owner",
        "fk_forum_settings_identity_owner",
        "fk_forum_identity_operation_owner",
    ):
        assert (
            f"constraint `{constraint}` foreign key" in compact
        )
    assert compact.count(
        "references `forum_anonymous_identities` (`user_id`,`id`) "
        "on delete restrict on update restrict"
    ) == 4


def test_reverse_quality_gate_schema_has_config_and_isolated_endpoint_pool():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    competition = specs["ranking_competitions"]
    endpoints = specs["ranking_agent_judge_endpoints"]

    assert competition.columns["reverse_quality_gate_enabled"].lower() == (
        "tinyint(1) not null default '0'"
    )
    assert competition.columns["reverse_quality_gate_prompt"].lower() == "mediumtext"
    assert endpoints.columns["pool_kind"].lower() == (
        "varchar(32) not null default 'primary'"
    )
    assert endpoints.columns["context_window_tokens"].lower() == (
        "int not null default '1000000'"
    )
    assert endpoints.columns["max_output_tokens"].lower() == (
        "int not null default '384000'"
    )
    assert endpoints.columns["thinking_compatibility"].lower() == (
        "tinyint(1) not null default '1'"
    )
    assert "idx_aje_comp_pool" in endpoints.indexes
    assert "(`competition_id`,`pool_kind`)" in endpoints.indexes["idx_aje_comp_pool"]


def test_dynamic_site_config_schema_is_fully_declared():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()

    assert specs["problems"].columns["llm_endpoint_bindings"].lower() == (
        "json default null"
    )
    assert specs["ranking_agent_judge_endpoints"].columns["protocol"].lower() == (
        "varchar(16) default null"
    )
    assert specs["ranking_agent_judge_endpoints"].columns["thinking_format"].lower() == (
        "varchar(32) default null"
    )
    for table in (
        "llm_endpoints",
        "llm_feature_bindings",
        "dynamic_config_test_grants",
        "site_mail_settings",
        "site_web_search_settings",
    ):
        assert table in specs

    endpoints = specs["llm_endpoints"]
    assert endpoints.columns["protocol"].lower() == "varchar(16) not null"
    assert endpoints.columns["thinking_format"].lower() == (
        "varchar(32) not null default 'none'"
    )
    for price_field in (
        "input_price_per_million",
        "cached_input_price_per_million",
        "output_price_per_million",
    ):
        assert endpoints.columns[price_field].lower() == "decimal(20,8) not null"
    assert "name" not in endpoints.columns
    assert endpoints.columns["model"].lower() == "varchar(255) not null"
    assert endpoints.columns["context_window_tokens"].lower() == (
        "int not null default '384000'"
    )
    assert endpoints.columns["max_output_tokens"].lower() == (
        "int not null default '32000'"
    )
    assert "uq_llm_endpoint_name" not in endpoints.indexes
    assert "uq_llm_endpoint_model" not in endpoints.indexes
    assert (
        endpoints.indexes["idx_llm_endpoint_model"].lower()
        == "key `idx_llm_endpoint_model` (`model`)"
    )

    grants = specs["dynamic_config_test_grants"]
    assert grants.columns["token_hash"].lower() == "char(64) not null"
    assert "uq_dynamic_config_test_token" in grants.indexes



def test_agent_task_run_schema_declares_endpoint_snapshot():
    from scripts import init_db_schema

    agent_runs = init_db_schema._load_schema_specs()["agent_task_runs"]
    assert agent_runs.columns["harness"].lower() == "varchar(32) default null"
    assert agent_runs.columns["endpoint_id"].lower() == "bigint default null"
    assert agent_runs.columns["endpoint_model"].lower() == (
        "varchar(255) default null"
    )
    assert agent_runs.columns["context_window_tokens"].lower() == (
        "int default null"
    )
    assert agent_runs.columns["max_output_tokens"].lower() == "int default null"


def test_agent_session_turn_schema_declares_retry_lineage_and_runtime_base():
    from scripts import init_db_schema

    turns = init_db_schema._load_schema_specs()["agent_session_turns"]

    assert turns.columns["base_runtime_checkpoint_id"].lower() == (
        "varchar(64) default null"
    )
    assert turns.columns["base_native_session_id"].lower() == (
        "varchar(128) default null"
    )
    assert turns.columns["retry_of_task_id"].lower() == (
        "varchar(64) default null"
    )
    assert turns.columns["superseded_by_task_id"].lower() == (
        "varchar(64) default null"
    )
    assert turns.columns["superseded_at"].lower() == "datetime default null"
    assert "idx_agent_turns_session_visible" in turns.indexes
    assert "idx_agent_turns_retry_of" in turns.indexes
    assert "idx_agent_turns_superseded_by" in turns.indexes


def test_agent_session_queue_schema_is_additive_and_indexed():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    sessions = specs["agent_sessions"]
    messages = specs["agent_session_messages"]

    assert sessions.columns["reasoning_effort"].lower() == (
        "varchar(16) not null default 'default'"
    )
    assert sessions.columns["queue_paused"].lower() == (
        "tinyint(1) not null default '0'"
    )
    assert sessions.columns["queue_pause_reason"].lower() == "text"
    assert sessions.columns["fresh_native_session_pending"].lower() == (
        "tinyint(1) not null default '0'"
    )
    assert messages.columns["delivery_mode"].lower() == "varchar(16) not null"
    assert messages.columns["status"].lower() == (
        "varchar(16) not null default 'queued'"
    )
    assert messages.columns["dispatch_payload_json"].lower() == "longtext"
    assert messages.columns["dispatch_attempt_id"].lower() == (
        "varchar(64) default null"
    )
    assert messages.columns["dispatch_attempted_at"].lower() == (
        "datetime default null"
    )
    assert messages.columns["broker_enqueued_at"].lower() == (
        "datetime default null"
    )
    assert "uniq_agent_message_id" in messages.indexes
    assert "uniq_agent_message_final_task" in messages.indexes
    assert "idx_agent_messages_session_queue" in messages.indexes
    assert "idx_agent_messages_delivery_status" in messages.indexes
    assert "idx_agent_messages_dispatch_recovery" in messages.indexes


def test_empty_database_dry_run_plans_full_schema_without_connecting_to_it(monkeypatch):
    from scripts import init_db_schema

    specs = OrderedDict(
        [
            (
                "users",
                init_db_schema.TableSpec(
                    name="users",
                    create_sql="CREATE TABLE `users` (`id` INT PRIMARY KEY) ENGINE=InnoDB",
                ),
            )
        ]
    )
    monkeypatch.setattr(init_db_schema, "_load_config", lambda: SimpleNamespace(MYSQL_DB="empty_db"))
    monkeypatch.setattr(init_db_schema, "_load_schema_specs", lambda: specs)

    def fake_ensure(_config, dry_run, actions):
        assert dry_run is True
        actions.append("CREATE DATABASE IF NOT EXISTS `empty_db`")
        return False

    monkeypatch.setattr(init_db_schema, "_ensure_database", fake_ensure)
    monkeypatch.setattr(
        init_db_schema,
        "_connect",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("dry-run must not connect to an absent database")
        ),
    )

    actions = init_db_schema.init_schema(dry_run=True)

    assert actions == [
        "CREATE DATABASE IF NOT EXISTS `empty_db`",
        "USE `empty_db`",
        "SET FOREIGN_KEY_CHECKS=0",
        specs["users"].create_sql,
        "SET FOREIGN_KEY_CHECKS=1",
    ]
