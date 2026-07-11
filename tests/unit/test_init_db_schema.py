# -*- coding: utf-8 -*-


def test_problem_test_code_schema_definition_is_longtext():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    assert specs["problems"].columns["test_code"].lower() == "longtext"
    assert init_db_schema._column_needs_type_change("text", "longtext") is True
    assert init_db_schema._column_needs_type_change("longtext", "longtext") is False


def test_plagiarism_records_schema_has_lookup_indexes():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    spec = specs["plagiarism_records"]
    assert spec.columns["comparison_rule"].lower() == "varchar(64) not null"
    assert "idx_plagiarism_username" in spec.indexes
    assert "idx_plagiarism_class" in spec.indexes
    assert "uniq_plagiarism_record" in spec.indexes


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
    assert "idx_aje_comp_pool" in endpoints.indexes
    assert "(`competition_id`,`pool_kind`)" in endpoints.indexes["idx_aje_comp_pool"]
