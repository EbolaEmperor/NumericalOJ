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
