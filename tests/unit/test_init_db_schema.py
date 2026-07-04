# -*- coding: utf-8 -*-


def test_problem_test_code_schema_definition_is_longtext():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    assert specs["problems"].columns["test_code"].lower() == "longtext"
    assert init_db_schema._column_needs_type_change("text", "longtext") is True
    assert init_db_schema._column_needs_type_change("longtext", "longtext") is False
