# -*- coding: utf-8 -*-

import pytest

from oj_modules.problem_llm_bindings import (
    CODE_GENERATION_ENDPOINT_ID,
    DIRECT_IMAGE_GRADING_ENDPOINT_ID,
    OCR_ENDPOINT_ID,
    OUTPUT_IMAGE_GRADING_ENDPOINT_ID,
    REVIEW_ENDPOINT_ID,
    TEXT_GRADING_ENDPOINT_ID,
    ProblemLlmBindingsError,
    build_problem_llm_endpoint_candidates,
    deserialize_problem_llm_bindings,
    normalize_problem_llm_bindings,
    problem_llm_bindings_from_form,
    serialize_problem_llm_bindings,
)


@pytest.mark.parametrize(
    ("problem_type", "mode", "bindings"),
    [
        (1, 1, {OUTPUT_IMAGE_GRADING_ENDPOINT_ID: 11}),
        (1, 2, {OUTPUT_IMAGE_GRADING_ENDPOINT_ID: "12"}),
        (
            1,
            3,
            {REVIEW_ENDPOINT_ID: 13, CODE_GENERATION_ENDPOINT_ID: "14"},
        ),
        (
            2,
            1,
            {
                OCR_ENDPOINT_ID: 15,
                TEXT_GRADING_ENDPOINT_ID: 16,
                DIRECT_IMAGE_GRADING_ENDPOINT_ID: 17,
            },
        ),
    ],
)
def test_normalize_problem_llm_bindings_accepts_only_current_kind(
    problem_type, mode, bindings
):
    normalized = normalize_problem_llm_bindings(
        bindings,
        problem_type=problem_type,
        programming_grading_mode=mode,
    )
    assert normalized == {key: int(value) for key, value in bindings.items()}


@pytest.mark.parametrize(
    ("problem_type", "mode", "bindings"),
    [
        (1, 1, {OCR_ENDPOINT_ID: 1}),
        (1, 3, {OUTPUT_IMAGE_GRADING_ENDPOINT_ID: 1}),
        (2, 1, {REVIEW_ENDPOINT_ID: 1}),
        (2, 1, {"unknown_endpoint_id": 1}),
    ],
)
def test_normalize_problem_llm_bindings_rejects_unknown_key_for_kind(
    problem_type, mode, bindings
):
    with pytest.raises(ProblemLlmBindingsError, match="当前题型不允许"):
        normalize_problem_llm_bindings(
            bindings,
            problem_type=problem_type,
            programming_grading_mode=mode,
        )


@pytest.mark.parametrize("bad_value", [True, 0, -1, 1.5, "1.0", "abc", [], {}])
def test_normalize_problem_llm_bindings_rejects_non_positive_integer_id(bad_value):
    with pytest.raises(ProblemLlmBindingsError, match="正整数"):
        normalize_problem_llm_bindings(
            {OUTPUT_IMAGE_GRADING_ENDPOINT_ID: bad_value},
            problem_type=1,
            programming_grading_mode=1,
        )


def test_problem_binding_id_uses_same_signed_bigint_range_as_endpoint_table():
    maximum = 9_223_372_036_854_775_807
    assert normalize_problem_llm_bindings(
        {OUTPUT_IMAGE_GRADING_ENDPOINT_ID: maximum},
        problem_type=1,
    ) == {OUTPUT_IMAGE_GRADING_ENDPOINT_ID: maximum}
    with pytest.raises(ProblemLlmBindingsError, match="正整数"):
        normalize_problem_llm_bindings(
            {OUTPUT_IMAGE_GRADING_ENDPOINT_ID: maximum + 1},
            problem_type=1,
        )


def test_null_and_blank_ids_remove_binding_and_empty_serializes_to_sql_null():
    normalized = normalize_problem_llm_bindings(
        {
            OCR_ENDPOINT_ID: None,
            TEXT_GRADING_ENDPOINT_ID: "  ",
            DIRECT_IMAGE_GRADING_ENDPOINT_ID: 9,
        },
        problem_type=2,
    )
    assert normalized == {DIRECT_IMAGE_GRADING_ENDPOINT_ID: 9}
    assert serialize_problem_llm_bindings({}) is None


def test_json_round_trip_is_stable():
    bindings = {REVIEW_ENDPOINT_ID: 22, CODE_GENERATION_ENDPOINT_ID: 23}
    serialized = serialize_problem_llm_bindings(bindings)
    assert deserialize_problem_llm_bindings(serialized) == bindings


def test_form_without_binding_fields_preserves_existing_dangling_id():
    existing = {TEXT_GRADING_ENDPOINT_ID: 987654}
    assert problem_llm_bindings_from_form(
        {"title": "只改标题"},
        problem_type=2,
        existing=existing,
    ) == existing


def test_form_individual_fields_replace_current_kind_bindings():
    result = problem_llm_bindings_from_form(
        {
            OCR_ENDPOINT_ID: "31",
            TEXT_GRADING_ENDPOINT_ID: "",
            DIRECT_IMAGE_GRADING_ENDPOINT_ID: "32",
        },
        problem_type=2,
        existing={TEXT_GRADING_ENDPOINT_ID: 99},
    )
    assert result == {
        OCR_ENDPOINT_ID: 31,
        DIRECT_IMAGE_GRADING_ENDPOINT_ID: 32,
    }


def test_candidates_are_grouped_by_usage_without_secret_fields():
    candidates = build_problem_llm_endpoint_candidates(
        [
            {
                "id": 1,
                "name": "多模态",
                "protocol": "openai",
                "category": "omni",
                "model": "omni-model",
                "api_key": "never expose",
            },
            {
                "id": 2,
                "name": "文本",
                "protocol": "anthropic",
                "category": "text",
                "model": "text-model",
            },
            {
                "id": 3,
                "name": "视觉",
                "protocol": "anthropic",
                "category": "vision",
                "model": "vision-model",
            },
            {
                "id": 4,
                "name": "向量",
                "protocol": "openai",
                "category": "embedding",
                "model": "embedding-model",
            },
        ]
    )

    assert [item["id"] for item in candidates[TEXT_GRADING_ENDPOINT_ID]] == [1, 2]
    assert [item["id"] for item in candidates[OCR_ENDPOINT_ID]] == [1, 3]
    assert all(
        "api_key" not in endpoint
        for grouped in candidates.values()
        for endpoint in grouped
    )
