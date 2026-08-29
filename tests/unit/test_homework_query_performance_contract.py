from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_student_homework_query_avoids_redundant_ranking_aggregation():
    source = (ROOT / "oj_modules/problems/catalog.py").read_text(encoding="utf-8")
    score_query_source = source.split(
        "def _get_homeworks_for_classes", 1,
    )[1].split("def get_class_grades_map", 1)[0]

    assert "SELECT competition_id, MAX(score) AS rk_best" not in score_query_source
    assert "LEFT JOIN max_score" not in score_query_source
    assert "LEFT JOIN ac_record" not in score_query_source
    assert "ORDER BY id ASC" not in source.split(
        "def _attach_user_homework_scores", 1,
    )[1].split("def invalidate_problem_list_cache_for_user", 1)[0]


def test_homework_submission_indexes_cover_user_deadline_lookups():
    schema = (ROOT / "database/bootstrap.sql").read_text(encoding="utf-8")
    normalized = schema.replace("`", "")

    assert (
        "idx_submissions_user_problem_created "
        "(username, problem_id, created_at, id)"
    ) in normalized
    assert (
        "idx_rs_user_comp_created "
        "(username, competition_id, created_at, id)"
    ) in normalized
