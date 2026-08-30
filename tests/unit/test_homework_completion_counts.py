from backend.oj_modules.routes import homework_routes


class _Cursor:
    def __init__(self, result_sets):
        self.result_sets = list(result_sets)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((" ".join(str(sql).split()), params))

    def fetchall(self):
        return self.result_sets.pop(0)


def test_completion_counts_batch_problem_and_ranking_homeworks():
    cursor = _Cursor([
        [{"homework_id": 1, "completed_count": 2}],
        [{"homework_id": 2, "completed_count": 3}],
    ])

    counts = homework_routes._homework_completion_counts(
        cursor,
        "C2026",
        [
            {"id": 1, "problem_id": 10, "ranking_competition_id": None},
            {"id": 2, "problem_id": None, "ranking_competition_id": 20},
            {"id": 3, "problem_id": 11, "ranking_competition_id": None},
        ],
    )

    assert counts == {1: 2, 2: 3, 3: 0}
    assert len(cursor.executions) == 2

    problem_sql, problem_params = cursor.executions[0]
    assert "COUNT(DISTINCT u.id)" in problem_sql
    assert "JOIN submissions s" in problem_sql
    assert "s.created_at <= COALESCE(h.ddl, s.created_at)" in problem_sql
    assert "GROUP BY h.id" in problem_sql
    assert problem_params[0] == "C2026"

    ranking_sql, ranking_params = cursor.executions[1]
    assert "COUNT(DISTINCT u.id)" in ranking_sql
    assert "JOIN ranking_submissions rs" in ranking_sql
    assert "rs.created_at <= COALESCE(h.ddl, rs.created_at)" in ranking_sql
    assert ranking_params == ("C2026",)


def test_completion_counts_skip_queries_for_empty_homework_list():
    cursor = _Cursor([])

    assert homework_routes._homework_completion_counts(cursor, "C2026", []) == {}
    assert cursor.executions == []
