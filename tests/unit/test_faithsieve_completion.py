"""FaithSieve 成绩与运行终态的原子提交、时限及提交后失败边界。"""

import json

import pytest

from backend.oj_modules.submissions import faithsieve


class DatabaseFailure(RuntimeError):
    pass


class Cursor:
    def __init__(self, connection):
        self.connection = connection
        self.calls = []
        self.rowcount = 1
        self.selected = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, parameters):
        sql = " ".join(sql.split())
        self.calls.append((sql, parameters))
        self.rowcount = 1
        db = self.connection
        if sql.startswith("SELECT submission_id"):
            db.events.append("lock_run")
            assert "FOR UPDATE" in sql
            assert "TIMESTAMPDIFF(SECOND, started_at, NOW())" in sql
            self.selected = db.run
        elif sql.startswith("SELECT s.id"):
            db.events.append("lock_submission")
            assert "FOR UPDATE" in sql
            self.selected = db.submission
        elif sql.startswith("UPDATE submissions"):
            db.events.append("update_submission")
            if db.fail_at == "submission":
                raise DatabaseFailure("submission update failed")
            score, comment, status, identifier = parameters
            assert identifier == db.submission["id"]
            db.staged_submission = {**db.submission, "score": score, "code": comment, "status": status}
        elif sql.startswith("UPDATE faithsieve_grading_runs"):
            db.events.append("update_run")
            assert "status='running'" in sql and "started_at IS NOT NULL" in sql
            assert "TIMESTAMPDIFF(SECOND, started_at, NOW()) < %s" in sql
            message, result_json, _attempt, timeout = parameters
            assert timeout == faithsieve.RUN_TIMEOUT_SECONDS
            if db.fail_at == "run":
                raise DatabaseFailure("run update failed")
            if db.expired_at_final_update:
                self.rowcount = 0
            else:
                db.staged_run = {**db.run, "status": "completed", "message": message, "result_json": result_json}
        else:
            raise AssertionError(f"unexpected query: {sql}")

    def fetchone(self):
        return dict(self.selected) if self.selected is not None else None


class Connection:
    def __init__(self, *, elapsed=10, status="running", fail_at=None):
        self.run = {"submission_id": 11, "problem_id": 7, "status": status, "elapsed_seconds": elapsed}
        self.submission = {"id": 11, "username": "alice", "problem_id": 7, "problem_type": 2,
                           "written_grading_mode": 4, "max_score": 5,
                           "score": 4, "code": "原人工批阅", "status": "Unaccepted"}
        self.fail_at = fail_at
        self.expired_at_final_update = False
        self.staged_submission = None
        self.staged_run = None
        self.events = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self.cursor_instance = Cursor(self)

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.events.append("commit")
        self.commits += 1
        assert self.staged_submission and self.staged_run
        if self.fail_at == "commit_before_apply":
            raise DatabaseFailure("commit connection response lost")
        self.submission = self.staged_submission
        self.run = self.staged_run
        if self.fail_at == "commit_after_apply":
            raise DatabaseFailure("commit applied but response lost")

    def rollback(self):
        self.events.append("rollback")
        self.rollbacks += 1
        self.staged_submission = None
        self.staged_run = None

    def close(self):
        self.events.append("close")
        self.closed = True
        if self.fail_at == "close":
            raise DatabaseFailure("connection close failed")


RESULT = {"verdict": "correct", "score": 5, "comment": "证明正确且充分。"}


def configure(monkeypatch, connection, *, failed_hook=None):
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: connection)

    def hook(name, returned=None):
        def perform(*args):
            assert connection.run["status"] == "completed"
            assert connection.events.index("commit") < connection.events.index("close")
            connection.events.append(name)
            if failed_hook == name:
                raise RuntimeError("derived update failed")
            return returned
        return perform

    monkeypatch.setattr(faithsieve, "refresh_submission_status_snapshot", hook("snapshot"))
    monkeypatch.setattr(faithsieve, "get_user_by_username", hook("user_lookup", {"id": 29}))
    monkeypatch.setattr(faithsieve, "upsert_user_problem_max_score_if_higher", hook("max_score"))
    monkeypatch.setattr(faithsieve, "insert_user_problem_ac_record_if_absent", hook("ac_record"))


def test_result_submission_status_and_run_complete_commit_as_one_transaction(monkeypatch):
    connection = Connection(elapsed=faithsieve.RUN_TIMEOUT_SECONDS - 1)
    configure(monkeypatch, connection)
    assert faithsieve.complete_run("attempt", RESULT) == RESULT
    assert connection.commits == 1 and connection.rollbacks == 0
    assert connection.closed
    assert connection.submission["score"] == 5
    assert connection.submission["code"] == RESULT["comment"]
    assert connection.submission["status"] == "Accepted"
    assert connection.run["status"] == "completed"
    assert json.loads(connection.run["result_json"]) == RESULT
    assert connection.events == ["lock_run", "lock_submission", "update_submission", "update_run", "commit", "close", "snapshot", "user_lookup", "max_score", "ac_record"]


@pytest.mark.parametrize("fail_at", ["submission", "run"])
def test_failure_before_commit_rolls_back_both_submission_and_run(monkeypatch, fail_at):
    connection = Connection(fail_at=fail_at)
    configure(monkeypatch, connection)
    with pytest.raises(DatabaseFailure):
        faithsieve.complete_run("attempt", RESULT)
    assert connection.submission["code"] == "原人工批阅"
    assert connection.submission["score"] == 4
    assert connection.run["status"] == "running"
    assert connection.commits == 0 and connection.rollbacks == 1
    assert not any(name in connection.events for name in ["snapshot", "max_score", "ac_record"])


@pytest.mark.parametrize("status", ["queued", "failed", "inconclusive", "completed"])
def test_only_a_still_running_locked_request_can_overwrite_grade(monkeypatch, status):
    connection = Connection(status=status)
    configure(monkeypatch, connection)
    with pytest.raises(faithsieve.FaithSieveRunNotRunningError):
        faithsieve.complete_run("attempt", RESULT)
    assert connection.events == ["lock_run", "rollback", "close"]
    assert connection.submission["code"] == "原人工批阅"


@pytest.mark.parametrize("change", ["missing_submission", "problem_mismatch", "not_written", "not_manual"])
def test_locked_submission_and_problem_still_match_supported_grading_mode(monkeypatch, change):
    connection = Connection()
    if change == "missing_submission":
        connection.submission = None
    elif change == "problem_mismatch":
        connection.submission["problem_id"] = 8
    elif change == "not_written":
        connection.submission["problem_type"] = 1
    else:
        connection.submission["written_grading_mode"] = 1
    configure(monkeypatch, connection)
    with pytest.raises(faithsieve.FaithSieveCompletionError):
        faithsieve.complete_run("attempt", RESULT)
    assert connection.commits == 0 and connection.rollbacks == 1
    assert "update_submission" not in connection.events


@pytest.mark.parametrize("elapsed", [faithsieve.RUN_TIMEOUT_SECONDS, faithsieve.RUN_TIMEOUT_SECONDS + 1])
def test_database_clock_at_or_beyond_overall_deadline_blocks_every_grade_write(monkeypatch, elapsed):
    connection = Connection(elapsed=elapsed)
    configure(monkeypatch, connection)
    with pytest.raises(faithsieve.FaithSieveRunTimedOutError):
        faithsieve.complete_run("attempt", RESULT)
    assert connection.events == ["lock_run", "rollback", "close"]


def test_deadline_crossed_after_submission_update_rolls_back_the_entire_transaction(monkeypatch):
    connection = Connection(elapsed=faithsieve.RUN_TIMEOUT_SECONDS - 1)
    connection.expired_at_final_update = True
    configure(monkeypatch, connection)
    with pytest.raises(faithsieve.FaithSieveRunTimedOutError, match="提交前"):
        faithsieve.complete_run("attempt", RESULT)
    assert connection.events == ["lock_run", "lock_submission", "update_submission", "update_run", "rollback", "close"]
    assert connection.run["status"] == "running"
    assert connection.submission["score"] == 4


@pytest.mark.parametrize("elapsed", [None, True, -1, "invalid"])
def test_missing_or_invalid_database_run_start_fails_closed(monkeypatch, elapsed):
    connection = Connection(elapsed=elapsed)
    configure(monkeypatch, connection)
    with pytest.raises(faithsieve.FaithSieveCompletionError):
        faithsieve.complete_run("attempt", RESULT)
    assert "update_submission" not in connection.events


@pytest.mark.parametrize("failed_hook", ["snapshot", "user_lookup", "max_score", "ac_record"])
def test_postcommit_cache_or_aggregate_failure_keeps_durable_completion(monkeypatch, caplog, failed_hook):
    connection = Connection()
    configure(monkeypatch, connection, failed_hook=failed_hook)
    assert faithsieve.complete_run("attempt", RESULT) == RESULT
    assert connection.run["status"] == "completed"
    assert connection.submission["score"] == 5
    assert connection.commits == 1 and connection.rollbacks == 0
    assert "成绩已提交" in caplog.text
    assert RESULT["comment"] not in caplog.text


@pytest.mark.parametrize("fail_at", ["commit_before_apply", "commit_after_apply"])
def test_commit_response_loss_is_unknown_and_never_claimed_as_an_unwritten_grade(monkeypatch, fail_at):
    connection = Connection(fail_at=fail_at)
    configure(monkeypatch, connection)
    with pytest.raises(faithsieve.FaithSieveCommitOutcomeUnknownError, match="重读持久状态"):
        faithsieve.complete_run("attempt", RESULT)
    assert connection.commits == 1
    assert "snapshot" not in connection.events
    assert connection.run["status"] == ("completed" if fail_at == "commit_after_apply" else "running")


def test_connection_close_failure_after_commit_does_not_turn_completion_into_failure(monkeypatch, caplog):
    connection = Connection(fail_at="close")
    configure(monkeypatch, connection)
    assert faithsieve.complete_run("attempt", RESULT) == RESULT
    assert connection.run["status"] == "completed"
    assert "连接关闭失败" in caplog.text


@pytest.mark.parametrize("payload", [
    {"verdict": "incorrect", "score": 5, "comment": "判断错误却给满分"},
    {"verdict": "correct", "score": 3, "comment": "正确判断却给不完整证明分"},
    {"verdict": "inconclusive", "score": 0, "comment": "没有可靠证据"},
    {"verdict": "correct", "score": True, "comment": "无效整数"},
    {**RESULT, "extra": "无效协议字段"},
])
def test_domain_entry_revalidates_result_before_opening_database(monkeypatch, payload):
    monkeypatch.setattr(faithsieve, "get_db_connection", lambda: pytest.fail("invalid result must not open DB"))
    with pytest.raises(ValueError):
        faithsieve.complete_run("attempt", payload)


def test_four_point_minor_defect_keeps_original_scale_and_does_not_insert_ac(monkeypatch):
    connection = Connection()
    configure(monkeypatch, connection)
    result = {"verdict": "incorrect", "score": 4, "comment": "核心正确，仅有不影响结论的轻微缺漏。"}
    assert faithsieve.complete_run("attempt", result) == result
    assert connection.submission["status"] == "Unaccepted"
    assert "max_score" in connection.events
    assert "ac_record" not in connection.events


@pytest.mark.parametrize("max_score", [0, -1, 10])
def test_ac_record_retains_existing_positive_problem_maximum_rule(monkeypatch, max_score):
    connection = Connection()
    connection.submission["max_score"] = max_score
    configure(monkeypatch, connection)
    assert faithsieve.complete_run("attempt", RESULT) == RESULT
    assert "ac_record" not in connection.events
