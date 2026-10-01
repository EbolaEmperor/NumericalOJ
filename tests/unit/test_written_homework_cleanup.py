from pathlib import Path

import pytest
import pymysql
from celery.exceptions import SoftTimeLimitExceeded

from backend.oj_modules.tasks import written_homework_tasks as written_tasks


class _FakeCelery:
    def __init__(self):
        self.tasks = {}
        self.options = {}

    def task(self, **options):
        def decorator(function):
            self.tasks[options['name']] = function
            self.options[options['name']] = options
            return function

        return decorator


def _run_tex_task(monkeypatch, tmp_path, scenario):
    uploaded_zip = tmp_path / 'answer.zip'
    uploaded_zip.write_bytes(b'zip placeholder')
    released = []
    score_updates = []
    status_updates = []
    comment_updates = []

    submission = {
        'id': 17,
        'problem_id': 3,
        'problem_type': 2,
        'status': 'Pending',
    }
    monkeypatch.delenv('NUMOJ_FAKE_WRITTEN_HOMEWORK_SCORE', raising=False)
    monkeypatch.setattr(written_tasks, 'get_submission_by_id', lambda _sid: submission.copy())
    monkeypatch.setattr(written_tasks, 'get_latest_attempt', lambda *_args, **_kwargs: None)
    def fake_acquire_lock(_sid, *, ttl_seconds=None):
        assert ttl_seconds == written_tasks._WRITTEN_LOCK_TTL_SECONDS
        assert ttl_seconds > written_tasks._WRITTEN_TASK_TIME_LIMIT + 120
        return None, None, None

    monkeypatch.setattr(written_tasks, 'acquire_submission_lock', fake_acquire_lock)
    monkeypatch.setattr(
        written_tasks,
        'release_submission_lock',
        lambda *_args: released.append(True),
    )
    monkeypatch.setattr(
        written_tasks, 'update_submission_status',
        lambda _sid, status: status_updates.append(status),
    )
    monkeypatch.setattr(written_tasks, 'refresh_submission_status_snapshot', lambda *_args: None)
    monkeypatch.setattr(
        written_tasks,
        'resolve_problem_llm_endpoint_snapshot',
        lambda _problem, binding_key: ('snapshot', binding_key),
    )
    monkeypatch.setattr(
        written_tasks,
        '_resolve_written_vote_plan',
        lambda _problem, _mode: ([{'endpoint_id': 1, 'count': 1}], [
            {'vote_index': 1, 'endpoint_id': 1, 'endpoint_revision': 1,
             'model': 'test-model', 'endpoint': 'snapshot'},
        ]),
    )
    monkeypatch.setattr(
        written_tasks,
        'create_attempt',
        lambda _sid, _mode, _config, votes: (
            votes[0].update(id=1) or {'id': 1, 'votes': votes}
        ),
    )
    monkeypatch.setattr(
        written_tasks,
        '_evaluate_written_votes',
        lambda attempt, plan, evaluator, reconsider: evaluator(
            plan[0]['endpoint'], plan[0]['vote_index'],
        ),
    )
    monkeypatch.setattr(
        written_tasks,
        'update_submission_score_and_comment',
        lambda *args: score_updates.append(args),
    )
    monkeypatch.setattr(
        written_tasks, 'update_submission_comment',
        lambda _sid, comment: comment_updates.append(comment),
    )
    monkeypatch.setattr(written_tasks, 'finish_attempt', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        written_tasks,
        'get_file_path_for_submission',
        lambda _sid: str(uploaded_zip),
    )
    monkeypatch.setattr(
        written_tasks,
        'get_problem',
        lambda _pid: {
            'id': 3,
            'written_grading_mode': 3,
            'written_grading_model': 'test-model',
        },
    )

    def fake_extract(_zip_path, target_dir):
        target = Path(target_dir)
        target.mkdir(parents=True, exist_ok=True)
        (target / 'partial.tmp').write_text('temporary', encoding='utf-8')
        if scenario == 'extract_error':
            raise RuntimeError('simulated extraction failure')
        if scenario != 'missing_main':
            (target / 'main.tex').write_text(
                r'\documentclass{article}\begin{document}ok\end{document}',
                encoding='utf-8',
            )

    def fake_compile(tex_path, output_dir, timeout_seconds=120):
        assert Path(tex_path).name in {'main.tex', 'main__cjk_fallback__.tex'}
        assert timeout_seconds == 120
        if scenario == 'compile_error':
            return False, None, 'simulated compile failure'
        compiled_pdf = Path(output_dir) / 'compiled.pdf'
        compiled_pdf.write_bytes(b'compiled pdf')
        return True, str(compiled_pdf), 'compile succeeded'

    monkeypatch.setattr(written_tasks, '_safe_extract_zip', fake_extract)
    monkeypatch.setattr(written_tasks, '_compile_tex_with_xelatex', fake_compile)
    def fake_grade(*_args, **_kwargs):
        if scenario == 'grading_timeout':
            raise SoftTimeLimitExceeded()
        if scenario == 'grading_db_error':
            raise pymysql.err.OperationalError(2006, 'database unavailable')
        return 5, 'ok'

    monkeypatch.setattr(written_tasks, 'evaluate_written_homework_with_ai', fake_grade)

    celery_app = _FakeCelery()
    task = written_tasks.register_written_homework_task(celery_app)
    if scenario == 'grading_db_error':
        with pytest.raises(pymysql.err.OperationalError):
            task(None, submission['id'])
    else:
        task(None, submission['id'])
    if scenario == 'grading_timeout':
        assert status_updates[-1] == 'Pending'
        assert comment_updates
    return uploaded_zip, released, score_updates


@pytest.mark.parametrize(
    'scenario',
    ('success', 'missing_main', 'compile_error', 'extract_error'),
)
def test_tex_project_is_removed_for_every_task_exit(monkeypatch, tmp_path, scenario):
    uploaded_zip, released, score_updates = _run_tex_task(
        monkeypatch, tmp_path, scenario,
    )

    assert uploaded_zip.exists()
    assert not (tmp_path / 'answer_project').exists()
    assert released == [True]
    assert score_updates

    compile_log = tmp_path / 'answer_xelatex.log'
    if scenario == 'success':
        assert (tmp_path / 'answer.pdf').read_bytes() == b'compiled pdf'
        assert compile_log.read_text(encoding='utf-8') == 'compile succeeded'
    elif scenario == 'compile_error':
        assert compile_log.read_text(encoding='utf-8') == 'simulated compile failure'
        assert (tmp_path / 'answer_xelatex_error.txt').exists()


@pytest.mark.parametrize('scenario', ('grading_timeout', 'grading_db_error'))
def test_tex_grading_operational_errors_do_not_record_zero(monkeypatch, tmp_path, scenario):
    uploaded_zip, released, score_updates = _run_tex_task(monkeypatch, tmp_path, scenario)

    assert uploaded_zip.exists()
    assert not (tmp_path / 'answer_project').exists()
    assert released == [True]
    assert score_updates == []


def test_written_task_budget_covers_all_judges_rounds_and_independent_repairs():
    celery_app = _FakeCelery()
    written_tasks.register_written_homework_task(celery_app)
    options = celery_app.options[written_tasks.WRITTEN_TASK_NAME]
    grading_budget = 3 * 4 * 2 * (5 * 45 + 5 + 20 + 60 + 60)
    processing_hard = max(60, int(written_tasks.EVALUATE_SUBMISSION_LOCK_TTL_SECONDS) - 120)
    processing_soft = max(30, processing_hard - 60)

    assert grading_budget == 8880
    assert options['time_limit'] >= processing_hard + grading_budget
    assert options['soft_time_limit'] >= processing_soft + grading_budget
    assert options['soft_time_limit'] < options['time_limit']
    assert written_tasks._WRITTEN_LOCK_TTL_SECONDS > options['time_limit'] + 120
