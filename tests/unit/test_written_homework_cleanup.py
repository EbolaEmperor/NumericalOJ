from pathlib import Path

import pytest

from oj_modules.tasks import written_homework_tasks as written_tasks


class _FakeCelery:
    def __init__(self):
        self.tasks = {}

    def task(self, **options):
        def decorator(function):
            self.tasks[options['name']] = function
            return function

        return decorator


def _run_tex_task(monkeypatch, tmp_path, scenario):
    uploaded_zip = tmp_path / 'answer.zip'
    uploaded_zip.write_bytes(b'zip placeholder')
    released = []
    score_updates = []

    submission = {
        'id': 17,
        'problem_id': 3,
        'problem_type': 2,
        'status': 'Pending',
    }
    monkeypatch.delenv('NUMOJ_FAKE_WRITTEN_HOMEWORK_SCORE', raising=False)
    monkeypatch.setattr(written_tasks, 'get_submission_by_id', lambda _sid: submission.copy())
    monkeypatch.setattr(
        written_tasks,
        'acquire_submission_lock',
        lambda _sid: (None, None, None),
    )
    monkeypatch.setattr(
        written_tasks,
        'release_submission_lock',
        lambda *_args: released.append(True),
    )
    monkeypatch.setattr(written_tasks, 'update_submission_status', lambda *_args: None)
    monkeypatch.setattr(written_tasks, 'refresh_submission_status_snapshot', lambda *_args: None)
    monkeypatch.setattr(
        written_tasks,
        'resolve_problem_llm_endpoint_snapshot',
        lambda _problem, binding_key: ('snapshot', binding_key),
    )
    monkeypatch.setattr(
        written_tasks,
        'update_submission_score_and_comment',
        lambda *args: score_updates.append(args),
    )
    monkeypatch.setattr(written_tasks, 'update_submission_comment', lambda *_args: None)
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
    monkeypatch.setattr(
        written_tasks,
        'evaluate_written_homework_with_ai',
        lambda *_args, **_kwargs: (5, 'ok'),
    )

    celery_app = _FakeCelery()
    task = written_tasks.register_written_homework_task(celery_app)
    task(None, submission['id'])
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
