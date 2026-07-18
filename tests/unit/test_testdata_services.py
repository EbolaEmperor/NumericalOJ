import zipfile

import pytest

from oj_modules import testdata_services


def test_import_testdata_uses_restricted_extraction_and_replaces_stale_files(
        monkeypatch, tmp_path):
    archive = tmp_path / 'testdata.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', '1 2\n')
        zf.writestr('1.out', '3\n')

    destination = tmp_path / 'extracted'
    destination.mkdir()
    (destination / 'stale.in').write_text('stale', encoding='utf-8')
    saved = []
    monkeypatch.setattr(
        testdata_services,
        'update_problem_testdata',
        lambda problem_id, rows: saved.append((problem_id, rows)),
    )

    result = testdata_services.import_testdata_zip(7, archive, destination)

    assert result == {
        'count': 1,
        'testdata': [{'input': '1 2', 'output': '3'}],
    }
    assert saved == [(7, result['testdata'])]
    assert not (destination / 'stale.in').exists()


def test_import_testdata_rejects_traversal_without_leaving_partial_output(tmp_path):
    archive = tmp_path / 'unsafe.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', 'input')
        zf.writestr('../escape.out', 'escape')

    destination = tmp_path / 'extracted'
    with pytest.raises(testdata_services.TestdataValidationError, match='目录穿越'):
        testdata_services.import_testdata_zip(7, archive, destination)

    assert not destination.exists()
    assert not (tmp_path / 'escape.out').exists()


def test_import_testdata_rejects_declared_total_over_policy(monkeypatch, tmp_path):
    archive = tmp_path / 'large.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('1.in', b'1234')
        zf.writestr('1.out', b'5678')

    monkeypatch.setattr(testdata_services, 'TESTDATA_ZIP_MAX_FILE_BYTES', 8)
    monkeypatch.setattr(testdata_services, 'TESTDATA_ZIP_MAX_TOTAL_BYTES', 7)

    with pytest.raises(testdata_services.TestdataValidationError, match='总大小'):
        testdata_services.import_testdata_zip(7, archive, tmp_path / 'out')
