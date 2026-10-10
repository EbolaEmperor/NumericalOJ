"""预装镜像工具的路径契约；不需要下载 Lean 或启动容器。"""

from importlib.util import module_from_spec, spec_from_file_location
import base64
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


_SOURCE = Path(__file__).resolve().parents[2] / 'docker/agent_judge'


@pytest.fixture
def tool(tmp_path, monkeypatch):
    spec = spec_from_file_location('faithsieve_runtime_tool', _SOURCE / 'faithsieve_tool.py')
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    mathlib = tmp_path / 'opt/numoj-lean-project'
    olean = mathlib / '.lake/build/lib/lean/Mathlib.olean'
    olean.parent.mkdir(parents=True)
    olean.write_bytes(b'compiled mathlib')
    cached = tmp_path / 'opt/numoj-lean-path'
    cached.write_text('./.lake/build/lib/lean:./.lake/packages/batteries/.lake/build/lib/lean')
    monkeypatch.setattr(module, 'MATHLIB', mathlib)
    monkeypatch.setattr(module, 'ELAN', tmp_path / 'opt/elan')
    monkeypatch.setattr(module, 'LEAN_PATH_FILE', cached)
    return module


def test_preflight_compiles_mathlib_and_uses_symbolic_tools_without_identity_checks(tool, monkeypatch):
    import sympy
    monkeypatch.setitem(sys.modules, 'sympy', SimpleNamespace(Rational=sympy.Rational, simplify=sympy.simplify))
    monkeypatch.setattr(tool.shutil, 'which', lambda name: f'/usr/bin/{name}')
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        assert command[0] == '/usr/local/bin/lean'
        assert Path(command[1]).read_text().startswith('import Mathlib.Data.Nat.Basic\n')
        assert kwargs['timeout'] == 30
        return {'exit_code': 0, 'stdout': '', 'stderr': '', 'commands': [command]}
    monkeypatch.setattr(tool, '_run', run)
    result = tool.preflight({})
    assert result['ready'] is True
    assert len(calls) == 1
    assert 'python' not in result and 'sympy' not in result


def test_preflight_rejects_actual_mathlib_compile_failure(tool, monkeypatch):
    monkeypatch.setattr(tool.shutil, 'which', lambda name: f'/usr/bin/{name}')
    monkeypatch.setattr(tool, '_run', lambda *_args, **_kwargs: {'exit_code': 1, 'stdout': '', 'stderr': 'import failed'})
    with pytest.raises(ValueError, match='无法编译'):
        tool.preflight({})


def test_pdf_processing_only_renders_all_pages_without_text_or_ocr(tool, monkeypatch, tmp_path):
    workspace = tmp_path / 'pages'
    calls = []
    def run(command, **_kwargs):
        calls.append(command)
        if command[0] == 'pdfinfo':
            stdout = 'Pages: 2\n'
        elif command[0] == 'pdftoppm':
            Path(command[-1] + '.png').write_bytes(b'\x89PNG\r\n\x1a\nrendered image')
            stdout = ''
        else:
            pytest.fail('PDF 不应执行文本提取或 OCR')
        return {'exit_code': 0, 'stdout': stdout, 'stderr': '', 'commands': [command]}
    monkeypatch.setattr(tool, '_run', run)
    result = tool.extract({'pdf': base64.b64encode(b'%PDF-sample').decode(), 'workspace': str(workspace)})
    assert [command[0] for command in calls] == ['pdfinfo', 'pdftoppm', 'pdftoppm']
    assert result == {
        'page_count': 2,
        'pages': [{'page': page, 'image_path': str(workspace / f'page-{page}.png'), 'rendered': True} for page in (1, 2)],
        'exit_code': 0, 'tool_executed': True,
    }


def test_pdf_rendering_failure_never_returns_completed_page_manifest(tool, monkeypatch, tmp_path):
    def run(command, **_kwargs):
        return {'exit_code': 0, 'stdout': 'Pages: 1\n' if command[0] == 'pdfinfo' else '', 'stderr': '', 'commands': [command]}
    monkeypatch.setattr(tool, '_run', run)
    with pytest.raises(ValueError, match='未成功渲染'):
        tool.extract({'pdf': base64.b64encode(b'%PDF-sample').decode(), 'workspace': str(tmp_path / 'pages')})


@pytest.mark.parametrize('budget', [None, 45])
def test_compile_resolves_lake_relative_cache_paths_and_applies_default_or_explicit_budget(tool, monkeypatch, tmp_path, budget):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'statement.lean').write_text('import Mathlib\ndef p : Prop := True')
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return {'exit_code': 0, 'stdout': '', 'stderr': '', 'commands': [command]}
    monkeypatch.setattr(tool, '_run', run)
    payload = {'workspace': str(workspace), 'path': 'statement.lean'}
    if budget is not None:
        payload['timeout_seconds'] = budget
    assert tool.compile_lean(payload)['exit_code'] == 0
    command, kwargs = calls[0]
    assert command == ['/usr/local/bin/lean', str(workspace / 'statement.lean')]
    assert kwargs['env']['ELAN_HOME'] == str(tool.ELAN)
    assert kwargs['timeout'] == (300 if budget is None else budget)
    assert kwargs['env']['LEAN_PATH'].split(':') == [str(workspace), str(tool.MATHLIB / '.lake/build/lib/lean'), str(tool.MATHLIB / '.lake/packages/batteries/.lake/build/lib/lean')]


def test_both_images_copy_same_immutable_tool_and_pin_symbolic_dependencies():
    root = _SOURCE.parents[1]
    full = (_SOURCE / 'Dockerfile').read_text()
    lite = (root / 'docker/agent_judge-lite/Dockerfile').read_text()
    assert 'COPY faithsieve_tool.py /usr/local/share/numoj/faithsieve_tool.py' in full
    assert 'COPY agent_judge/faithsieve_tool.py /usr/local/share/numoj/faithsieve_tool.py' in lite
    for source in (full, lite):
        assert 'sympy==1.14.0 mpmath==1.3.0' in source
    assert 'tesseract-ocr-chi-sim' in lite
    wrapper = (_SOURCE / 'lean').read_text()
    assert 'root=Path("/opt/numoj-lean-project")' in wrapper
    assert 'exec /opt/elan/bin/lean "$@"' in wrapper
