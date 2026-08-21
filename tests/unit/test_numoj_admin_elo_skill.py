"""numoj-admin skill 的 ELO 输出协议契约。"""

import ast
import json
import runpy
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ELO_REFERENCE = ROOT / "skills" / "numoj-admin" / "references" / "ranking-contests" / "elo.md"
ELO_SCRIPT = ELO_REFERENCE.parent / "elo" / "scoring_script.py"


def test_elo_reference_only_teaches_explicit_text_and_html_protocol():
    reference = ELO_REFERENCE.read_text(encoding="utf-8")

    assert '### 文本详情' in reference
    assert '### HTML 详情' in reference
    assert '"format": "text"' in reference
    assert '"format": "html"' in reference
    assert '`details` 必须包含 `format` 和 `content`' in reference
    assert '"details": {"reason"' not in reference
    assert "历史字符串" not in reference
    assert "普通 JSON 对象" not in reference
    assert "动画" not in reference
    assert "requestAnimationFrame" not in reference
    assert "<submission_a_dir> <submission_b_dir>" in reference
    assert "Agent Judge" in reference


def test_bundled_elo_scoring_script_emits_explicit_text_details():
    source = ELO_SCRIPT.read_text(encoding="utf-8")
    ast.parse(source)

    result = subprocess.run(
        [sys.executable, str(ELO_SCRIPT)],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)

    assert payload["details"] == {
        "format": "text",
        "content": "评分脚本参数不足：需要 submission_a 和 submission_b",
    }
    assert source.count("'format': 'text'") >= 2


def test_bundled_elo_scoring_script_reads_prescribed_summaries_directory(tmp_path):
    summaries = tmp_path / "summaries"
    summaries.mkdir()
    paper = summaries / "paper-a.tex"
    paper.write_text("\\documentclass{article}", encoding="utf-8")
    namespace = runpy.run_path(str(ELO_SCRIPT))

    assert namespace["_find_tex_paths"](str(tmp_path)) == {
        "paper-a": str(paper),
    }
