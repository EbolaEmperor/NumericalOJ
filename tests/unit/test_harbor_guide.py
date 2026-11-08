from flask import Flask

from backend.oj_modules.api.ranking_api import ranking_api_bp
from backend.oj_modules.ranking.reverse_judge import guide
from backend.oj_modules.routes.spa_routes import is_spa_document_path


def test_harbor_guide_renders_the_markdown_source_with_navigation():
    app = Flask(__name__)
    app.register_blueprint(ranking_api_bp)
    response = app.test_client().get('/api/ranking/harbor-guide/rendered')
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['success'] is True
    assert 'Harbor 格式说明' in payload['html']
    assert 'instruction.md' in payload['html'] and 'solution/solve.sh' in payload['html']
    assert 'href="#' in payload['toc_html']
    assert 'environment_mode' not in payload['html']


def test_harbor_guide_uses_the_shared_sanitized_markdown_renderer(tmp_path, monkeypatch):
    source = tmp_path / 'guide.md'
    source.write_text('# 说明\n\n## 提交\n\n<script>alert(1)</script>\n\n[链接](javascript:alert(1))', encoding='utf-8')
    monkeypatch.setattr(guide, 'HARBOR_GUIDE_PATH', source)
    html, toc = guide.render_harbor_guide()
    assert '<script' not in html.lower() and 'href="javascript:' not in html.lower()
    assert 'href="#' in toc


def test_harbor_guide_has_a_direct_spa_document_route():
    assert is_spa_document_path('/rankings/harbor-guide')
    assert is_spa_document_path('/rankings/harbor-guide/')
    assert not is_spa_document_path('/rankings/harbor-guide/extra')
    assert not is_spa_document_path('/app/rankings/harbor-guide')
