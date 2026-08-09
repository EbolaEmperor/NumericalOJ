from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "templates/problems/detail.html"
SCRIPT = ROOT / "static/app/problem-agent-launch.js"
STYLESHEET = ROOT / "static/app/problem-agent-launch.css"
CHOICE_PICKER = ROOT / "static/app/choice-picker.js"
CHOICE_STYLESHEET = ROOT / "static/app/choice-picker.css"
SITE_LAYOUT = ROOT / "templates/layouts/site.html"


def _read(path):
    return path.read_text(encoding="utf-8")


def test_agent_launch_modals_use_shared_custom_choice_pickers():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)
    picker = _read(CHOICE_PICKER)

    assert "{% macro agent_launch_picker" in template
    assert template.count("{{ agent_launch_picker(") == 4
    assert template.count("'harness', 'Harness'") == 2
    assert template.count("'endpoint', 'LLM 节点'") == 2
    assert 'role="combobox"' in template
    assert 'role="listbox"' in template
    assert 'aria-haspopup="listbox"' in template
    assert 'aria-expanded="false"' in template
    assert "data-agent-choice-input" in template
    assert "global.ChoicePicker.create" in script
    assert "setAttribute('role', 'option')" in picker
    assert "<select" not in template.lower()
    assert "<option" not in template.lower()


def test_agent_launch_assets_and_harness_branding_are_wired_once():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)
    stylesheet = _read(STYLESHEET)
    choice_stylesheet = _read(CHOICE_STYLESHEET)
    site_layout = _read(SITE_LAYOUT)

    for asset in (
        "app/ranking/harness-logos.css",
        "app/problem-agent-launch.css",
        "app/problem-agent-launch.js",
    ):
        assert asset in template
    assert site_layout.count("app/choice-picker.css") == 1
    assert site_layout.count("app/choice-picker.js") == 1
    assert "app/choice-picker.js" not in template
    for harness in ("claude_code", "codex", "opencode", "pi"):
        assert harness in script
    assert "harness-logo--" in script
    assert ".agent-launch-modal" in stylesheet
    assert ".rk-choice-trigger:focus-visible" in choice_stylesheet
    assert ".agent-launch-choice .rk-choice-trigger" not in stylesheet


def test_agent_launch_loads_task_specific_options_and_restores_preference():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)

    assert "'/admin/agent_launch_options'" in template
    assert 'data-task-kind="solve"' in template
    assert 'data-task-kind="testdata"' in template
    assert "addQuery(this.optionsUrl, 'task_kind', this.taskKind)" in script
    assert "cache: 'no-store'" in script
    assert "payload.success !== true" in script
    assert "payload.harnesses" in script
    assert "payload.endpoints_by_harness" in script
    assert "payload.preference" in script
    assert "preference.harness" in script
    assert "preference.endpoint_id" in script
    assert "show.bs.modal" in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script


def test_agent_launch_disambiguates_duplicate_models_with_endpoint_id():
    script = _read(SCRIPT)

    assert "'节点 #' + endpoint.id" in script
    assert "meta: endpointMeta(endpoint)" in script
    assert "model: endpoint.model" in script


def test_agent_launch_payloads_include_harness_and_endpoint_without_secrets():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)

    assert "harness: harness" in script
    assert "endpoint_id: endpoint.numericId" in script
    assert "payload.test_point_count = count" in script
    assert "payload.data_requirement = requirement" in script
    assert "payload.standard_solution = solutionFile" in script
    assert "new global.FormData()" in script
    for field_name in (
        "harness",
        "endpoint_id",
        "test_point_count",
        "data_requirement",
        "standard_solution",
    ):
        assert f"formData.append('{field_name}'" in script
    assert "extra_prompt" not in f"{template}\n{script}"
    assert "agentSolveExtraPrompt" not in template
    assert "payload.standard_code" not in script
    assert "api_key" not in script
    assert "base_url" not in script
    assert "JSON.stringify(payload)" in script

    form_data = script.index("new global.FormData()")
    multipart_return = script.index("return options;", form_data)
    json_content_type = script.index("options.headers['Content-Type']")
    assert form_data < multipart_return < json_content_type


def test_agent_launch_uses_inline_feedback_instead_of_browser_alerts():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)

    assert template.count("data-agent-launch-feedback") == 2
    assert template.count('aria-live="polite"') >= 2
    assert "setFeedback" in script
    assert "is-error" in script
    assert "is-success" in script
    assert "alert(" not in script
    assert "confirm(" not in script
    assert "测试点数量必须是正整数" in script
    assert "请选择正解文件" in script


def test_agent_launch_keeps_only_functional_copy_and_data_fields():
    template = _read(TEMPLATE)

    assert "PROBLEM AGENT" in template
    assert "TESTDATA AGENT" in template
    for explanatory_copy in (
        "NUMOJ-USER SKILL",
        "numoj-user skill",
        "生成 1.in/1.out 至 n.in/n.out。",
        "可选，最长 4000 字。",
        "上传单个源代码文件，用于生成输出并逐点验证。",
        "例如：覆盖边界值、随机大数据与特殊构造",
    ):
        assert explanatory_copy not in template
    assert "解题 Agent" in template
    assert "造数据 Agent" in template
    assert "测试点要求" in template
    assert ">正解</label>" in template
    for field_id in (
        "agentTestPointCount",
        "agentDataRequirement",
        "agentStandardSolution",
    ):
        assert f'id="{field_id}"' in template
    assert 'max="5000"' not in template
    assert 'maxlength="4000"' not in template
    assert "requirement.length > 4000" not in _read(SCRIPT)


def test_testdata_solution_uses_accessible_custom_file_picker():
    template = _read(TEMPLATE)
    script = _read(SCRIPT)
    stylesheet = _read(STYLESHEET)

    field_start = template.index('id="agentStandardSolutionLabel"')
    field_end = template.index('</div>\n          </div>', field_start)
    field = template[field_start:field_end]

    assert 'type="file"' in field
    assert 'class="visually-hidden"' in field
    assert 'name="standard_solution"' in field
    assert "data-agent-solution-file" in field
    assert 'for="agentStandardSolution"' in field
    assert 'aria-labelledby="agentStandardSolutionLabel agentSolutionFileTitle"' in field
    assert "aria-describedby" not in field
    assert 'aria-live="polite"' in field
    assert "tabindex" not in field
    assert "file.name" in script
    assert "重新选择" in script
    assert ".agent-launch-file input:focus-visible + .agent-launch-file-trigger" in stylesheet
    assert ".agent-launch-file.has-file" in stylesheet


def test_only_standard_testpoint_mode_shows_testdata_agent():
    template = _read(TEMPLATE)

    assert 'id="btnAgentSolve"' in template
    assert (
        "{% if programming_mode == 1 %}\n"
        '            <button type="button" class="btn btn-outline-primary" '
        'data-bs-toggle="modal" data-bs-target="#agentGenerateDataModal">'
    ) in template
    assert (
        "{% if programming_mode == 1 %}\n"
        '<div class="modal fade agent-launch-modal"\n'
        '     id="agentGenerateDataModal"'
    ) in template


def test_feedback_precedes_testdata_form_and_mobile_controls_are_touch_safe():
    template = _read(TEMPLATE)
    stylesheet = _read(STYLESHEET)
    choice_stylesheet = _read(CHOICE_STYLESHEET)

    data_modal = template.index('id="agentGenerateDataModal"')
    selector_grid = template.index('class="agent-launch-selector-grid"', data_modal)
    feedback = template.index("data-agent-launch-feedback", selector_grid)
    data_grid = template.index('class="agent-launch-data-grid"', selector_grid)
    mobile_styles = stylesheet.split("@media (max-width: 620px)", 1)[1]

    assert selector_grid < feedback < data_grid
    assert "position: sticky" in stylesheet
    assert ".agent-launch-field .form-control" in mobile_styles
    assert "font-size: 16px" in mobile_styles
    assert ".agent-launch-modal .modal-footer .btn" in mobile_styles
    assert "min-height: 44px" in mobile_styles
    choice_mobile = choice_stylesheet.split("@media (max-width: 575.98px)", 1)[1]
    assert ".rk-choice-option" in choice_mobile
    assert "min-height: 44px" in choice_mobile
