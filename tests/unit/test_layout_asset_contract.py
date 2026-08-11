"""全局布局的静态资产边界契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_LAYOUT = (ROOT / "templates" / "layouts" / "base.html").read_text(
    encoding="utf-8"
)
SITE_LAYOUT = (ROOT / "templates" / "layouts" / "site.html").read_text(
    encoding="utf-8"
)
NAVIGATION = (
    ROOT / "templates" / "components" / "layout" / "navigation.html"
).read_text(encoding="utf-8")
EMBEDDED_LAYOUT = (ROOT / "templates" / "layouts" / "embedded.html").read_text(
    encoding="utf-8"
)
MATHJAX_COMPONENT = (
    ROOT / "templates" / "components" / "layout" / "mathjax.html"
).read_text(encoding="utf-8")
LAYOUT_COMPONENTS = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted((ROOT / "templates" / "components" / "layout").glob("*.html"))
)
PASSWORD_MODAL = (
    ROOT / "templates" / "components" / "layout" / "password_modal.html"
).read_text(encoding="utf-8")
CLASS_MANAGER_MODAL = (
    ROOT / "templates" / "components" / "layout" / "class_manager_modal.html"
).read_text(encoding="utf-8")
ADMIN_USERS = (ROOT / "templates" / "admin" / "users.html").read_text(
    encoding="utf-8"
)
REGISTER = (ROOT / "templates" / "auth" / "register.html").read_text(
    encoding="utf-8"
)
AUTH_BASE = (ROOT / "templates" / "auth" / "base.html").read_text(
    encoding="utf-8"
)
AUTH_TEMPLATES = "\n".join(
    (ROOT / "templates" / "auth" / name).read_text(encoding="utf-8")
    for name in ("login.html", "register.html", "forgot_password.html")
)
AUTH_CSS = (ROOT / "static" / "app" / "auth.css").read_text(encoding="utf-8")
AUTH_JS = (ROOT / "static" / "app" / "auth.js").read_text(encoding="utf-8")
CLASS_LOGO = (
    ROOT / "templates" / "components" / "layout" / "class_logo.html"
).read_text(encoding="utf-8")
LAYOUT_CSS = (ROOT / "static" / "app" / "layout.css").read_text(encoding="utf-8")
LAYOUT_JS = (ROOT / "static" / "app" / "layout.js").read_text(encoding="utf-8")
IDENTICON_JS = (
    ROOT / "static" / "app" / "identicon.js"
).read_text(encoding="utf-8")
CLASS_SELECT_JS = (
    ROOT / "static" / "app" / "class-select.js"
).read_text(encoding="utf-8")
AUTH_ROUTES = (
    ROOT / "oj_modules" / "routes" / "auth_routes.py"
).read_text(encoding="utf-8")
CLASS_MANAGEMENT_ROUTES = (
    ROOT / "oj_modules" / "routes" / "class_management_routes.py"
).read_text(encoding="utf-8")


def test_layout_loads_shared_static_assets_instead_of_inline_app_code():
    assert SITE_LAYOUT.count('{% extends "layouts/base.html" %}') == 1
    assert EMBEDDED_LAYOUT.count('{% extends "layouts/base.html" %}') == 1
    for asset in (
        "bootstrap/bootstrap.min.css",
        "vendor/fontawesome/css/all.min.css",
        "math-curve-loaders/loader.css",
        "math-curve-loaders/loader.js",
        "bootstrap/bootstrap.bundle.min.js",
    ):
        assert BASE_LAYOUT.count(asset) == 1

    assert "filename='app/layout.css'" in SITE_LAYOUT
    assert "filename='app/identicon.js'" in SITE_LAYOUT
    assert "filename='app/class-select.js'" in SITE_LAYOUT
    assert "filename='app/layout.js'" in SITE_LAYOUT
    assert SITE_LAYOUT.index("app/class-select.js") < SITE_LAYOUT.index("app/layout.js")
    assert SITE_LAYOUT.index("app/identicon.js") < SITE_LAYOUT.index("app/layout.js")
    for layout in (BASE_LAYOUT, SITE_LAYOUT, EMBEDDED_LAYOUT):
        assert "<style" not in layout
        assert "style=" not in layout
        assert "onclick=" not in layout


def test_mathjax_is_an_explicit_page_level_capability():
    assert "window.MathJax" not in BASE_LAYOUT
    assert "vendor/mathjax" not in BASE_LAYOUT
    assert "window.MathJax" in MATHJAX_COMPONENT
    assert "vendor/mathjax/tex-mml-chtml.js" in MATHJAX_COMPONENT

    consumers = {
        "problems/create.html",
        "problems/detail.html",
        "problems/edit.html",
        "forum/index.html",
        "submissions/detail.html",
        "ranking/detail.html",
        "ranking/appeal_review.html",
    }
    include = "{% include 'components/layout/mathjax.html' %}"
    for name in consumers:
        source = (ROOT / "templates" / name).read_text(encoding="utf-8")
        assert source.count(include) == 1

    non_consumers = {
        "auth/login.html",
        "submissions/all.html",
    }
    for name in non_consumers:
        source = (ROOT / "templates" / name).read_text(encoding="utf-8")
        assert include not in source


def test_layout_passes_server_values_to_javascript_through_data_attributes():
    attributes = (
        "data-password-code-url",
        "data-user-email",
        "data-classes-url",
        "data-join-class-url",
        "data-leave-class-url",
        "data-class-adjust-url",
    )
    for attribute in attributes:
        assert attribute in LAYOUT_COMPONENTS

    assert "{{" not in LAYOUT_JS
    assert "fetch('/" not in LAYOUT_JS
    assert "modalEl.dataset.classesUrl" in LAYOUT_JS
    assert "form.dataset.passwordCodeUrl" in LAYOUT_JS


def test_layout_styles_and_behaviors_live_in_their_responsible_assets():
    for selector in (
        ".layout-navbar",
        ".layout-offcanvas-nav.layout-nav-compact",
        ".numoj-account-modal",
        ".numoj-membership-row",
        ".numoj-class-select",
    ):
        assert selector in LAYOUT_CSS

    for initializer in (
        "initAdaptiveNavigation()",
        "initClassManager()",
        "initPasswordForm()",
        "initUserAvatar()",
    ):
        assert initializer in LAYOUT_JS


def test_sidebar_avatar_reuses_the_forum_username_identicon_renderer():
    assert "data-numoj-user-avatar" in NAVIGATION
    assert 'data-avatar-seed="{{ user.username }}"' in NAVIGATION
    assert "identicon.cellsForSeed(seed)" in LAYOUT_JS
    assert "identicon.paint(" in LAYOUT_JS
    assert "new TextEncoder()" in IDENTICON_JS
    assert "Math.imul(hash, 0x01000193)" in IDENTICON_JS
    assert "grid-template-columns: repeat(8, 1fr);" in LAYOUT_CSS
    assert ".numoj-avatar > span.is-filled" in LAYOUT_CSS


def test_class_membership_and_registration_share_the_custom_logo_picker():
    for source in (CLASS_MANAGER_MODAL, REGISTER):
        assert "data-numoj-class-select" in source
        assert 'role="listbox"' in source
        assert "numoj-class-select-trigger" in source
        assert "numoj-class-select-logo" in source

    assert "<select" not in CLASS_MANAGER_MODAL
    assert '<select name="class"' not in REGISTER
    assert 'type="hidden" id="joinClassSelect"' in CLASS_MANAGER_MODAL
    assert 'type="hidden"' in REGISTER
    assert 'name="class"' in REGISTER
    assert "data-class-select-required" in REGISTER
    assert "components/layout/class_logo.html" in REGISTER
    assert "cls.logo.cells" in CLASS_LOGO

    assert "const MAX_VISIBLE_OPTIONS = 8;" in CLASS_SELECT_JS
    assert "--numoj-class-option-height: 46px;" in LAYOUT_CSS
    assert "--numoj-class-menu-capacity" in LAYOUT_CSS
    assert "overflow-y: auto;" in LAYOUT_CSS
    assert ".numoj-class-select-option.is-selected" in LAYOUT_CSS
    assert "ArrowDown" in CLASS_SELECT_JS
    assert "ArrowUp" in CLASS_SELECT_JS
    assert "Home" in CLASS_SELECT_JS
    assert "End" in CLASS_SELECT_JS
    assert "Escape" in CLASS_SELECT_JS
    assert "createLogo" in CLASS_SELECT_JS
    assert "joinPicker.setItems" in LAYOUT_JS

    assert "attach_class_logos(get_all_classes())" in AUTH_ROUTES
    assert "memberships=attach_class_logos(user_classes)" in CLASS_MANAGEMENT_ROUTES
    assert "all_classes=attach_class_logos(all_classes)" in CLASS_MANAGEMENT_ROUTES
    assert "logo_seed" not in CLASS_MANAGER_MODAL


def test_class_manager_picker_opens_downward_without_modal_clipping():
    overflow_rule = LAYOUT_CSS.split(
        ".numoj-class-modal .modal-content,", 1
    )[1].split("}", 1)[0]
    menu_rule = LAYOUT_CSS.split(
        ".numoj-class-modal .numoj-class-select-menu", 1
    )[1].split("}", 1)[0]

    assert ".numoj-class-modal .modal-body" in overflow_rule
    assert "overflow: visible;" in overflow_rule
    assert "top: calc(100% + 6px);" in menu_rule
    assert "bottom: auto;" in menu_rule


def test_auth_pages_share_the_ui_v2_card_and_homepage_logo_contract():
    assert '{% extends "layouts/site.html" %}' in AUTH_BASE
    assert "filename='app/auth.css'" in AUTH_BASE
    assert "filename='app/auth.js'" in AUTH_BASE
    assert "numoj-auth-shell" in AUTH_BASE
    assert "M4 20Q8 4 12 12T20 4" in AUTH_BASE
    assert "ACCOUNT ACCESS" not in AUTH_BASE
    assert "AI-NATIVE JUDGE" not in AUTH_BASE
    assert "numoj-auth-heading" not in AUTH_BASE
    assert "auth_heading" not in AUTH_TEMPLATES

    for template_name in ("login.html", "register.html", "forgot_password.html"):
        source = (ROOT / "templates" / "auth" / template_name).read_text(
            encoding="utf-8"
        )
        assert '{% extends "auth/base.html" %}' in source
        assert "<style" not in source
        assert "<script" not in source
        assert "style=" not in source
        assert "onclick=" not in source

    assert "data-auth-password-toggle" in AUTH_TEMPLATES
    assert "numoj-auth-eye-slash" in AUTH_TEMPLATES
    assert "button.textContent" not in AUTH_JS
    assert "data-send-code-url" in REGISTER
    assert "fetch(sendCodeButton.dataset.sendCodeUrl" in AUTH_JS
    assert ".numoj-auth-card" in AUTH_CSS
    assert ".numoj-auth-password-toggle" in AUTH_CSS
    assert "margin-top: 9px;" in AUTH_CSS


def test_class_memberships_have_no_primary_class_frontend_concept():
    for source in (
        CLASS_MANAGER_MODAL,
        LAYOUT_JS,
        NAVIGATION,
        ADMIN_USERS,
    ):
        assert "主班级" not in source

    assert "data-set-primary-class-url" not in CLASS_MANAGER_MODAL
    for removed_state in (
        "setPrimary",
        "setPrimaryClassUrl",
        "primary_en",
        "is_primary",
    ):
        assert removed_state not in LAYOUT_JS
    for removed_selector in (
        ".numoj-membership-row.is-primary",
        ".numoj-membership-primary",
        ".numoj-membership-action.is-primary-action",
        ".numoj-class-primary-label",
    ):
        assert removed_selector not in LAYOUT_CSS

    assert "user.class_cn" not in NAVIGATION
    assert "!isAdmin && model.memberships.length <= 1" in LAYOUT_JS
    assert "u.classes" in ADMIN_USERS
    assert "u.extra_classes" not in ADMIN_USERS
    assert "u.class_cn" not in ADMIN_USERS
    assert "editClassModal" not in ADMIN_USERS
    assert "showEditClassModal" not in ADMIN_USERS
    assert "renderClassBadge" in ADMIN_USERS
    assert "removeUserClass" in ADMIN_USERS


def test_admin_role_grant_is_separate_from_class_membership():
    assert "u.is_admin" in ADMIN_USERS
    assert "授予管理员" in ADMIN_USERS
    assert "grantUserAdmin" in ADMIN_USERS
    assert "admin_user.grant_user_admin_ajax" in ADMIN_USERS
    assert "form.append('user_id', userId)" in ADMIN_USERS
    assert "roleBadge.textContent = '教师'" in ADMIN_USERS
    assert "button.remove()" in ADMIN_USERS
    assert "撤销管理员" not in ADMIN_USERS
    assert "降权" not in ADMIN_USERS


def test_account_modals_keep_the_approved_ui_v2_contract():
    for source in (PASSWORD_MODAL, CLASS_MANAGER_MODAL):
        assert "<style" not in source
        assert "<script" not in source
        assert "style=" not in source
        assert "onclick=" not in source

    for removed_copy in (
        "邮箱验证码",
        "设置新密码",
        "两次密码需要完全一致",
        "安全提示",
    ):
        assert removed_copy not in PASSWORD_MODAL
    assert "变更后需要短暂同步" not in CLASS_MANAGER_MODAL
    assert "喝一口茶" not in CLASS_MANAGER_MODAL
    assert "管理当前所属班级" not in CLASS_MANAGER_MODAL

    for element_id in (
        "passwordCodeInput",
        "passwordStrengthMeter",
        "passwordMatchMessage",
        "passwordSubmitBtn",
    ):
        assert f'id="{element_id}"' in PASSWORD_MODAL
    for element_id in (
        "classMembershipCount",
        "myClassesBox",
        "joinClassSelect",
        "joinClassBtn",
    ):
        assert f'id="{element_id}"' in CLASS_MANAGER_MODAL

    assert '.numoj-password-meter[data-level="2"] span.is-on' in LAYOUT_CSS
    assert "background: #eab308;" in LAYOUT_CSS
    assert '.numoj-password-meter[data-level="3"] span.is-on' in LAYOUT_CSS
    assert "background: #16a34a;" in LAYOUT_CSS
    assert "strengthMeter.dataset.level = String(score);" in LAYOUT_JS
    assert "'X-Requested-With': 'XMLHttpRequest'" in LAYOUT_JS
    assert "alert(" not in LAYOUT_JS
    assert "confirm(" not in LAYOUT_JS

    mobile_rules = LAYOUT_CSS.split("@media (max-width: 575.98px)", 1)[1]
    membership_row = mobile_rules.split(".numoj-membership-row {", 1)[1].split(
        "}",
        1,
    )[0]
    assert "grid-template-columns: 29px minmax(0, 1fr) auto;" in membership_row
    membership_actions = mobile_rules.split(
        ".numoj-membership-actions {",
        1,
    )[1].split("}", 1)[0]
    assert "justify-content: flex-end;" in membership_actions
    assert "grid-column: auto;" in membership_actions


def test_desktop_sidebar_width_and_collapsed_items_share_one_center_axis():
    assert "--numoj-sidebar-width: 186px;" in LAYOUT_CSS
    collapsed_rule = LAYOUT_CSS.split(
        ".numoj-site-shell.is-sidebar-collapsed .numoj-nav-item {",
        1,
    )[1].split("}", 1)[0]
    assert "width: calc(100% - 26px);" in collapsed_rule
    assert "margin-inline: 13px;" in collapsed_rule
    assert "justify-content: center;" in collapsed_rule
