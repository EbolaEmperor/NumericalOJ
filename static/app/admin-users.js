(function () {
  'use strict';

  const root = document.querySelector('[data-user-admin]');
  if (!root) return;

  const manageModalElement = document.getElementById('manageUserModal');
  const gradesModalElement = document.getElementById('gradesModal');
  const manageModal = bootstrap.Modal.getOrCreateInstance(manageModalElement);
  const gradesModal = bootstrap.Modal.getOrCreateInstance(gradesModalElement);
  const mailConfigured = root.dataset.mailConfigured === 'true';
  let activeUser = null;
  let allGrades = [];
  let toastTimer = null;

  if (window.ChoicePicker) window.ChoicePicker.init(manageModalElement);

  function query(selector, scope) {
    return (scope || document).querySelector(selector);
  }

  function queryAll(selector, scope) {
    return Array.from((scope || document).querySelectorAll(selector));
  }

  function setText(element, value) {
    if (element) element.textContent = value == null ? '' : String(value);
  }

  function setMessage(element, message, kind) {
    if (!element) return;
    element.textContent = message || '';
    element.classList.toggle('is-success', kind === 'success');
    element.classList.toggle('is-error', kind === 'error');
  }

  function setBusy(button, busy, busyLabel) {
    if (!button) return;
    if (!button.dataset.defaultLabel) button.dataset.defaultLabel = button.textContent.trim();
    button.disabled = !!busy;
    button.textContent = busy ? busyLabel : button.dataset.defaultLabel;
  }

  function showToast(message, kind) {
    const toast = query('[data-admin-toast]', root);
    clearTimeout(toastTimer);
    setText(query('[data-admin-toast-text]', toast), message);
    toast.classList.toggle('is-error', kind === 'error');
    const icon = query('i', toast);
    icon.className = kind === 'error' ? 'fas fa-exclamation' : 'fas fa-check';
    toast.hidden = false;
    toastTimer = window.setTimeout(function () { toast.hidden = true; }, 4200);
  }

  query('[data-admin-toast-close]', root).addEventListener('click', function () {
    query('[data-admin-toast]', root).hidden = true;
  });

  async function postForm(url, formData) {
    let response;
    try {
      response = await fetch(url, {
        method: 'POST',
        body: formData,
        headers: {'X-Requested-With': 'XMLHttpRequest'},
      });
    } catch (_error) {
      throw new Error('网络连接失败，请稍后重试');
    }

    let data;
    try {
      data = await response.json();
    } catch (_error) {
      throw new Error('服务器返回了无法识别的响应');
    }
    if (!response.ok || !data.success) {
      throw new Error(data.message || '操作失败，请稍后重试');
    }
    return data;
  }

  function modelFromRow(row) {
    let memberships = [];
    try {
      memberships = JSON.parse(row.dataset.classes || '[]');
    } catch (_error) {
      memberships = [];
    }
    return {
      id: Number(row.dataset.userId),
      username: row.dataset.username || '',
      email: row.dataset.email || '',
      isAdmin: row.dataset.isAdmin === 'true',
      memberships: memberships,
      row: row,
    };
  }

  function paintAvatar(element, username) {
    if (!element || !window.NumojIdenticon) return;
    element.dataset.avatarSeed = username;
    element.dataset.avatarLabel = username;
    window.NumojIdenticon.paint(
      element,
      window.NumojIdenticon.cellsForSeed(username),
      username
    );
  }

  function renderRowClasses(user) {
    const container = query('.user-admin-class-summary', user.row);
    container.replaceChildren();
    if (!user.memberships.length) {
      const empty = document.createElement('span');
      empty.className = 'is-empty';
      empty.textContent = '未分配';
      container.appendChild(empty);
      return;
    }
    user.memberships.slice(0, 3).forEach(function (membership) {
      const badge = document.createElement('span');
      badge.dataset.classEn = membership.class_en;
      badge.textContent = membership.class_cn || membership.class_en;
      container.appendChild(badge);
    });
    if (user.memberships.length > 3) {
      const more = document.createElement('span');
      more.className = 'is-more';
      more.textContent = '+' + (user.memberships.length - 3);
      container.appendChild(more);
    }
  }

  function syncRow(user) {
    user.row.dataset.username = user.username;
    user.row.dataset.email = user.email;
    user.row.dataset.isAdmin = user.isAdmin ? 'true' : 'false';
    user.row.dataset.classes = JSON.stringify(user.memberships);
    setText(query('.user-username', user.row), user.username);
    const email = query('.user-admin-email', user.row);
    setText(email, user.email || '未设置邮箱');
    email.classList.toggle('is-empty', !user.email);
    const role = query('.user-role-badge', user.row);
    role.classList.toggle('is-admin', user.isAdmin);
    role.hidden = !user.isAdmin;
    setText(query('[data-role-label]', role), '教师');
    paintAvatar(query('.user-admin-avatar', user.row), user.username);
    renderRowClasses(user);
  }

  function resetChoicePicker() {
    const input = document.getElementById('manageClassSelect');
    const picker = input.closest('[data-rk-choice]');
    const controller = picker.__choicePickerController;
    if (controller) controller.setValue('', false);
    else {
      input.value = '';
      input.dispatchEvent(new Event('change', {bubbles: true}));
    }
    const owned = new Set(activeUser.memberships.map(function (item) { return item.class_en; }));
    queryAll('[data-choice-value]', picker).forEach(function (option) {
      const value = option.dataset.choiceValue || '';
      const disabled = !value || owned.has(value);
      option.toggleAttribute('data-choice-disabled', disabled);
      option.setAttribute('aria-disabled', disabled ? 'true' : 'false');
    });
  }

  function renderMemberships() {
    const list = query('[data-membership-list]', manageModalElement);
    list.replaceChildren();
    setText(query('[data-membership-count]', manageModalElement), activeUser.memberships.length);
    if (!activeUser.memberships.length) {
      const empty = document.createElement('div');
      empty.className = 'user-admin-membership-empty';
      empty.textContent = '尚未加入任何班级';
      list.appendChild(empty);
    } else {
      activeUser.memberships.forEach(function (membership) {
        const row = document.createElement('div');
        row.className = 'user-admin-membership';
        const copy = document.createElement('span');
        const name = document.createElement('strong');
        const code = document.createElement('small');
        name.textContent = membership.class_cn || membership.class_en;
        code.textContent = membership.class_en;
        copy.append(name, code);
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.textContent = '×';
        remove.title = '移除班级';
        remove.setAttribute('aria-label', '从' + name.textContent + '移除该用户');
        remove.addEventListener('click', function () { removeMembership(membership, remove); });
        row.append(copy, remove);
        list.appendChild(row);
      });
    }
    resetChoicePicker();
  }

  function updateSecurityPanel() {
    const role = query('[data-manage-role]', manageModalElement);
    role.classList.toggle('is-admin', activeUser.isAdmin);
    role.lastChild.textContent = activeUser.isAdmin ? '教师' : '学生';
    setText(
      query('[data-role-description]', manageModalElement),
      activeUser.isAdmin ? '教师账户拥有站点管理权限。' : '学生账户仅拥有常规学习权限。'
    );
    query('[data-grant-admin-start]', manageModalElement).hidden = activeUser.isAdmin;
    query('[data-grant-admin-confirm]', manageModalElement).hidden = true;

    const resetButton = query('[data-reset-password-start]', manageModalElement);
    resetButton.disabled = !mailConfigured || !activeUser.email;
    const description = !mailConfigured
      ? '站点邮件服务未配置，暂时无法发送重置邮件。'
      : (activeUser.email
        ? '生成随机密码，并仅发送至当前账户邮箱。'
        : '请先为该用户设置有效邮箱。');
    setText(query('[data-reset-password-description]', manageModalElement), description);
    setText(query('[data-reset-recipient]', manageModalElement), activeUser.email || '未设置邮箱');
    query('[data-reset-password-confirm]', manageModalElement).hidden = true;
  }

  function openManage(row) {
    activeUser = modelFromRow(row);
    queryAll('[data-manage-user-id-input]', manageModalElement).forEach(function (input) {
      input.value = activeUser.id;
    });
    setText(query('[data-manage-user-id]', manageModalElement), 'UID ' + String(activeUser.id).padStart(4, '0'));
    setText(query('[data-manage-title]', manageModalElement), activeUser.username);
    setText(query('[data-manage-email-summary]', manageModalElement), activeUser.email || '尚未设置邮箱');
    query('[data-manage-username]', manageModalElement).value = activeUser.username;
    query('[data-manage-email]', manageModalElement).value = activeUser.email;
    paintAvatar(query('[data-manage-avatar]', manageModalElement), activeUser.username);
    queryAll('.user-admin-form-message', manageModalElement).forEach(function (message) {
      setMessage(message, '', '');
    });
    renderMemberships();
    updateSecurityPanel();
    manageModal.show();
  }

  queryAll('[data-user-manage]', root).forEach(function (button) {
    button.addEventListener('click', function () { openManage(button.closest('[data-user-row]')); });
  });

  query('[data-username-form]', manageModalElement).addEventListener('submit', async function (event) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = query('[data-manage-username]', form);
    const message = query('[data-username-message]', form);
    const button = query('button[type="submit"]', form);
    const username = input.value.trim();
    if (!username) {
      setMessage(message, '用户名不能为空', 'error');
      input.focus();
      return;
    }
    setBusy(button, true, '保存中');
    setMessage(message, '', '');
    try {
      const data = await postForm(root.dataset.editUsernameUrl, new FormData(form));
      activeUser.username = data.new_username;
      syncRow(activeUser);
      setText(query('[data-manage-title]', manageModalElement), activeUser.username);
      paintAvatar(query('[data-manage-avatar]', manageModalElement), activeUser.username);
      setMessage(message, '用户名已更新', 'success');
      showToast('用户名已更新');
    } catch (error) {
      setMessage(message, error.message, 'error');
    } finally {
      setBusy(button, false, '保存中');
    }
  });

  query('[data-email-form]', manageModalElement).addEventListener('submit', async function (event) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = query('[data-manage-email]', form);
    const message = query('[data-email-message]', form);
    const button = query('button[type="submit"]', form);
    if (!input.value.trim()) {
      setMessage(message, '邮箱不能为空', 'error');
      input.focus();
      return;
    }
    setBusy(button, true, '保存中');
    setMessage(message, '', '');
    try {
      const data = await postForm(root.dataset.setEmailUrl, new FormData(form));
      activeUser.email = data.email;
      syncRow(activeUser);
      setText(query('[data-manage-email-summary]', manageModalElement), activeUser.email);
      setMessage(message, data.message, 'success');
      updateSecurityPanel();
      showToast(data.message);
    } catch (error) {
      setMessage(message, error.message, 'error');
    } finally {
      setBusy(button, false, '保存中');
    }
  });

  query('[data-membership-form]', manageModalElement).addEventListener('submit', async function (event) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = document.getElementById('manageClassSelect');
    const message = query('[data-membership-message]', manageModalElement);
    const button = query('button[type="submit"]', form);
    const classEn = input.value;
    if (!classEn) {
      setMessage(message, '请选择一个尚未加入的班级', 'error');
      input.closest('[data-rk-choice]').classList.add('is-invalid');
      return;
    }
    const formData = new FormData();
    formData.append('user_id', activeUser.id);
    formData.append('class_en', classEn);
    button.disabled = true;
    try {
      const data = await postForm(root.dataset.addMembershipUrl, formData);
      const selected = queryAll('[data-choice-value]', input.closest('[data-rk-choice]')).find(function (option) {
        return option.dataset.choiceValue === classEn;
      });
      if (data.added !== false) {
        activeUser.memberships.push({
          class_en: classEn,
          class_cn: data.class_cn || (selected && selected.dataset.choiceLabel) || classEn,
        });
      }
      syncRow(activeUser);
      renderMemberships();
      setMessage(message, data.message || '班级已添加', 'success');
    } catch (error) {
      setMessage(message, error.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  async function removeMembership(membership, button) {
    const message = query('[data-membership-message]', manageModalElement);
    const formData = new FormData();
    formData.append('user_id', activeUser.id);
    formData.append('class_en', membership.class_en);
    button.disabled = true;
    try {
      const data = await postForm(root.dataset.removeMembershipUrl, formData);
      activeUser.memberships = activeUser.memberships.filter(function (item) {
        return item.class_en !== membership.class_en;
      });
      syncRow(activeUser);
      renderMemberships();
      setMessage(message, data.message || '已移出班级', 'success');
    } catch (error) {
      button.disabled = false;
      setMessage(message, error.message, 'error');
    }
  }

  query('[data-grant-admin-start]', manageModalElement).addEventListener('click', function () {
    query('[data-grant-admin-confirm]', manageModalElement).hidden = false;
  });
  query('[data-grant-admin-cancel]', manageModalElement).addEventListener('click', function () {
    query('[data-grant-admin-confirm]', manageModalElement).hidden = true;
  });
  query('[data-grant-admin-confirm-button]', manageModalElement).addEventListener('click', async function (event) {
    const button = event.currentTarget;
    const formData = new FormData();
    formData.append('user_id', activeUser.id);
    setBusy(button, true, '授予中');
    try {
      const data = await postForm(root.dataset.grantAdminUrl, formData);
      activeUser.isAdmin = true;
      syncRow(activeUser);
      setBusy(button, false, '授予中');
      updateSecurityPanel();
      showToast(data.message);
    } catch (error) {
      showToast(error.message, 'error');
      setBusy(button, false, '授予中');
    }
  });

  query('[data-reset-password-start]', manageModalElement).addEventListener('click', function () {
    query('[data-reset-password-confirm]', manageModalElement).hidden = false;
  });
  query('[data-reset-password-cancel]', manageModalElement).addEventListener('click', function () {
    query('[data-reset-password-confirm]', manageModalElement).hidden = true;
  });
  query('[data-reset-password-confirm-button]', manageModalElement).addEventListener('click', async function (event) {
    const button = event.currentTarget;
    const formData = new FormData();
    formData.append('user_id', activeUser.id);
    setBusy(button, true, '发送中');
    try {
      const data = await postForm(root.dataset.resetPasswordUrl, formData);
      query('[data-reset-password-confirm]', manageModalElement).hidden = true;
      showToast(data.message);
    } catch (error) {
      showToast(error.message, 'error');
    } finally {
      setBusy(button, false, '发送中');
    }
  });

  query('[data-add-class-form]').addEventListener('submit', async function (event) {
    event.preventDefault();
    const form = event.currentTarget;
    const message = query('[data-add-class-message]', form);
    const button = query('button[type="submit"]', form);
    const classEn = form.elements.class_en.value.trim();
    const classCn = form.elements.class_cn.value.trim();
    if (!/^[A-Za-z0-9_]+$/.test(classEn) || !classCn) {
      setMessage(message, '请填写有效的英文标识和班级名称', 'error');
      return;
    }
    setBusy(button, true, '创建中');
    try {
      const data = await postForm(root.dataset.addClassUrl, new FormData(form));
      setMessage(message, data.message, 'success');
      showToast(data.message);
      window.setTimeout(function () { window.location.reload(); }, 650);
    } catch (error) {
      setMessage(message, error.message, 'error');
      setBusy(button, false, '创建中');
    }
  });

  query('[data-open-grades]', manageModalElement).addEventListener('click', function () {
    manageModalElement.addEventListener('hidden.bs.modal', function openAfterClose() {
      manageModalElement.removeEventListener('hidden.bs.modal', openAfterClose);
      loadGrades();
      gradesModal.show();
    });
    manageModal.hide();
  });

  async function loadGrades() {
    setText(query('[data-grades-username]', gradesModalElement), activeUser.username);
    query('#gradeSearchInput', gradesModalElement).value = '';
    query('[data-grades-loading]', gradesModalElement).hidden = false;
    query('[data-grades-table-wrap]', gradesModalElement).hidden = true;
    query('[data-grades-error]', gradesModalElement).hidden = true;
    try {
      const response = await fetch(root.dataset.gradesUrl + '?user_id=' + encodeURIComponent(activeUser.id), {
        headers: {'X-Requested-With': 'XMLHttpRequest'},
      });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.message || '成绩读取失败');
      allGrades = data.grades || [];
      renderGrades(allGrades);
      query('[data-grades-table-wrap]', gradesModalElement).hidden = false;
    } catch (error) {
      const state = query('[data-grades-error]', gradesModalElement);
      setText(state, error.message || '成绩读取失败');
      state.hidden = false;
    } finally {
      query('[data-grades-loading]', gradesModalElement).hidden = true;
    }
  }

  function renderGrades(grades) {
    const body = query('[data-grades-body]', gradesModalElement);
    body.replaceChildren();
    if (!grades.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 4;
      const empty = document.createElement('div');
      empty.className = 'user-admin-membership-empty';
      empty.textContent = '暂无匹配的成绩记录';
      cell.appendChild(empty);
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    grades.forEach(function (grade) {
      const row = document.createElement('tr');
      const problemCell = document.createElement('td');
      const copy = document.createElement('span');
      copy.className = 'user-admin-grade-copy';
      const title = document.createElement('strong');
      const id = document.createElement('small');
      title.textContent = grade.problem_title || '未命名题目';
      id.textContent = 'P' + String(grade.problem_id).padStart(4, '0');
      copy.append(title, id);
      problemCell.appendChild(copy);

      const scoreCell = document.createElement('td');
      const input = document.createElement('input');
      input.className = 'user-admin-score-field';
      input.type = 'text';
      input.inputMode = 'numeric';
      input.value = grade.user_score == null ? '' : String(grade.user_score);
      input.setAttribute('aria-label', title.textContent + '当前成绩');
      scoreCell.appendChild(input);

      const maxCell = document.createElement('td');
      maxCell.textContent = String(grade.max_score);
      const actionCell = document.createElement('td');
      const save = document.createElement('button');
      save.type = 'button';
      save.className = 'user-admin-grade-save';
      save.textContent = '保存';
      save.addEventListener('click', function () { saveGrade(grade, input, save); });
      actionCell.appendChild(save);
      row.append(problemCell, scoreCell, maxCell, actionCell);
      body.appendChild(row);
    });
  }

  async function saveGrade(grade, input, button) {
    const raw = input.value.trim();
    if (raw && (!/^\d+$/.test(raw) || Number(raw) > Number(grade.max_score))) {
      showToast('成绩必须是 0 到 ' + grade.max_score + ' 之间的整数，或留空清除', 'error');
      input.focus();
      return;
    }
    const formData = new FormData();
    formData.append('user_id', activeUser.id);
    formData.append('problem_id', grade.problem_id);
    formData.append('score', raw);
    setBusy(button, true, '保存中');
    try {
      await postForm(root.dataset.updateGradeUrl, formData);
      if (!raw) {
        allGrades = allGrades.filter(function (item) { return item.problem_id !== grade.problem_id; });
        renderGrades(allGrades);
      } else {
        grade.user_score = Number(raw);
        setBusy(button, false, '保存中');
      }
      showToast('成绩已更新');
    } catch (error) {
      showToast(error.message, 'error');
      setBusy(button, false, '保存中');
    }
  }

  query('#gradeSearchInput', gradesModalElement).addEventListener('input', function (event) {
    const term = event.target.value.trim().toLocaleLowerCase();
    renderGrades(allGrades.filter(function (grade) {
      return String(grade.problem_id).includes(term)
        || String(grade.problem_title || '').toLocaleLowerCase().includes(term);
    }));
  });
}());
