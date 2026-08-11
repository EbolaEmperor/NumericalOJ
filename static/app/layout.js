(function () {
  'use strict';

  let accountToastTimer;

  function initUserAvatar() {
    const avatars = document.querySelectorAll('[data-numoj-user-avatar]');
    const identicon = window.NumojIdenticon;
    if (!avatars.length || !identicon) return;

    avatars.forEach((avatar) => {
      const seed = avatar.dataset.avatarSeed || 'numericaloj';
      const label = avatar.dataset.avatarLabel || seed;
      identicon.paint(avatar, identicon.cellsForSeed(seed), label);
    });
  }

  function showAccountToast(message) {
    const toast = document.getElementById('accountModalToast');
    if (!toast) return;

    window.clearTimeout(accountToastTimer);
    toast.textContent = message;
    toast.hidden = false;
    window.requestAnimationFrame(() => toast.classList.add('is-visible'));
    accountToastTimer = window.setTimeout(() => {
      toast.classList.remove('is-visible');
      window.setTimeout(() => {
        if (!toast.classList.contains('is-visible')) toast.hidden = true;
      }, 180);
    }, 2300);
  }

  function setAccountMessage(element, message, state = '') {
    if (!element) return;
    element.textContent = message;
    element.hidden = !message;
    element.classList.toggle('is-success', state === 'success');
    element.classList.toggle('is-error', state === 'error');
  }

  async function requestJson(url, options, fallbackMessage) {
    const response = await fetch(url, options);
    let data;
    try {
      data = await response.json();
    } catch (_error) {
      throw new Error(fallbackMessage);
    }
    if (!response.ok || !data.success) {
      throw new Error(data.message || fallbackMessage);
    }
    return data;
  }

  function initDesktopSidebar() {
    const shell = document.querySelector('[data-numoj-shell]');
    const sidebar = document.querySelector('[data-numoj-sidebar]');
    const toggle = document.querySelector('[data-numoj-sidebar-toggle]');
    if (!shell || !sidebar || !toggle) return;

    const media = window.matchMedia('(min-width: 992px)');
    const storageKey = 'numoj.desktopSidebarCollapsed';

    function readStoredState() {
      try {
        return window.localStorage.getItem(storageKey) === '1';
      } catch (_error) {
        return false;
      }
    }

    function writeStoredState(collapsed) {
      try {
        window.localStorage.setItem(storageKey, collapsed ? '1' : '0');
      } catch (_error) {
        // 存储被浏览器禁用时，当前页面内仍可正常折叠。
      }
    }

    function applyState(collapsed) {
      const effective = media.matches && collapsed;
      shell.classList.toggle('is-sidebar-collapsed', effective);
      toggle.setAttribute('aria-expanded', effective ? 'false' : 'true');
      toggle.setAttribute('aria-label', effective ? '展开侧边栏' : '收起侧边栏');
      toggle.setAttribute('title', effective ? '展开侧边栏' : '收起侧边栏');
    }

    let collapsed = readStoredState();
    applyState(collapsed);

    toggle.addEventListener('click', () => {
      collapsed = !shell.classList.contains('is-sidebar-collapsed');
      writeStoredState(collapsed);
      applyState(collapsed);
    });

    const onMediaChange = () => applyState(collapsed);
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', onMediaChange);
    } else if (typeof media.addListener === 'function') {
      media.addListener(onMediaChange);
    }
  }

  function initDesktopNavigationData() {
    const sidebars = document.querySelectorAll(
      '[data-numoj-sidebar], [data-numoj-mobile-sidebar]'
    );
    const dataSource = Array.from(sidebars).find(
      (sidebar) => sidebar.dataset.navigationUrl
    );
    if (!dataSource) return;

    const url = new URL(dataSource.dataset.navigationUrl, window.location.origin);
    const selectedClass = new URLSearchParams(window.location.search).get('class_en');
    if (selectedClass) url.searchParams.set('class_en', selectedClass);

    fetch(url.toString(), { headers: { Accept: 'application/json' } })
      .then((response) => response.json())
      .then((data) => {
        if (!data.success) return;
        const counts = data.counts || {};
        Object.entries(counts).forEach(([name, value]) => {
          sidebars.forEach((sidebar) => {
            const target = sidebar.querySelector(`[data-numoj-nav-count="${name}"]`);
            if (!target) return;
            target.textContent = String(value);
            target.classList.remove('d-none');
          });
        });
        sidebars.forEach((sidebar) => {
          sidebar
            .querySelector('[data-numoj-agent-active]')
            ?.classList.toggle('d-none', !data.agent_active);
        });
      })
      .catch(() => {});
  }

  function initAdaptiveNavigation() {
    const compactClass = 'layout-nav-compact';

    function bindAdaptiveFont(containerSelector, labelSelector, mediaQuery) {
      const container = document.querySelector(containerSelector);
      const label = container ? container.querySelector(labelSelector) : null;
      if (!container || !label) return;

      function updateFontSize() {
        container.classList.remove(compactClass);
        if (mediaQuery.matches && label.getClientRects().length > 1) {
          container.classList.add(compactClass);
        }
      }

      if (typeof mediaQuery.addEventListener === 'function') {
        mediaQuery.addEventListener('change', updateFontSize);
      } else if (typeof mediaQuery.addListener === 'function') {
        mediaQuery.addListener(updateFontSize);
      }
      window.addEventListener('resize', updateFontSize);

      if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(updateFontSize);
      } else {
        updateFontSize();
      }
    }

    bindAdaptiveFont(
      '.layout-navbar',
      '[data-problem-list-label="desktop"]',
      window.matchMedia('(min-width: 992px)')
    );
    bindAdaptiveFont(
      '.layout-offcanvas-nav',
      '[data-problem-list-label="mobile"]',
      window.matchMedia('(max-width: 991.98px)')
    );
  }

  function initClassManager() {
    const modalEl = document.getElementById('classManagerModal');
    if (!modalEl) return;

    const myBox = document.getElementById('myClassesBox');
    const membershipCount = document.getElementById('classMembershipCount');
    const joinSelect = document.getElementById('joinClassSelect');
    const joinPickerElement = document.getElementById('joinClassPicker');
    const joinButton = document.getElementById('joinClassBtn');
    const switchEl = document.getElementById('classAdjustSwitch');
    const switchLabel = document.getElementById('classAdjustLabel');
    const isAdmin = modalEl.dataset.isAdmin === '1';
    const endpoints = {
      classes: modalEl.dataset.classesUrl,
      join: modalEl.dataset.joinClassUrl,
      leave: modalEl.dataset.leaveClassUrl,
      classAdjust: modalEl.dataset.classAdjustUrl,
    };
    let classAdjustEnabled = modalEl.dataset.classAdjustEnabled === '1';
    const model = { memberships: [], all_classes: [] };
    const classSelect = window.NumojClassSelect;
    const joinPicker = classSelect?.create(joinPickerElement);
    if (!joinSelect || !joinPicker || !classSelect) return;

    function className(classEn) {
      const item = model.all_classes.find((candidate) => candidate.class_en === classEn);
      return (item && (item.class_cn || item.class_en)) || classEn;
    }

    function postForm(url, values) {
      const form = new FormData();
      Object.entries(values).forEach(([key, value]) => form.append(key, value));
      return requestJson(
        url,
        { method: 'POST', headers: { Accept: 'application/json' }, body: form },
        '操作失败，请稍后重试'
      );
    }

    function renderJoinSelect() {
      const owned = new Set(model.memberships.map((membership) => membership.class_en));
      joinPicker.setItems(model.all_classes.map((item) => ({
        ...item,
        disabled: owned.has(item.class_en),
        disabled_label: '已加入',
      })));
      joinPicker.setReady();
    }

    function canAdjustClasses() {
      return isAdmin || classAdjustEnabled;
    }

    function leaveClass(classEn) {
      postForm(endpoints.leave, { class_en: classEn })
        .then((data) => {
          if (!data.success) throw new Error(data.message || '退出失败');
          model.memberships = model.memberships.filter(
            (membership) => membership.class_en !== classEn
          );
          renderMyClasses();
          renderJoinSelect();
          updateJoinLeaveAvailability();
          showAccountToast('已退出「' + className(classEn) + '」');
        })
        .catch((error) => {
          showAccountToast(error.message || '退出班级失败');
          renderMyClasses();
        });
    }

    function renderMyClasses() {
      myBox.innerHTML = '';
      membershipCount.textContent =
        `${model.memberships.length} MEMBERSHIP${model.memberships.length === 1 ? '' : 'S'}`;
      if (!model.memberships.length) {
        const empty = document.createElement('div');
        empty.className = 'numoj-membership-state';
        empty.textContent = '暂无班级';
        myBox.appendChild(empty);
        return;
      }

      model.memberships.forEach((membership) => {
        const row = document.createElement('div');
        row.className = 'numoj-membership-row';
        row.dataset.classEn = membership.class_en;

        const copy = document.createElement('span');
        copy.className = 'numoj-membership-copy';
        const nameLine = document.createElement('span');
        nameLine.className = 'numoj-membership-name';
        const name = document.createElement('strong');
        name.textContent = membership.class_cn || membership.class_en;
        nameLine.appendChild(name);

        const code = document.createElement('span');
        code.className = 'numoj-membership-code';
        code.textContent = membership.class_en;
        copy.appendChild(nameLine);
        copy.appendChild(code);

        const actions = document.createElement('div');
        actions.className = 'numoj-membership-actions';

        const leaveButton = document.createElement('button');
        leaveButton.type = 'button';
        leaveButton.className = 'numoj-membership-action is-danger';
        leaveButton.textContent = '退出';
        leaveButton.disabled =
          !canAdjustClasses() || (!isAdmin && model.memberships.length <= 1);
        leaveButton.setAttribute(
          'aria-label',
          `退出「${membership.class_cn || membership.class_en}」`
        );
        let confirmTimer;
        leaveButton.addEventListener('click', () => {
          if (leaveButton.disabled) return;
          if (!leaveButton.classList.contains('is-confirming')) {
            leaveButton.classList.add('is-confirming');
            leaveButton.textContent = '再次点击确认';
            window.clearTimeout(confirmTimer);
            confirmTimer = window.setTimeout(() => {
              leaveButton.classList.remove('is-confirming');
              leaveButton.textContent = '退出';
            }, 3000);
            return;
          }
          window.clearTimeout(confirmTimer);
          leaveButton.disabled = true;
          leaveClass(membership.class_en);
        });
        actions.appendChild(leaveButton);

        row.appendChild(
          classSelect.createLogo(membership, 'numoj-membership-logo')
        );
        row.appendChild(copy);
        row.appendChild(actions);
        myBox.appendChild(row);
      });
    }

    function updateJoinLeaveAvailability() {
      joinButton.disabled = !joinSelect.value || !canAdjustClasses();
    }

    function loadClasses() {
      myBox.innerHTML = '';
      const loading = document.createElement('div');
      loading.className = 'numoj-membership-state';
      if (window.MathCurveLoader) {
        loading.innerHTML = window.MathCurveLoader.markup('正在加载班级…', 'sm');
      } else {
        loading.textContent = '正在加载班级…';
      }
      myBox.appendChild(loading);
      membershipCount.textContent = '正在加载';
      joinButton.disabled = true;
      joinPicker.setLoading();
      requestJson(
        endpoints.classes,
        { headers: { Accept: 'application/json' }, mathCurveLoader: true },
        '班级加载失败'
      )
        .then((data) => {
          model.memberships = data.memberships || [];
          model.all_classes = data.all_classes || [];
          renderMyClasses();
          renderJoinSelect();
          updateJoinLeaveAvailability();
        })
        .catch((error) => {
          myBox.innerHTML = '';
          const message = document.createElement('div');
          message.className = 'numoj-membership-state is-error';
          message.textContent = error.message || '班级加载失败';
          myBox.appendChild(message);
          membershipCount.textContent = 'LOAD FAILED';
          joinPicker.setLoading('加载失败');
        });
    }

    modalEl.addEventListener('show.bs.modal', loadClasses);

    joinButton.addEventListener('click', () => {
      const classEn = joinSelect.value;
      if (!classEn || !canAdjustClasses()) {
        showAccountToast(
          classEn ? '当前不允许调整班级，请联系老师' : '请选择班级'
        );
        return;
      }
      joinButton.disabled = true;
      postForm(endpoints.join, { class_en: classEn })
        .then((data) => {
          if (!data.success) throw new Error(data.message || '加入失败');
          model.memberships.push({
            class_en: classEn,
            class_cn: data.class_cn || className(classEn),
            logo: (model.all_classes.find(
              (candidate) => candidate.class_en === classEn
            ) || {}).logo,
          });
          renderMyClasses();
          renderJoinSelect();
          showAccountToast('已加入「' + (data.class_cn || className(classEn)) + '」');
        })
        .catch((error) => {
          showAccountToast(error.message || '加入班级失败');
        })
        .finally(() => {
          updateJoinLeaveAvailability();
        });
    });

    joinSelect.addEventListener('change', updateJoinLeaveAvailability);

    if (isAdmin && switchEl) {
      switchEl.addEventListener('change', () => {
        switchEl.disabled = true;
        postForm(endpoints.classAdjust, { enabled: switchEl.checked ? '1' : '0' })
          .then((data) => {
            classAdjustEnabled = Boolean(data.enabled);
            switchEl.checked = classAdjustEnabled;
            if (switchLabel) {
              switchLabel.textContent =
                '学生自助：' + (classAdjustEnabled ? '允许' : '禁止');
            }
            renderMyClasses();
            updateJoinLeaveAvailability();
            showAccountToast(
              classAdjustEnabled
                ? '已允许学生自助调整班级'
                : '已禁止学生自助调整班级'
            );
          })
          .catch((error) => {
            showAccountToast(error.message || '班级权限保存失败');
            switchEl.checked = classAdjustEnabled;
          })
          .finally(() => {
            switchEl.disabled = false;
          });
      });
    }
  }

  function initPasswordForm() {
    const form = document.getElementById('passwordForm');
    if (!form) return;

    const modalEl = document.getElementById('changePasswordModal');
    const sendCodeButton = document.getElementById('sendPasswordCodeBtn');
    const codeInput = document.getElementById('passwordCodeInput');
    const codeMessage = document.getElementById('passwordCodeMessage');
    const newPassword = document.getElementById('newPasswordInput');
    const confirmPassword = document.getElementById('confirmPasswordInput');
    const matchMessage = document.getElementById('passwordMatchMessage');
    const strengthLabel = document.getElementById('passwordStrengthLabel');
    const strengthMeter = document.getElementById('passwordStrengthMeter');
    const strengthBars = [...strengthMeter.querySelectorAll('span')];
    const ruleLength = document.getElementById('passwordRuleLength');
    const ruleMix = document.getElementById('passwordRuleMix');
    const formStatus = document.getElementById('passwordFormStatus');
    const submitButton = document.getElementById('passwordSubmitBtn');
    let codeTimer;
    let isSubmitting = false;

    function validatePassword() {
      const password = newPassword.value;
      const confirmation = confirmPassword.value;
      const longEnough = password.length >= 6;
      const mixed = /[A-Za-z]/.test(password) && /\d/.test(password);
      const matches = confirmation.length > 0 && confirmation === password;
      const hasCode = codeInput.value.length === 6;

      ruleLength.classList.toggle('is-passed', longEnough);
      ruleMix.classList.toggle('is-passed', mixed);
      confirmPassword.setAttribute(
        'aria-invalid',
        String(confirmation.length > 0 && !matches)
      );

      if (!confirmation) {
        setAccountMessage(matchMessage, '');
      } else if (matches) {
        setAccountMessage(matchMessage, '两次输入一致，可以提交。', 'success');
      } else {
        setAccountMessage(matchMessage, '两次输入不一致，请重新检查。', 'error');
      }

      const score = Math.min(
        3,
        Number(longEnough) + Number(mixed) + Number(password.length >= 10)
      );
      strengthMeter.dataset.level = String(score);
      strengthMeter.setAttribute('aria-valuenow', String(score));
      strengthBars.forEach((bar, index) => {
        bar.classList.toggle('is-on', index < score);
      });
      strengthLabel.textContent = !password
        ? '尚未输入'
        : ['较短', '可用', '良好', '更稳妥'][score];
      submitButton.disabled = isSubmitting || !(hasCode && longEnough && matches);
    }

    codeInput.addEventListener('input', () => {
      codeInput.value = codeInput.value.replace(/\D/g, '').slice(0, 6);
      setAccountMessage(formStatus, '');
      validatePassword();
    });
    [newPassword, confirmPassword].forEach((input) => {
      input.addEventListener('input', () => {
        setAccountMessage(formStatus, '');
        validatePassword();
      });
    });

    sendCodeButton.addEventListener('click', async () => {
      sendCodeButton.disabled = true;
      sendCodeButton.textContent = '正在发送…';
      setAccountMessage(codeMessage, '正在发送验证码…');
      try {
        await requestJson(
          form.dataset.passwordCodeUrl,
          {
            method: 'POST',
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({ email: form.dataset.userEmail }).toString(),
          },
          '验证码发送失败'
        );
        let seconds = 60;
        setAccountMessage(
          codeMessage,
          '验证码已发送，请在 5 分钟内完成验证。',
          'success'
        );
        showAccountToast('验证码已发送');
        window.clearInterval(codeTimer);
        const updateCountdown = () => {
          sendCodeButton.textContent = `${seconds}秒后重发`;
          seconds -= 1;
          if (seconds < 0) {
            window.clearInterval(codeTimer);
            sendCodeButton.disabled = false;
            sendCodeButton.textContent = '发送验证码';
          }
        };
        updateCountdown();
        codeTimer = window.setInterval(updateCountdown, 1000);
      } catch (error) {
        setAccountMessage(
          codeMessage,
          error.message || '验证码发送失败',
          'error'
        );
        sendCodeButton.disabled = false;
        sendCodeButton.textContent = '发送验证码';
      }
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      validatePassword();
      if (submitButton.disabled) return;

      isSubmitting = true;
      submitButton.disabled = true;
      submitButton.textContent = '正在保存…';
      setAccountMessage(formStatus, '');
      try {
        const data = await requestJson(
          form.action,
          {
            method: 'POST',
            headers: {
              Accept: 'application/json',
              'X-Requested-With': 'XMLHttpRequest',
            },
            body: new FormData(form),
          },
          '密码修改失败'
        );
        setAccountMessage(
          formStatus,
          data.message || '密码修改成功',
          'success'
        );
        submitButton.textContent = '已修改';
        showAccountToast(data.message || '密码修改成功');
        window.setTimeout(() => {
          const modal = window.bootstrap?.Modal.getInstance(modalEl);
          modal?.hide();
          form.reset();
          isSubmitting = false;
          submitButton.textContent = '确认修改';
          setAccountMessage(formStatus, '');
          setAccountMessage(matchMessage, '');
          validatePassword();
        }, 700);
      } catch (error) {
        isSubmitting = false;
        submitButton.textContent = '确认修改';
        setAccountMessage(
          formStatus,
          error.message || '密码修改失败',
          'error'
        );
        validatePassword();
      }
    });

    validatePassword();
  }

  initUserAvatar();
  initDesktopSidebar();
  initDesktopNavigationData();
  initAdaptiveNavigation();
  initClassManager();
  initPasswordForm();
})();
