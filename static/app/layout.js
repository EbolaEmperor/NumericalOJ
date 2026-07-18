(function () {
  'use strict';

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
    const joinSelect = document.getElementById('joinClassSelect');
    const joinButton = document.getElementById('joinClassBtn');
    const switchEl = document.getElementById('classAdjustSwitch');
    const switchLabel = document.getElementById('classAdjustLabel');
    const isAdmin = modalEl.dataset.isAdmin === '1';
    const endpoints = {
      classes: modalEl.dataset.classesUrl,
      join: modalEl.dataset.joinClassUrl,
      leave: modalEl.dataset.leaveClassUrl,
      setPrimary: modalEl.dataset.setPrimaryClassUrl,
      classAdjust: modalEl.dataset.classAdjustUrl,
    };
    let classAdjustEnabled = modalEl.dataset.classAdjustEnabled === '1';
    const model = { memberships: [], primary_en: '', all_classes: [] };

    function toast(message) {
      console.log(message);
    }

    function className(classEn) {
      const item = model.all_classes.find((candidate) => candidate.class_en === classEn);
      return (item && (item.class_cn || item.class_en)) || classEn;
    }

    function postForm(url, values) {
      const form = new FormData();
      Object.entries(values).forEach(([key, value]) => form.append(key, value));
      return fetch(url, { method: 'POST', body: form }).then((response) => response.json());
    }

    function renderJoinSelect() {
      const owned = new Set(model.memberships.map((membership) => membership.class_en));
      joinSelect.innerHTML = '<option value="">请选择班级</option>';
      model.all_classes.forEach((item) => {
        const option = document.createElement('option');
        option.value = item.class_en;
        option.textContent = item.class_cn || item.class_en;
        option.disabled = owned.has(item.class_en);
        joinSelect.appendChild(option);
      });
    }

    function setPrimary(classEn) {
      if (!classAdjustEnabled && !isAdmin) {
        alert('当前不允许调整班级，请联系老师');
        renderMyClasses();
        return;
      }
      postForm(endpoints.setPrimary, { class_en: classEn })
        .then((data) => {
          if (!data.success) throw new Error(data.message || '设置失败');
          model.primary_en = classEn;
          model.memberships.forEach((membership) => {
            membership.is_primary = membership.class_en === classEn;
          });
          renderMyClasses();
          toast('主班级已切换为：' + className(classEn));
        })
        .catch((error) => {
          alert(error);
          renderMyClasses();
        });
    }

    function leaveClass(classEn) {
      postForm(endpoints.leave, { class_en: classEn })
        .then((data) => {
          if (!data.success) throw new Error(data.message || '退出失败');
          model.memberships = model.memberships.filter(
            (membership) => membership.class_en !== classEn
          );
          if (data.primary_en) model.primary_en = data.primary_en;
          model.memberships.forEach((membership) => {
            membership.is_primary = membership.class_en === model.primary_en;
          });
          renderMyClasses();
          renderJoinSelect();
          toast('已退出：' + className(classEn));
        })
        .catch((error) => alert(error));
    }

    function renderMyClasses() {
      myBox.innerHTML = '';
      if (!model.memberships.length) {
        myBox.innerHTML = '<div class="list-group-item text-muted">暂无班级</div>';
        return;
      }

      model.memberships.forEach((membership) => {
        const row = document.createElement('div');
        row.className = 'list-group-item class-row';

        const left = document.createElement('div');
        left.className = 'class-left';

        const radioWrap = document.createElement('label');
        radioWrap.className = 'radio-wrap';
        const radio = document.createElement('input');
        radio.type = 'radio';
        radio.name = 'primaryClass';
        radio.value = membership.class_en;
        radio.checked = Boolean(membership.is_primary);
        radio.addEventListener('change', () => setPrimary(membership.class_en));
        radioWrap.appendChild(radio);
        radioWrap.appendChild(document.createTextNode('主'));
        left.appendChild(radioWrap);

        const name = document.createElement('span');
        name.className = 'class-name';
        name.textContent = membership.class_cn || membership.class_en;
        left.appendChild(name);

        if (membership.is_primary) {
          const badge = document.createElement('span');
          badge.className = 'badge bg-primary';
          badge.textContent = '主班级';
          left.appendChild(badge);
        }

        const actions = document.createElement('div');
        actions.className = 'class-actions';
        const leaveButton = document.createElement('button');
        leaveButton.className = 'btn btn-sm btn-outline-danger';
        leaveButton.innerHTML = '<i class="fas fa-sign-out-alt me-1"></i> 退出';
        leaveButton.disabled = model.memberships.length <= 1;
        leaveButton.addEventListener('click', () => {
          if (leaveButton.disabled) return;
          const displayName = membership.class_cn || membership.class_en;
          if (confirm(`确认退出「${displayName}」吗？`)) {
            leaveClass(membership.class_en);
          }
        });
        actions.appendChild(leaveButton);

        row.appendChild(left);
        row.appendChild(actions);
        myBox.appendChild(row);
      });
    }

    function updateJoinLeaveAvailability() {
      joinButton.disabled = !isAdmin && !classAdjustEnabled;
    }

    function loadClasses() {
      myBox.innerHTML =
        '<div class="list-group-item text-muted">' +
        MathCurveLoader.markup('正在加载班级…', 'sm') +
        '</div>';
      joinSelect.innerHTML = '<option value="">正在加载…</option>';
      fetch(endpoints.classes, { mathCurveLoader: true })
        .then((response) => response.json())
        .then((data) => {
          if (!data.success) throw new Error(data.message || '加载失败');
          model.memberships = data.memberships || [];
          model.primary_en = data.primary_en || '';
          model.all_classes = data.all_classes || [];
          renderMyClasses();
          renderJoinSelect();
          updateJoinLeaveAvailability();
        })
        .catch((error) => {
          myBox.innerHTML = '';
          const message = document.createElement('div');
          message.className = 'list-group-item text-danger';
          message.textContent = `加载失败：${error}`;
          myBox.appendChild(message);
          joinSelect.innerHTML = '<option value="">加载失败</option>';
        });
    }

    modalEl.addEventListener('show.bs.modal', loadClasses);

    joinButton.addEventListener('click', () => {
      const classEn = joinSelect.value;
      if (!classEn) {
        alert('请选择班级');
        return;
      }
      if (!classAdjustEnabled && !isAdmin) {
        alert('当前不允许调整班级，请联系老师');
        return;
      }
      joinButton.disabled = true;
      postForm(endpoints.join, { class_en: classEn })
        .then((data) => {
          if (!data.success) throw new Error(data.message || '加入失败');
          model.memberships.push({
            class_en: classEn,
            class_cn: data.class_cn || className(classEn),
            is_primary: false,
          });
          renderMyClasses();
          renderJoinSelect();
          toast('已加入：' + (data.class_cn || className(classEn)));
        })
        .catch((error) => alert(error))
        .finally(() => {
          joinButton.disabled = false;
        });
    });

    if (isAdmin && switchEl) {
      switchEl.addEventListener('change', () => {
        postForm(endpoints.classAdjust, { enabled: switchEl.checked ? '1' : '0' })
          .then((data) => {
            if (!data.success) throw new Error(data.message || '保存失败');
            classAdjustEnabled = Boolean(data.enabled);
            switchEl.checked = classAdjustEnabled;
            if (switchLabel) switchLabel.textContent = classAdjustEnabled ? '允许' : '禁止';
            updateJoinLeaveAvailability();
            toast('已保存：' + (classAdjustEnabled ? '允许' : '禁止'));
          })
          .catch((error) => {
            alert(error);
            switchEl.checked = classAdjustEnabled;
          });
      });
    }
  }

  function initPasswordForm() {
    const form = document.getElementById('passwordForm');
    if (!form) return;

    const sendCodeButton = document.getElementById('sendPasswordCodeBtn');
    sendCodeButton.addEventListener('click', () => {
      sendCodeButton.disabled = true;
      fetch(form.dataset.passwordCodeUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: form.dataset.userEmail }).toString(),
      })
        .then((response) => response.json())
        .then((data) => {
          if (!data.success) {
            alert(data.message);
            sendCodeButton.disabled = false;
            return;
          }
          let seconds = 60;
          const timer = window.setInterval(() => {
            sendCodeButton.textContent = `${seconds}秒后重发`;
            seconds -= 1;
            if (seconds < 0) {
              window.clearInterval(timer);
              sendCodeButton.disabled = false;
              sendCodeButton.textContent = '发送验证码';
            }
          }, 1000);
        })
        .catch(() => {
          sendCodeButton.disabled = false;
        });
    });

    form.addEventListener('submit', (event) => {
      event.preventDefault();
      fetch(form.action, { method: 'POST', body: new FormData(form) })
        .then((response) => {
          if (response.redirected) {
            window.location.href = response.url;
            return null;
          }
          return response.text();
        })
        .then((text) => {
          if (text === null) return;
          const documentFragment = new DOMParser().parseFromString(text, 'text/html');
          const error = documentFragment.querySelector('.alert-danger');
          if (error) alert(error.textContent);
        });
    });
  }

  initAdaptiveNavigation();
  initClassManager();
  initPasswordForm();
})();
