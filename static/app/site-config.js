(() => {
  'use strict';

  const root = document.querySelector('[data-site-config]');
  if (!root) return;

  const apiRoot = String(root.dataset.apiRoot || '/api/admin/dynamic-config').replace(/\/$/, '');
  const currentUserId = Number(root.dataset.currentUserId || 0);
  const REQUIRED_UNLOCK_PHRASE = '我已阅读上述内容，我清楚后果，我坚持要解锁';
  const mobileRailQuery = window.matchMedia('(max-width: 991.98px)');

  const $ = (selector, scope = root) => scope.querySelector(selector);
  const $$ = (selector, scope = root) => Array.from(scope.querySelectorAll(selector));
  const escapeHtml = (value) => String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  const protocolLabels = {openai: 'OpenAI 兼容', anthropic: 'Anthropic 兼容'};
  const protocolIcons = {openai: 'fa-code', anthropic: 'fa-brain'};
  const categoryLabels = {omni: '全模态', text: '纯文本', vision: '视觉理解', embedding: 'Embedding'};
  const categoryIcons = {omni: 'fa-layer-group', text: 'fa-font', vision: 'fa-eye', embedding: 'fa-vector-square'};
  const featureIcons = {
    ai_code_annotation: 'fa-highlighter',
    code_image_analysis: 'fa-image',
    solution_agent: 'fa-terminal',
    testdata_agent: 'fa-vials',
    agent_summary: 'fa-compress-alt',
    repository_query_summary: 'fa-search-plus',
    repository_structuring: 'fa-sitemap',
    repository_embedding: 'fa-vector-square',
  };

  const state = {
    meta: {
      protocols: ['openai', 'anthropic'],
      categories: ['omni', 'text', 'vision', 'embedding'],
      thinking_formats: ['enable_thinking', 'thinking_type', 'none'],
      features: [],
      unlock_confirmations: {},
    },
    endpoints: [],
    bindings: [],
    endpointTestToken: '',
    endpointFormFingerprint: '',
    lockTarget: null,
    unlockTarget: null,
    deleteTarget: null,
    featureControllers: new Map(),
    railReturnFocus: null,
  };

  const modal = (id) => bootstrap.Modal.getOrCreateInstance(document.getElementById(id));

  async function request(path, options = {}) {
    const init = {credentials: 'same-origin', ...options};
    init.headers = {Accept: 'application/json', ...(options.headers || {})};
    if (options.body && typeof options.body !== 'string') {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    const response = await fetch(`${apiRoot}${path}`, init);
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json')
      ? await response.json()
      : {success: false, message: await response.text()};
    if (!response.ok || payload.success === false) {
      const error = new Error(payload.message || payload.error || `请求失败（HTTP ${response.status}）`);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  function toast(message, type = 'success') {
    const region = $('[data-toast-region]');
    const item = document.createElement('div');
    item.className = `site-config-toast${type === 'error' ? ' is-error' : ''}`;
    item.innerHTML = `<i class="fas ${type === 'error' ? 'fa-exclamation-circle' : 'fa-check-circle'}" aria-hidden="true"></i><span>${escapeHtml(message)}</span>`;
    region.appendChild(item);
    window.setTimeout(() => item.remove(), type === 'error' ? 6500 : 3500);
  }

  function setBusy(button, busy, busyText = '处理中…') {
    if (!button) return;
    if (busy) {
      button.dataset.originalHtml = button.innerHTML;
      button.disabled = true;
      button.innerHTML = `<span class="site-config-spinner" aria-hidden="true"></span>${escapeHtml(busyText)}`;
      return;
    }
    button.disabled = false;
    if (button.dataset.originalHtml) button.innerHTML = button.dataset.originalHtml;
    delete button.dataset.originalHtml;
  }

  function values(items, fallback) {
    const source = Array.isArray(items) && items.length ? items : fallback;
    return source
      .map((item) => typeof item === 'string' ? item : item.value || item.key)
      .filter(Boolean);
  }

  function canUnlock(item) {
    if (typeof item.can_unlock === 'boolean') return item.can_unlock;
    return Boolean(currentUserId && Number(item.locked_by_user_id) === currentUserId);
  }

  function choiceOptionMarkup(entry) {
    const classes = ['rk-choice-option'];
    if (entry.missing) classes.push('is-missing');
    const meta = entry.meta
      ? `<span class="rk-choice-option-meta">${escapeHtml(entry.meta)}</span>`
      : '';
    return `
      <button type="button"
              class="${classes.join(' ')}"
              role="option"
              aria-selected="false"
              data-choice-value="${escapeHtml(entry.value)}"
              data-choice-label="${escapeHtml(entry.label)}"
              data-choice-icon="${escapeHtml(entry.icon || 'fa-circle')}">
        <span class="rk-choice-option-main">
          <i class="fas ${escapeHtml(entry.icon || 'fa-circle')}" aria-hidden="true"></i>
          <span>
            <span class="rk-choice-option-name">${escapeHtml(entry.label)}</span>
            ${meta}
          </span>
        </span>
        <i class="fas fa-check rk-choice-option-check" aria-hidden="true"></i>
      </button>`;
  }

  function configureChoice(picker, entries, value, {disabled = false} = {}) {
    if (!picker || !window.ChoicePicker) return null;
    const input = $('input[type="hidden"]', picker);
    const menu = $('.rk-choice-menu', picker);
    menu.innerHTML = entries.map(choiceOptionMarkup).join('');
    let controller = picker.__choicePickerController;
    if (!controller) {
      controller = window.ChoicePicker.create({
        picker,
        input,
        trigger: $('.rk-choice-trigger', picker),
        menu,
        label: $('[data-rk-choice-label]', picker),
        icon: $('[data-rk-choice-icon]', picker),
      });
    }
    if (!controller) return null;
    controller.refresh();
    controller.setValue(value == null ? '' : String(value), false);
    controller.setDisabled(disabled);
    return controller;
  }

  function enumEntries(items, fallback, labels, icons) {
    return values(items, fallback).map((value) => ({
      value,
      label: labels[value] || value,
      icon: icons[value] || 'fa-circle',
    }));
  }

  function endpointChoice(kind) {
    return $(`[data-choice-kind="${kind}"]`, $('[data-endpoint-form]'));
  }

  function setEndpointChoice(kind, value) {
    const picker = endpointChoice(kind);
    const controller = picker && picker.__choicePickerController;
    if (controller) controller.setValue(value, false);
    else if (picker) $('input[type="hidden"]', picker).value = value;
  }

  function initializeMetaControls() {
    const form = $('[data-endpoint-form]');
    configureChoice(
      endpointChoice('protocol'),
      enumEntries(state.meta.protocols, ['openai', 'anthropic'], protocolLabels, protocolIcons),
      form.elements.protocol.value || 'openai',
    );
    configureChoice(
      endpointChoice('category'),
      enumEntries(state.meta.categories, ['omni', 'text', 'vision', 'embedding'], categoryLabels, categoryIcons),
      form.elements.category.value || 'text',
    );
    updateThinkingControls(true);
  }

  function testStatus(endpoint) {
    const raw = String(endpoint.test_status || 'untested').toLowerCase();
    if (['passed', 'success', 'ok'].includes(raw)) {
      const latency = endpoint.test_latency_ms != null ? ` · ${endpoint.test_latency_ms} ms` : '';
      return {className: 'is-ok', label: `连接正常${latency}`};
    }
    if (['failed', 'error'].includes(raw)) return {className: 'is-failed', label: '最近测试失败'};
    return {className: '', label: '尚未测试'};
  }

  function endpointCard(endpoint, position) {
    const status = testStatus(endpoint);
    const locked = Boolean(endpoint.is_locked);
    const apiKey = endpoint.api_key_configured ? '密钥已配置' : '密钥缺失';
    return `
      <article class="site-config-endpoint-card" data-endpoint-id="${Number(endpoint.id)}">
        <div class="site-config-endpoint-main">
          <div class="site-config-endpoint-top">
            <div>
              <span class="site-config-endpoint-number">端点 ${String(position + 1).padStart(2, '0')}</span>
              <h3 class="site-config-endpoint-title" title="${escapeHtml(endpoint.model)}">${escapeHtml(endpoint.model)}</h3>
            </div>
            <div class="site-config-endpoint-chips">
              <span class="site-config-chip is-protocol">${escapeHtml(protocolLabels[endpoint.protocol] || endpoint.protocol)}</span>
              <span class="site-config-chip">${escapeHtml(categoryLabels[endpoint.category] || endpoint.category)}</span>
            </div>
          </div>
          <div class="site-config-endpoint-url"><small>地址 · ${escapeHtml(apiKey)}</small><span title="${escapeHtml(endpoint.base_url)}">${escapeHtml(endpoint.base_url)}</span></div>
        </div>
        <footer class="site-config-endpoint-foot">
          <span class="site-config-test-state ${status.className}" title="${escapeHtml(endpoint.test_message || '')}"><i aria-hidden="true"></i>${escapeHtml(status.label)}</span>
          ${locked ? '' : `
            <button class="site-config-icon-button" type="button" data-endpoint-action="test" title="复测连接" aria-label="复测 ${escapeHtml(endpoint.model)}"><i class="fas fa-vial" aria-hidden="true"></i></button>
            <button class="site-config-icon-button" type="button" data-endpoint-action="lock" title="加锁" aria-label="加锁 ${escapeHtml(endpoint.model)}"><i class="fas fa-lock" aria-hidden="true"></i></button>
            <button class="site-config-icon-button" type="button" data-endpoint-action="edit" title="编辑" aria-label="编辑 ${escapeHtml(endpoint.model)}"><i class="fas fa-pen" aria-hidden="true"></i></button>
            <button class="site-config-icon-button is-danger" type="button" data-endpoint-action="delete" title="删除" aria-label="删除 ${escapeHtml(endpoint.model)}"><i class="fas fa-trash-alt" aria-hidden="true"></i></button>`}
        </footer>
        ${locked ? '<div class="site-config-lock-overlay"><button type="button" data-endpoint-action="unlock"><i class="fas fa-unlock-alt" aria-hidden="true"></i> 解锁</button></div>' : ''}
      </article>`;
  }

  function renderEndpoints() {
    const grid = $('[data-endpoint-grid]');
    const empty = $('[data-endpoint-empty]');
    $('[data-endpoint-loading]').hidden = true;
    $('[data-endpoint-count]').textContent = String(state.endpoints.length);
    grid.innerHTML = state.endpoints.map(endpointCard).join('');
    grid.hidden = state.endpoints.length === 0;
    empty.hidden = state.endpoints.length !== 0;
  }

  function featureMeta(binding) {
    return state.meta.features.find((item) => (item.key || item.feature_key) === binding.feature_key) || binding;
  }

  function candidatesFor(binding) {
    const allowed = binding.allowed_categories || featureMeta(binding).allowed_categories || [];
    return state.endpoints.filter((endpoint) => allowed.includes(endpoint.category));
  }

  function featureChoiceMarkup(key, label) {
    const token = `feature-${String(key).replace(/[^a-zA-Z0-9_-]/g, '-')}`;
    return `
      <div class="rk-choice site-config-choice" data-feature-choice>
        <input type="hidden" data-feature-select value="">
        <button type="button"
                class="rk-choice-trigger"
                id="${token}-trigger"
                role="combobox"
                aria-haspopup="listbox"
                aria-expanded="false"
                aria-controls="${token}-menu"
                aria-label="${escapeHtml(label)}端点">
          <span class="rk-choice-trigger-main">
            <i class="fas fa-minus-circle" data-rk-choice-icon aria-hidden="true"></i>
            <span data-rk-choice-label></span>
          </span>
          <i class="fas fa-chevron-down rk-choice-caret" aria-hidden="true"></i>
        </button>
        <div class="rk-choice-menu"
             id="${token}-menu"
             role="listbox"
             aria-labelledby="${token}-trigger"></div>
      </div>`;
  }

  function featureCard(binding) {
    const meta = featureMeta(binding);
    const key = binding.feature_key || meta.key;
    const label = binding.label || meta.label || key;
    const lockable = Boolean(meta.lockable || key === 'repository_embedding');
    const locked = lockable && Boolean(binding.is_locked);
    return `
      <article class="site-config-feature-card${lockable ? ' is-embedding' : ''}" data-feature-key="${escapeHtml(key)}">
        <span class="site-config-feature-icon"><i class="fas ${escapeHtml(featureIcons[key] || 'fa-cog')}" aria-hidden="true"></i></span>
        <div class="site-config-feature-copy">
          <div class="site-config-feature-head">
            <h3>${escapeHtml(label)}</h3>
            ${lockable && !locked ? '<button class="site-config-icon-button site-config-feature-lock" type="button" data-feature-lock title="加锁" aria-label="加锁"><i class="fas fa-lock" aria-hidden="true"></i></button>' : ''}
          </div>
          <div class="site-config-feature-control">
            ${featureChoiceMarkup(key, label)}
            <span class="site-config-feature-saving" data-feature-saving aria-live="polite"></span>
          </div>
        </div>
        ${locked ? '<div class="site-config-lock-overlay"><button type="button" data-feature-unlock><i class="fas fa-unlock-alt" aria-hidden="true"></i> 解锁</button></div>' : ''}
      </article>`;
  }

  function featureOptions(binding) {
    const selectedId = binding.endpoint_id == null ? '' : String(binding.endpoint_id);
    const candidates = candidatesFor(binding);
    const selectedEndpoint = state.endpoints.find((endpoint) => String(endpoint.id) === selectedId);
    const selectedIsCandidate = candidates.some((endpoint) => String(endpoint.id) === selectedId);
    const options = [{value: '', label: '未配置', icon: 'fa-minus-circle'}];
    if (selectedId && !selectedIsCandidate) {
      options.push({
        value: selectedId,
        label: selectedEndpoint ? selectedEndpoint.model : `端点 ${selectedId}`,
        meta: selectedEndpoint
          ? `${protocolLabels[selectedEndpoint.protocol] || selectedEndpoint.protocol} · ${categoryLabels[selectedEndpoint.category] || selectedEndpoint.category}`
          : '端点已删除',
        icon: 'fa-exclamation-triangle',
        missing: true,
      });
    }
    candidates.forEach((endpoint) => {
      options.push({
        value: String(endpoint.id),
        label: endpoint.model,
        meta: `${protocolLabels[endpoint.protocol] || endpoint.protocol} · ${categoryLabels[endpoint.category] || endpoint.category}`,
        icon: categoryIcons[endpoint.category] || 'fa-circle',
      });
    });
    return options;
  }

  function renderBindings() {
    const grid = $('[data-feature-grid]');
    state.featureControllers.clear();
    grid.innerHTML = state.bindings.map(featureCard).join('');
    state.bindings.forEach((binding) => {
      const card = $(`[data-feature-key="${CSS.escape(binding.feature_key)}"]`, grid);
      if (!card) return;
      const controller = configureChoice(
        $('[data-feature-choice]', card),
        featureOptions(binding),
        binding.endpoint_id == null ? '' : String(binding.endpoint_id),
        {disabled: Boolean(binding.is_locked)},
      );
      if (controller) state.featureControllers.set(binding.feature_key, controller);
    });
  }

  function endpointPayload(form) {
    return {
      endpoint_id: form.elements.endpoint_id.value ? Number(form.elements.endpoint_id.value) : undefined,
      protocol: form.elements.protocol.value,
      category: form.elements.category.value,
      base_url: form.elements.base_url.value.trim(),
      api_key: form.elements.api_key.value,
      model: form.elements.model.value.trim(),
      thinking_enabled: form.elements.thinking_enabled.value === 'true',
      thinking_format: form.elements.thinking_format.value,
    };
  }

  function fingerprint(payload) {
    return JSON.stringify(payload, Object.keys(payload).sort());
  }

  function invalidateEndpointTest() {
    state.endpointTestToken = '';
    state.endpointFormFingerprint = '';
    $('[data-endpoint-save]').disabled = true;
    $('[data-endpoint-test-result]').hidden = true;
  }

  function setThinking(enabled) {
    const form = $('[data-endpoint-form]');
    const button = $('[data-thinking-switch]', form);
    const active = Boolean(enabled) && form.elements.category.value !== 'embedding';
    form.elements.thinking_enabled.value = active ? 'true' : 'false';
    form.elements.thinking_format.value = active
      ? (form.elements.protocol.value === 'anthropic' ? 'thinking_type' : 'enable_thinking')
      : 'none';
    button.setAttribute('aria-checked', active ? 'true' : 'false');
    $('[data-thinking-switch-label]', button).textContent = active ? '开启' : '关闭';
  }

  function updateThinkingControls(preserve = true) {
    const form = $('[data-endpoint-form]');
    let protocol = form.elements.protocol.value || 'openai';
    const category = form.elements.category.value || 'text';
    if (category === 'embedding' && protocol !== 'openai') {
      protocol = 'openai';
      setEndpointChoice('protocol', protocol);
    }
    const wasEnabled = preserve && form.elements.thinking_enabled.value === 'true';
    $('[data-thinking-toggle-field]', form).hidden = category === 'embedding';
    setThinking(wasEnabled);
  }

  function openEndpointModal(endpoint = null) {
    const form = $('[data-endpoint-form]');
    form.reset();
    initializeMetaControls();
    $('[data-endpoint-modal-title]').textContent = endpoint ? '编辑端点' : '新建端点';
    form.elements.endpoint_id.value = endpoint?.id || '';
    setEndpointChoice('protocol', endpoint?.protocol || values(state.meta.protocols, ['openai'])[0]);
    setEndpointChoice('category', endpoint?.category || values(state.meta.categories, ['text'])[0]);
    form.elements.base_url.value = endpoint?.base_url || '';
    form.elements.api_key.value = '';
    form.elements.model.value = endpoint?.model || '';
    updateThinkingControls(false);
    setThinking(Boolean(endpoint?.thinking_enabled));
    invalidateEndpointTest();
    modal('endpointModal').show();
  }

  async function testEndpoint(form, button) {
    if (!form.reportValidity()) return;
    const payload = endpointPayload(form);
    if (!payload.endpoint_id && !payload.api_key.trim()) {
      form.elements.api_key.setCustomValidity('创建端点时必须填写 API 密钥');
      form.elements.api_key.reportValidity();
      form.elements.api_key.setCustomValidity('');
      return;
    }
    const resultBox = $('[data-endpoint-test-result]');
    setBusy(button, true, '测试中…');
    resultBox.hidden = false;
    resultBox.className = 'site-config-test-result';
    resultBox.textContent = '测试中…';
    try {
      const data = await request('/llm-endpoints/test', {method: 'POST', body: payload});
      state.endpointTestToken = data.test_token || data.test?.test_token || '';
      state.endpointFormFingerprint = fingerprint(payload);
      const test = data.test || data;
      resultBox.className = 'site-config-test-result is-ok';
      resultBox.textContent = `连接成功${test.latency_ms != null ? ` · ${test.latency_ms} ms` : ''}${test.message ? ` · ${test.message}` : ''}`;
      $('[data-endpoint-save]').disabled = !state.endpointTestToken;
    } catch (error) {
      state.endpointTestToken = '';
      state.endpointFormFingerprint = '';
      $('[data-endpoint-save]').disabled = true;
      resultBox.className = 'site-config-test-result is-error';
      resultBox.textContent = error.message;
    } finally {
      setBusy(button, false);
    }
  }

  async function saveEndpoint(form, button) {
    if (!form.reportValidity()) return;
    const payload = endpointPayload(form);
    if (!state.endpointTestToken || state.endpointFormFingerprint !== fingerprint(payload)) {
      invalidateEndpointTest();
      toast('字段已经变化，请重新测试连接', 'error');
      return;
    }
    payload.test_token = state.endpointTestToken;
    const id = payload.endpoint_id;
    setBusy(button, true, '保存中…');
    try {
      await request(id ? `/llm-endpoints/${id}` : '/llm-endpoints', {
        method: id ? 'PUT' : 'POST',
        body: payload,
      });
      modal('endpointModal').hide();
      toast(id ? '端点已更新' : '端点已创建');
      await loadEndpoints();
      await loadBindings();
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function retestEndpoint(endpoint, button) {
    setBusy(button, true, '');
    try {
      await request('/llm-endpoints/test', {
        method: 'POST',
        body: {
          endpoint_id: Number(endpoint.id),
          protocol: endpoint.protocol,
          category: endpoint.category,
          base_url: endpoint.base_url,
          api_key: '',
          model: endpoint.model,
          thinking_enabled: Boolean(endpoint.thinking_enabled),
          thinking_format: endpoint.thinking_format,
        },
      });
      toast(`“${endpoint.model}”连接正常`);
    } catch (error) {
      toast(`“${endpoint.model}”复测失败：${error.message}`, 'error');
    } finally {
      setBusy(button, false);
      await loadEndpoints().catch(() => {});
    }
  }

  function openLockTarget(kind, item) {
    state.lockTarget = {kind, item};
    const form = $('[data-lock-form]');
    form.reset();
    $('.modal-title', form).textContent = kind === 'endpoint' ? `加锁 · ${item.model}` : '加锁 · Embedding 绑定';
    modal('lockModal').show();
  }

  async function submitLock(form, button) {
    const target = state.lockTarget;
    if (!target || !form.reportValidity()) return;
    const path = target.kind === 'endpoint'
      ? `/llm-endpoints/${target.item.id}/lock`
      : '/feature-bindings/repository_embedding/lock';
    setBusy(button, true, '加锁中…');
    try {
      await request(path, {method: 'POST', body: {reason: form.elements.reason.value.trim()}});
      modal('lockModal').hide();
      toast('配置已加锁');
      if (target.kind === 'endpoint') await loadEndpoints();
      else await loadBindings();
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  function openUnlockTarget(kind, item) {
    state.unlockTarget = {kind, item};
    const form = $('[data-unlock-form]');
    form.reset();
    const allowed = canUnlock(item);
    $('[data-unlock-reason]', form).textContent = item.lock_reason || '未记录原因';
    $('[data-unlock-denied]', form).hidden = allowed;
    $('[data-unlock-owner-fields]', form).hidden = !allowed;
    $('[data-unlock-submit]', form).hidden = !allowed;
    const key = kind === 'endpoint' ? 'endpoint' : 'embedding_binding';
    const phrase = state.meta.unlock_confirmations?.[key] || REQUIRED_UNLOCK_PHRASE;
    $('[data-unlock-phrase]', form).textContent = phrase;
    $('[data-unlock-confirmation]', form).placeholder = phrase;
    modal('unlockModal').show();
  }

  async function submitUnlock(form, button) {
    const target = state.unlockTarget;
    if (!target || !canUnlock(target.item) || !form.reportValidity()) return;
    const key = target.kind === 'endpoint' ? 'endpoint' : 'embedding_binding';
    const phrase = state.meta.unlock_confirmations?.[key] || REQUIRED_UNLOCK_PHRASE;
    if (form.elements.confirmation.value !== phrase) {
      form.elements.confirmation.setCustomValidity('确认文本必须完全一致');
      form.elements.confirmation.reportValidity();
      form.elements.confirmation.setCustomValidity('');
      return;
    }
    const path = target.kind === 'endpoint'
      ? `/llm-endpoints/${target.item.id}/unlock`
      : '/feature-bindings/repository_embedding/unlock';
    setBusy(button, true, '解锁中…');
    try {
      await request(path, {
        method: 'POST',
        body: {password: form.elements.password.value, confirmation: form.elements.confirmation.value},
      });
      modal('unlockModal').hide();
      toast('配置已解锁');
      if (target.kind === 'endpoint') await loadEndpoints();
      else await loadBindings();
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  function openDelete(endpoint) {
    state.deleteTarget = endpoint;
    $('[data-delete-model]').textContent = endpoint.model;
    modal('deleteModal').show();
  }

  async function submitDelete(button) {
    if (!state.deleteTarget) return;
    setBusy(button, true, '删除中…');
    try {
      await request(`/llm-endpoints/${state.deleteTarget.id}`, {method: 'DELETE'});
      modal('deleteModal').hide();
      toast('端点已删除');
      await loadEndpoints();
      await loadBindings();
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function saveBinding(card, input) {
    const key = card.dataset.featureKey;
    const indicator = $('[data-feature-saving]', card);
    const previous = state.bindings.find((binding) => binding.feature_key === key)?.endpoint_id;
    const controller = state.featureControllers.get(key);
    controller?.setDisabled(true);
    indicator.className = 'site-config-feature-saving';
    indicator.textContent = '保存中…';
    try {
      const data = await request(`/feature-bindings/${encodeURIComponent(key)}`, {
        method: 'PUT',
        body: {endpoint_id: input.value ? Number(input.value) : null},
      });
      const updated = data.binding || data.settings;
      if (updated) {
        const index = state.bindings.findIndex((binding) => binding.feature_key === key);
        if (index >= 0) state.bindings[index] = updated;
      }
      indicator.className = 'site-config-feature-saving is-ok';
      indicator.textContent = '已保存';
      window.setTimeout(() => {
        if (indicator.isConnected) indicator.textContent = '';
      }, 1800);
    } catch (error) {
      controller?.setValue(previous == null ? '' : String(previous), false);
      indicator.className = 'site-config-feature-saving is-error';
      indicator.textContent = '保存失败';
      toast(error.message, 'error');
    } finally {
      const binding = state.bindings.find((item) => item.feature_key === key);
      controller?.setDisabled(Boolean(binding?.is_locked));
    }
  }

  function settingsObject(payload) {
    return payload.settings === undefined ? payload : payload.settings;
  }

  function populateMail(payload) {
    const settings = settingsObject(payload);
    const form = $('[data-mail-form]');
    form.elements.smtp_server.value = settings?.smtp_server || '';
    form.elements.smtp_port.value = settings?.smtp_port || 465;
    form.elements.smtp_username.value = settings?.smtp_username || '';
    form.elements.smtp_password.value = '';
    $('[data-mail-state]').textContent = settings ? '已配置' : '未配置';
    $('[data-mail-state]').classList.toggle('is-configured', Boolean(settings));
    $('[data-mail-clear]').disabled = !settings;
  }

  function populateSearch(payload) {
    const settings = settingsObject(payload);
    const form = $('[data-search-form]');
    form.elements.base_url.value = settings?.base_url || '';
    form.elements.authorization.value = '';
    $('[data-search-state]').textContent = settings ? '已配置' : '未配置';
    $('[data-search-state]').classList.toggle('is-configured', Boolean(settings));
    $('[data-search-clear]').disabled = !settings;
  }

  function formBody(form) {
    return Object.fromEntries(new FormData(form).entries());
  }

  async function saveService(kind, form, button) {
    if (!form.reportValidity()) return;
    const body = formBody(form);
    if (kind === 'mail') body.smtp_port = Number(body.smtp_port);
    setBusy(button, true, '保存中…');
    try {
      const data = await request(`/${kind}`, {method: 'PUT', body});
      if (kind === 'mail') populateMail(data);
      else populateSearch(data);
      toast(kind === 'mail' ? '邮件配置已保存' : '联网搜索配置已保存');
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function testService(kind, form, button) {
    if (!form.reportValidity()) return;
    const body = formBody(form);
    if (kind === 'mail') body.smtp_port = Number(body.smtp_port);
    setBusy(button, true, kind === 'mail' ? '发送中…' : '测试中…');
    try {
      const data = await request(`/${kind}/test`, {method: 'POST', body});
      const result = data.test || data;
      toast(`${kind === 'mail' ? '测试邮件已发送' : '搜索服务连接正常'}${result.latency_ms != null ? `（${result.latency_ms} ms）` : ''}`);
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function clearService(kind, button) {
    const label = kind === 'mail' ? '邮件' : '联网搜索';
    if (!window.confirm(`确定清除整组${label}配置？`)) return;
    setBusy(button, true, '清除中…');
    try {
      await request(`/${kind}`, {method: 'DELETE'});
      if (kind === 'mail') populateMail({settings: null});
      else populateSearch({settings: null});
      toast(`${label}配置已清除`);
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function loadMeta() {
    const data = await request('/meta');
    state.meta = {...state.meta, ...data};
    initializeMetaControls();
  }

  async function loadEndpoints() {
    const data = await request('/llm-endpoints');
    state.endpoints = Array.isArray(data.endpoints) ? data.endpoints : [];
    renderEndpoints();
    if (state.bindings.length) renderBindings();
  }

  async function loadBindings() {
    const data = await request('/feature-bindings');
    state.bindings = Array.isArray(data.bindings) ? data.bindings : [];
    renderBindings();
  }

  async function loadMail() {
    populateMail(await request('/mail'));
  }

  async function loadSearch() {
    populateSearch(await request('/web-search'));
  }

  function railIsOpen() {
    return $('[data-config-rail]').classList.contains('is-open');
  }

  function syncRailMode() {
    const rail = $('[data-config-rail]');
    const backdrop = $('[data-config-rail-backdrop]');
    if (mobileRailQuery.matches) {
      rail.setAttribute('role', 'dialog');
      rail.setAttribute('aria-modal', 'true');
      rail.setAttribute('aria-hidden', railIsOpen() ? 'false' : 'true');
      backdrop.hidden = !railIsOpen();
      return;
    }
    rail.classList.remove('is-open');
    rail.removeAttribute('role');
    rail.removeAttribute('aria-modal');
    rail.setAttribute('aria-hidden', 'false');
    backdrop.hidden = true;
    document.body.classList.remove('site-config-rail-is-open');
    $('[data-config-rail-toggle]').setAttribute('aria-expanded', 'false');
  }

  function openRail() {
    if (!mobileRailQuery.matches) return;
    const rail = $('[data-config-rail]');
    const backdrop = $('[data-config-rail-backdrop]');
    state.railReturnFocus = document.activeElement;
    rail.classList.add('is-open');
    rail.setAttribute('aria-hidden', 'false');
    backdrop.hidden = false;
    $('[data-config-rail-toggle]').setAttribute('aria-expanded', 'true');
    document.body.classList.add('site-config-rail-is-open');
    window.requestAnimationFrame(() => $('[data-config-rail-close]').focus());
  }

  function closeRail({restoreFocus = false} = {}) {
    const rail = $('[data-config-rail]');
    const backdrop = $('[data-config-rail-backdrop]');
    rail.classList.remove('is-open');
    backdrop.hidden = true;
    $('[data-config-rail-toggle]').setAttribute('aria-expanded', 'false');
    document.body.classList.remove('site-config-rail-is-open');
    rail.setAttribute('aria-hidden', mobileRailQuery.matches ? 'true' : 'false');
    if (restoreFocus && state.railReturnFocus?.isConnected) state.railReturnFocus.focus();
  }

  function trapRailFocus(event) {
    if (!mobileRailQuery.matches || !railIsOpen()) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      closeRail({restoreFocus: true});
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = $$('button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])', $('[data-config-rail]'))
      .filter((item) => item.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function activateTab(name, updateHash = true) {
    const normalized = ['endpoints', 'features', 'other'].includes(name) ? name : 'endpoints';
    $$('[data-config-tab]').forEach((button) => {
      const active = button.dataset.configTab === normalized;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', active ? 'true' : 'false');
      button.tabIndex = active ? 0 : -1;
    });
    $$('[data-config-panel]').forEach((panel) => {
      const active = panel.dataset.configPanel === normalized;
      panel.hidden = !active;
      panel.classList.toggle('active', active);
    });
    if (updateHash) history.replaceState(null, '', `#${normalized}`);
  }

  const tabButtons = $$('[data-config-tab]');
  tabButtons.forEach((button, index) => {
    button.addEventListener('click', () => {
      const restoreFocus = mobileRailQuery.matches && railIsOpen();
      activateTab(button.dataset.configTab);
      if (restoreFocus) closeRail({restoreFocus: true});
    });
    button.addEventListener('keydown', (event) => {
      let nextIndex = null;
      if (['ArrowRight', 'ArrowDown'].includes(event.key)) nextIndex = (index + 1) % tabButtons.length;
      else if (['ArrowLeft', 'ArrowUp'].includes(event.key)) nextIndex = (index - 1 + tabButtons.length) % tabButtons.length;
      else if (event.key === 'Home') nextIndex = 0;
      else if (event.key === 'End') nextIndex = tabButtons.length - 1;
      if (nextIndex == null) return;
      event.preventDefault();
      const next = tabButtons[nextIndex];
      activateTab(next.dataset.configTab);
      next.focus();
    });
  });

  $('[data-config-rail-toggle]').addEventListener('click', openRail);
  $('[data-config-rail-close]').addEventListener('click', () => closeRail({restoreFocus: true}));
  $('[data-config-rail-backdrop]').addEventListener('click', () => closeRail({restoreFocus: true}));
  document.addEventListener('keydown', trapRailFocus);
  if (typeof mobileRailQuery.addEventListener === 'function') mobileRailQuery.addEventListener('change', syncRailMode);
  else mobileRailQuery.addListener(syncRailMode);

  $('[data-endpoint-create]').addEventListener('click', () => openEndpointModal());
  $('[data-endpoint-grid]').addEventListener('click', (event) => {
    const actionButton = event.target.closest('[data-endpoint-action]');
    if (!actionButton) return;
    const card = actionButton.closest('[data-endpoint-id]');
    const endpoint = state.endpoints.find((item) => Number(item.id) === Number(card?.dataset.endpointId));
    if (!endpoint) return;
    const action = actionButton.dataset.endpointAction;
    if (action === 'edit') openEndpointModal(endpoint);
    else if (action === 'test') retestEndpoint(endpoint, actionButton);
    else if (action === 'lock') openLockTarget('endpoint', endpoint);
    else if (action === 'unlock') openUnlockTarget('endpoint', endpoint);
    else if (action === 'delete') openDelete(endpoint);
  });

  const endpointForm = $('[data-endpoint-form]');
  endpointForm.addEventListener('input', (event) => {
    if (event.target.name === 'api_key') event.target.setCustomValidity('');
    invalidateEndpointTest();
  });
  endpointForm.addEventListener('change', (event) => {
    if (['protocol', 'category', 'thinking_format'].includes(event.target.name)) updateThinkingControls(true);
    invalidateEndpointTest();
  });
  $('[data-thinking-switch]').addEventListener('click', () => {
    setThinking(endpointForm.elements.thinking_enabled.value !== 'true');
    invalidateEndpointTest();
  });
  $('[data-endpoint-test]').addEventListener('click', (event) => testEndpoint(endpointForm, event.currentTarget));
  endpointForm.addEventListener('submit', (event) => {
    event.preventDefault();
    saveEndpoint(endpointForm, $('[data-endpoint-save]'));
  });

  $('[data-lock-form]').addEventListener('submit', (event) => {
    event.preventDefault();
    submitLock(event.currentTarget, event.submitter);
  });
  $('[data-unlock-form]').addEventListener('submit', (event) => {
    event.preventDefault();
    submitUnlock(event.currentTarget, event.submitter);
  });
  $('[data-delete-form]').addEventListener('submit', (event) => {
    event.preventDefault();
    submitDelete(event.submitter);
  });

  $('[data-feature-grid]').addEventListener('change', (event) => {
    if (!event.target.matches('[data-feature-select]')) return;
    saveBinding(event.target.closest('[data-feature-key]'), event.target);
  });
  $('[data-feature-grid]').addEventListener('click', (event) => {
    const card = event.target.closest('[data-feature-key]');
    if (!card) return;
    const binding = state.bindings.find((item) => item.feature_key === card.dataset.featureKey);
    if (!binding) return;
    if (event.target.closest('[data-feature-lock]')) openLockTarget('embedding_binding', binding);
    if (event.target.closest('[data-feature-unlock]')) openUnlockTarget('embedding_binding', binding);
  });

  $('[data-mail-form]').addEventListener('submit', (event) => {
    event.preventDefault();
    saveService('mail', event.currentTarget, event.submitter);
  });
  $('[data-mail-test]').addEventListener('click', (event) => testService('mail', $('[data-mail-form]'), event.currentTarget));
  $('[data-mail-clear]').addEventListener('click', (event) => clearService('mail', event.currentTarget));
  $('[data-search-form]').addEventListener('submit', (event) => {
    event.preventDefault();
    saveService('web-search', event.currentTarget, event.submitter);
  });
  $('[data-search-test]').addEventListener('click', (event) => testService('web-search', $('[data-search-form]'), event.currentTarget));
  $('[data-search-clear]').addEventListener('click', (event) => clearService('web-search', event.currentTarget));

  async function initialize() {
    activateTab(location.hash.replace('#', ''), false);
    syncRailMode();
    try {
      await loadMeta();
      const results = await Promise.allSettled([loadEndpoints(), loadBindings(), loadMail(), loadSearch()]);
      const failed = results.filter((result) => result.status === 'rejected');
      if (failed.length) toast(failed[0].reason?.message || '部分配置读取失败', 'error');
    } catch (error) {
      $('[data-endpoint-loading]').innerHTML = `<i class="fas fa-exclamation-circle" aria-hidden="true"></i> ${escapeHtml(error.message)}`;
      $('[data-feature-grid]').innerHTML = `<div class="site-config-empty"><i class="fas fa-exclamation-circle" aria-hidden="true"></i><h3>配置读取失败</h3><span>${escapeHtml(error.message)}</span></div>`;
      toast(error.message, 'error');
    }
  }

  initialize();
})();
