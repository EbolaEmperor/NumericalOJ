(() => {
  'use strict';

  const root = document.querySelector('[data-site-config]');
  if (!root) return;

  const apiRoot = String(root.dataset.apiRoot || '/api/admin/dynamic-config').replace(/\/$/, '');
  const agentPublicAccessPath = String(
    root.dataset.agentPublicAccessUrl || `${apiRoot}/agent-public-access`
  ).replace(apiRoot, '') || '/agent-public-access';
  const agentConcurrencyPath = String(
    root.dataset.agentConcurrencyUrl || `${apiRoot}/agent-concurrency`
  ).replace(apiRoot, '') || '/agent-concurrency';
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

  const decimalText = (value) => {
    let text = String(value ?? '').trim();
    if (!text) return '';
    if (!/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(text)) return text;
    text = text.replace(/^([+-]?)0+(?=\d)/, '$1');
    if (text.includes('.')) text = text.replace(/0+$/, '').replace(/\.$/, '');
    return ['-0', '+0', ''].includes(text) ? '0' : text;
  };
  const moneyText = (value) => {
    const text = decimalText(value);
    return text ? `${text} 元` : '—';
  };

  const protocolLabels = {openai: 'OpenAI 兼容', anthropic: 'Anthropic 兼容'};
  const protocolIcons = {openai: 'fa-code', anthropic: 'fa-brain'};
  const categoryLabels = {omni: '全模态', text: '纯文本', vision: '视觉理解', embedding: 'Embedding'};
  const categoryIcons = {omni: 'fa-layer-group', text: 'fa-font', vision: 'fa-eye', embedding: 'fa-vector-square'};
  const featureIcons = {
    ai_code_annotation: 'fa-highlighter',
    code_image_analysis: 'fa-image',
    repository_structuring: 'fa-sitemap',
    repository_embedding: 'fa-vector-square',
  };

  const modelIconClass = (model) => window.NumojModelFamily
    ? window.NumojModelFamily.iconClass(model)
    : 'fas fa-microchip';

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
    agentPublicEnabled: true,
    agentConcurrencyLimit: 8,
    agentConcurrencySaving: false,
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

  function enumEntries(items, fallback, labels, icons) {
    return values(items, fallback).map((value) => ({
      value,
      label: labels[value] || value,
      icon: icons[value] || 'fa-circle',
    }));
  }

  const endpointForm = $('[data-endpoint-editor][data-endpoint-editor-mode="global"]');
  const endpointEditor = window.NumOJEndpointEditor.mount(endpointForm);

  function configureEndpointEditor(title) {
    endpointEditor.configure({
      title,
      protocols: enumEntries(
        state.meta.protocols,
        ['openai', 'anthropic'],
        protocolLabels,
        protocolIcons,
      ),
      categories: enumEntries(
        state.meta.categories,
        ['omni', 'text', 'vision', 'embedding'],
        categoryLabels,
        categoryIcons,
      ),
      defaultProtocol: values(state.meta.protocols, ['openai'])[0],
      defaultCategory: values(state.meta.categories, ['text'])[0],
      createKeyNote: '新建端点必须填写 API 密钥。',
      editKeyNote: '留空表示继续使用已保存的密钥。',
    });
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

  function endpointIdentity(endpoint) {
    const model = String(endpoint?.model || '未命名模型');
    const id = Number(endpoint?.id);
    return Number.isSafeInteger(id) && id > 0 ? `${model}（节点 #${id}）` : model;
  }

  function endpointCard(endpoint) {
    const status = testStatus(endpoint);
    const locked = Boolean(endpoint.is_locked);
    const apiKey = endpoint.api_key_configured ? '密钥已配置' : '密钥缺失';
    const identity = endpointIdentity(endpoint);
    return `
      <article class="site-config-endpoint-card" data-endpoint-id="${Number(endpoint.id)}">
        <div class="site-config-endpoint-main">
          <div class="site-config-endpoint-top">
            <div>
              <span class="site-config-endpoint-number">节点 #${Number(endpoint.id)}</span>
              <h3 class="site-config-endpoint-title" title="${escapeHtml(endpoint.model)}"><i class="${modelIconClass(endpoint.model)}" aria-hidden="true"></i><span>${escapeHtml(endpoint.model)}</span></h3>
            </div>
            <div class="site-config-endpoint-chips">
              <span class="site-config-chip is-protocol">${escapeHtml(protocolLabels[endpoint.protocol] || endpoint.protocol)}</span>
              <span class="site-config-chip">${escapeHtml(categoryLabels[endpoint.category] || endpoint.category)}</span>
            </div>
          </div>
          <div class="site-config-endpoint-url"><small>地址 · ${escapeHtml(apiKey)}</small><span title="${escapeHtml(endpoint.base_url)}">${escapeHtml(endpoint.base_url)}</span></div>
          <dl class="site-config-endpoint-prices" aria-label="节点价格，人民币每百万 Token">
            <div><dt>INPUT</dt><dd>${escapeHtml(moneyText(endpoint.input_price_per_million))}</dd></div>
            <div><dt>CACHED</dt><dd>${escapeHtml(moneyText(endpoint.cached_input_price_per_million))}</dd></div>
            <div><dt>OUTPUT</dt><dd>${escapeHtml(moneyText(endpoint.output_price_per_million))}</dd></div>
          </dl>
        </div>
        <footer class="site-config-endpoint-foot">
          <span class="site-config-test-state ${status.className}" title="${escapeHtml(endpoint.test_message || '')}"><i aria-hidden="true"></i>${escapeHtml(status.label)}</span>
          ${locked ? '' : `
            <button class="site-config-icon-button" type="button" data-endpoint-action="test" title="复测连接" aria-label="复测 ${escapeHtml(identity)}"><i class="fas fa-vial" aria-hidden="true"></i></button>
            <button class="site-config-icon-button" type="button" data-endpoint-action="lock" title="加锁" aria-label="加锁 ${escapeHtml(identity)}"><i class="fas fa-lock" aria-hidden="true"></i></button>
            <button class="site-config-icon-button" type="button" data-endpoint-action="edit" title="编辑" aria-label="编辑 ${escapeHtml(identity)}"><i class="fas fa-pen" aria-hidden="true"></i></button>
            <button class="site-config-icon-button is-danger" type="button" data-endpoint-action="delete" title="删除" aria-label="删除 ${escapeHtml(identity)}"><i class="fas fa-trash-alt" aria-hidden="true"></i></button>`}
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
      <article class="site-config-feature-card" data-feature-key="${escapeHtml(key)}">
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
          ? `节点 #${selectedEndpoint.id} · ${protocolLabels[selectedEndpoint.protocol] || selectedEndpoint.protocol} · ${categoryLabels[selectedEndpoint.category] || selectedEndpoint.category}`
          : '端点已删除',
        icon: 'fa-exclamation-triangle',
        missing: true,
      });
    }
    candidates.forEach((endpoint) => {
      options.push({
        value: String(endpoint.id),
        label: endpoint.model,
        meta: `节点 #${endpoint.id} · ${protocolLabels[endpoint.protocol] || endpoint.protocol} · ${categoryLabels[endpoint.category] || endpoint.category}`,
        icon: 'fa-microchip',
        model: endpoint.model,
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
      const controller = window.ChoicePicker.configure(
        $('[data-feature-choice]', card),
        featureOptions(binding),
        binding.endpoint_id == null ? '' : String(binding.endpoint_id),
        {disabled: Boolean(binding.is_locked)},
      );
      if (controller) state.featureControllers.set(binding.feature_key, controller);
    });
  }

  function endpointPayload() {
    const payload = endpointEditor.values();
    delete payload.name;
    return payload;
  }

  function fingerprint(payload) {
    return JSON.stringify(payload, Object.keys(payload).sort());
  }

  function invalidateEndpointTest() {
    state.endpointTestToken = '';
    state.endpointFormFingerprint = '';
    $('[data-endpoint-editor-save]', endpointForm).disabled = true;
    endpointEditor.clearResult();
  }

  function openEndpointModal(endpoint = null) {
    configureEndpointEditor(endpoint ? '编辑端点' : '新建端点');
    if (endpoint) {
      endpointEditor.fill({
        ...endpoint,
        input_price_per_million: decimalText(endpoint.input_price_per_million),
        cached_input_price_per_million: decimalText(endpoint.cached_input_price_per_million),
        output_price_per_million: decimalText(endpoint.output_price_per_million),
      });
    } else {
      endpointEditor.reset({
        protocol: values(state.meta.protocols, ['openai'])[0],
        category: values(state.meta.categories, ['text'])[0],
      });
    }
    invalidateEndpointTest();
    modal('endpointModal').show();
  }

  async function testEndpoint(button) {
    if (!endpointEditor.validate()) return;
    const payload = endpointPayload();
    const testedFingerprint = fingerprint(payload);
    setBusy(button, true, '测试中…');
    endpointEditor.setResult('测试中…', 'pending');
    try {
      const data = await request('/llm-endpoints/test', {method: 'POST', body: payload});
      if (fingerprint(endpointPayload()) !== testedFingerprint) {
        invalidateEndpointTest();
        endpointEditor.setResult('字段已经变化，请重新测试连接。', 'error');
        return;
      }
      const test = data.test || data;
      endpointEditor.applyTestedLimits(test);
      state.endpointTestToken = data.test_token || data.test?.test_token || '';
      state.endpointFormFingerprint = fingerprint(endpointPayload());
      endpointEditor.setResult(
        `连接成功${test.latency_ms != null ? ` · ${test.latency_ms} ms` : ''}${test.limits_adjusted ? ' · 已按上游上限调整容量' : ''}${test.message ? ` · ${test.message}` : ''}`,
        'ok',
      );
      $('[data-endpoint-editor-save]', endpointForm).disabled = !state.endpointTestToken;
    } catch (error) {
      state.endpointTestToken = '';
      state.endpointFormFingerprint = '';
      $('[data-endpoint-editor-save]', endpointForm).disabled = true;
      endpointEditor.setResult(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function saveEndpoint(button) {
    if (!endpointEditor.validate()) return;
    const payload = endpointPayload();
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
      const candidate = {
        endpoint_id: Number(endpoint.id),
        protocol: endpoint.protocol,
        category: endpoint.category,
        base_url: endpoint.base_url,
        api_key: '',
        model: endpoint.model,
        context_window_tokens: endpoint.context_window_tokens,
        max_output_tokens: endpoint.max_output_tokens,
        thinking_enabled: Boolean(endpoint.thinking_enabled),
        thinking_format: endpoint.thinking_format,
        input_price_per_million: decimalText(endpoint.input_price_per_million),
        cached_input_price_per_million: decimalText(endpoint.cached_input_price_per_million),
        output_price_per_million: decimalText(endpoint.output_price_per_million),
      };
      const tested = await request('/llm-endpoints/test', {
        method: 'POST',
        body: candidate,
      });
      const test = tested.test || tested;
      if (test.limits_adjusted) {
        candidate.context_window_tokens = test.context_window_tokens;
        candidate.max_output_tokens = test.max_output_tokens;
        candidate.test_token = tested.test_token || test.test_token;
        delete candidate.endpoint_id;
        await request(`/llm-endpoints/${Number(endpoint.id)}`, {
          method: 'PUT',
          body: candidate,
        });
        toast(`“${endpointIdentity(endpoint)}”已按上游上限调整容量`);
      } else {
        toast(`“${endpointIdentity(endpoint)}”连接正常`);
      }
    } catch (error) {
      toast(`“${endpointIdentity(endpoint)}”复测失败：${error.message}`, 'error');
    } finally {
      setBusy(button, false);
      await loadEndpoints().catch(() => {});
    }
  }

  function openLockTarget(kind, item) {
    state.lockTarget = {kind, item};
    const form = $('[data-lock-form]');
    form.reset();
    $('.modal-title', form).textContent = kind === 'endpoint' ? `加锁 · ${endpointIdentity(item)}` : '加锁 · Embedding 绑定';
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
    $('.modal-title', form).textContent = kind === 'endpoint' ? `解锁 · ${endpointIdentity(item)}` : '解锁 · Embedding 绑定';
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
    $('[data-delete-model]').textContent = endpointIdentity(endpoint);
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
    $('[data-feature-count]').textContent = String(state.meta.features.length);
    configureEndpointEditor();
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

  function renderAgentPublicAccess(enabled) {
    state.agentPublicEnabled = Boolean(enabled);
    const button = $('[data-agent-public-access-switch]');
    const label = $('[data-agent-public-access-label]');
    button.disabled = false;
    button.setAttribute('aria-checked', state.agentPublicEnabled ? 'true' : 'false');
    label.textContent = state.agentPublicEnabled ? '开启' : '关闭';
  }

  async function loadAgentPublicAccess() {
    const data = await request(agentPublicAccessPath);
    const settings = data.settings || data;
    renderAgentPublicAccess(
      settings.public_enabled ?? settings.enabled ?? settings.agent_public_enabled ?? true
    );
  }

  async function saveAgentPublicAccess(button) {
    const next = !state.agentPublicEnabled;
    button.disabled = true;
    try {
      const data = await request(agentPublicAccessPath, {
        method: 'PUT',
        body: {enabled: next},
      });
      const settings = data.settings || data;
      renderAgentPublicAccess(
        settings.public_enabled ?? settings.enabled ?? settings.agent_public_enabled ?? next
      );
      toast(next ? '已允许普通用户使用 Agent' : '已暂停普通用户使用 Agent');
    } catch (error) {
      button.disabled = false;
      toast(error.message, 'error');
    }
  }

  function parsedAgentConcurrency() {
    const input = $('[data-agent-concurrency-input]');
    const text = String(input.value || '').trim();
    if (!/^\d{1,3}$/.test(text)) return null;
    const value = Number(text);
    return Number.isInteger(value) && value >= 1 && value <= 100 ? value : null;
  }

  function syncAgentConcurrencyControls() {
    const input = $('[data-agent-concurrency-input]');
    const decrement = $('[data-agent-concurrency-decrement]');
    const increment = $('[data-agent-concurrency-increment]');
    const save = $('[data-agent-concurrency-save]');
    const description = $('[data-agent-concurrency-description]');
    const value = parsedAgentConcurrency();
    const valid = value !== null;
    const dirty = valid && value !== state.agentConcurrencyLimit;

    input.disabled = state.agentConcurrencySaving;
    input.setAttribute('aria-invalid', valid ? 'false' : 'true');
    if (valid) input.setAttribute('aria-valuenow', String(value));
    else input.removeAttribute('aria-valuenow');
    decrement.disabled = state.agentConcurrencySaving || !valid || value <= 1;
    increment.disabled = state.agentConcurrencySaving || !valid || value >= 100;
    save.disabled = state.agentConcurrencySaving || !dirty;
    description.textContent = !valid
      ? '请输入 1 至 100 的整数'
      : dirty
        ? `尚未保存 · 将调整为 ${value}`
        : '';
  }

  function renderAgentConcurrency(value) {
    const numeric = Number(value);
    state.agentConcurrencyLimit = Number.isInteger(numeric) && numeric >= 1 && numeric <= 100
      ? numeric
      : 8;
    $('[data-agent-concurrency-input]').value = String(state.agentConcurrencyLimit);
    syncAgentConcurrencyControls();
  }

  async function loadAgentConcurrency() {
    const data = await request(agentConcurrencyPath);
    const settings = data.settings || data;
    renderAgentConcurrency(settings.limit ?? 8);
  }

  function changeAgentConcurrency(delta) {
    const input = $('[data-agent-concurrency-input]');
    const current = parsedAgentConcurrency() ?? state.agentConcurrencyLimit;
    input.value = String(Math.min(100, Math.max(1, current + delta)));
    syncAgentConcurrencyControls();
    input.focus();
  }

  async function saveAgentConcurrency(button) {
    const limit = parsedAgentConcurrency();
    if (limit === null) {
      syncAgentConcurrencyControls();
      toast('Agent 任务并发上限必须是 1 至 100 的整数', 'error');
      return;
    }
    state.agentConcurrencySaving = true;
    setBusy(button, true, '保存中…');
    syncAgentConcurrencyControls();
    try {
      const data = await request(agentConcurrencyPath, {
        method: 'PUT',
        body: {limit},
      });
      const settings = data.settings || data;
      renderAgentConcurrency(settings.limit ?? limit);
      toast(data.applied === false
        ? '配置已保存，Agent worker 重启后生效'
        : 'Agent 任务并发上限已生效');
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      state.agentConcurrencySaving = false;
      setBusy(button, false);
      syncAgentConcurrencyControls();
    }
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

  endpointForm.addEventListener('input', (event) => {
    invalidateEndpointTest();
  });
  endpointForm.addEventListener('change', invalidateEndpointTest);
  $('[data-agent-public-access-switch]').addEventListener('click', (event) => {
    saveAgentPublicAccess(event.currentTarget);
  });
  $('[data-agent-concurrency-decrement]').addEventListener('click', () => {
    changeAgentConcurrency(-1);
  });
  $('[data-agent-concurrency-increment]').addEventListener('click', () => {
    changeAgentConcurrency(1);
  });
  $('[data-agent-concurrency-input]').addEventListener('input', () => {
    syncAgentConcurrencyControls();
  });
  $('[data-agent-concurrency-input]').addEventListener('blur', (event) => {
    if (parsedAgentConcurrency() === null) {
      event.currentTarget.value = String(state.agentConcurrencyLimit);
    }
    syncAgentConcurrencyControls();
  });
  $('[data-agent-concurrency-input]').addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      changeAgentConcurrency(-1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      changeAgentConcurrency(1);
    } else if (event.key === 'Home') {
      event.preventDefault();
      event.currentTarget.value = '1';
      syncAgentConcurrencyControls();
    } else if (event.key === 'End') {
      event.preventDefault();
      event.currentTarget.value = '100';
      syncAgentConcurrencyControls();
    } else if (event.key === 'Enter' && !$('[data-agent-concurrency-save]').disabled) {
      event.preventDefault();
      $('[data-agent-concurrency-save]').click();
    }
  });
  $('[data-agent-concurrency-save]').addEventListener('click', (event) => {
    saveAgentConcurrency(event.currentTarget);
  });
  $('[data-endpoint-editor-test]', endpointForm).addEventListener('click', (event) => testEndpoint(event.currentTarget));
  endpointForm.addEventListener('submit', (event) => {
    event.preventDefault();
    saveEndpoint($('[data-endpoint-editor-save]', endpointForm));
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
      const results = await Promise.allSettled([
        loadEndpoints(), loadBindings(), loadMail(), loadSearch(), loadAgentPublicAccess(),
        loadAgentConcurrency(),
      ]);
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
