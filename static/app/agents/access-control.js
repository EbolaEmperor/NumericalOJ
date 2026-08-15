(function (global) {
  'use strict';

  function asText(value) {
    return value == null ? '' : String(value).trim();
  }

  function escapeHtml(value) {
    return asText(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function decimalText(value) {
    var text = asText(value);
    if (!text) return '';
    if (!/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(text)) return text;
    text = text.replace(/^([+-]?)0+(?=\d)/, '$1');
    if (text.indexOf('.') >= 0) text = text.replace(/0+$/, '').replace(/\.$/, '');
    if (text === '-0' || text === '+0' || text === '') return '0';
    return text;
  }

  function moneyText(value) {
    var formatted = decimalText(value);
    return formatted ? formatted + ' 元' : '—';
  }

  function multiplyDecimal(value, multiplier) {
    var text = decimalText(value);
    if (!text || !Number.isSafeInteger(multiplier) || multiplier < 0) return '';
    var negative = text.charAt(0) === '-';
    if (negative || text.charAt(0) === '+') text = text.slice(1);
    var parts = text.split('.');
    var scale = parts[1] ? parts[1].length : 0;
    var digits = (parts[0] || '0') + (parts[1] || '');
    try {
      var product = BigInt(digits || '0') * BigInt(multiplier);
      var output = product.toString().padStart(scale + 1, '0');
      if (scale) output = output.slice(0, -scale) + '.' + output.slice(-scale);
      return decimalText((negative ? '-' : '') + output);
    } catch (_error) {
      return decimalText(Number(value) * multiplier);
    }
  }

  function readJson(root, selector, fallback) {
    var node = root.querySelector(selector);
    if (!node) return fallback;
    try {
      return JSON.parse(node.textContent || '');
    } catch (_error) {
      return fallback;
    }
  }

  function setFeedback(node, message, error) {
    if (!node) return;
    node.textContent = message || '';
    node.hidden = !message;
    node.classList.toggle('is-error', error === true);
  }

  function fieldShell(element) {
    return element && element.closest('.agent-access-input-shell');
  }

  function validateForm(form, feedback, names) {
    var allowed = Array.isArray(names) ? new Set(names) : null;
    var firstInvalid = null;
    Array.prototype.forEach.call(form.elements, function (element) {
      if (!element.name || element.disabled || element.type === 'hidden'
          || element.type === 'submit' || element.type === 'button'
          || (allowed && !allowed.has(element.name))) return;
      var valid = element.checkValidity();
      var shell = fieldShell(element);
      if (shell) shell.classList.toggle('is-invalid', !valid);
      element.setAttribute('aria-invalid', valid ? 'false' : 'true');
      if (!valid && !firstInvalid) firstInvalid = element;
    });
    if (!firstInvalid) return true;
    setFeedback(feedback, '请完整填写必填项，并检查输入格式。', true);
    firstInvalid.focus();
    return false;
  }

  function clearFieldError(event) {
    var shell = fieldShell(event.target);
    if (shell) shell.classList.remove('is-invalid');
    if (event.target && event.target.removeAttribute) event.target.removeAttribute('aria-invalid');
  }

  function activateTab(root, button, tabSelector, panelSelector, tabKey, panelKey, focus) {
    if (!button) return;
    var name = button.dataset[tabKey];
    root.querySelectorAll(tabSelector).forEach(function (candidate) {
      var active = candidate === button;
      candidate.classList.toggle('is-current', active);
      candidate.setAttribute('aria-selected', active ? 'true' : 'false');
      candidate.tabIndex = active ? 0 : -1;
    });
    root.querySelectorAll(panelSelector).forEach(function (panel) {
      panel.hidden = panel.dataset[panelKey] !== name;
    });
    if (focus) button.focus();
  }

  function bindTabs(root, container, tabSelector, panelSelector, tabKey, panelKey) {
    if (!container) return;
    container.addEventListener('click', function (event) {
      activateTab(root, event.target.closest(tabSelector), tabSelector, panelSelector, tabKey, panelKey, false);
    });
    container.addEventListener('keydown', function (event) {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      var tabs = Array.prototype.slice.call(container.querySelectorAll(tabSelector));
      var current = event.target.closest(tabSelector);
      var index = tabs.indexOf(current);
      if (index < 0 || !tabs.length) return;
      event.preventDefault();
      if (event.key === 'Home') index = 0;
      else if (event.key === 'End') index = tabs.length - 1;
      else index = (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      activateTab(root, tabs[index], tabSelector, panelSelector, tabKey, panelKey, true);
    });
  }

  function request(url, options) {
    if (!asText(url)) return Promise.reject(new Error('服务地址未配置'));
    var init = Object.assign({credentials: 'same-origin'}, options || {});
    init.headers = Object.assign({Accept: 'application/json'}, init.headers || {});
    if (init.body && !(init.body instanceof global.FormData) && typeof init.body !== 'string') {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(init.body);
    }
    return global.fetch(url, init).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (payload) {
        if (!response.ok || !payload || payload.success === false) {
          throw new Error(asText(payload && (payload.message || payload.error)) || '请求失败（HTTP ' + response.status + '）');
        }
        return payload;
      });
    });
  }

  function payloadValue(payload, keys, fallback) {
    for (var index = 0; index < keys.length; index += 1) {
      if (payload && payload[keys[index]] !== undefined) return payload[keys[index]];
    }
    return fallback;
  }

  function normalizeSummary(payload) {
    return payloadValue(payload, ['summary', 'quota', 'account'], payload) || {};
  }

  function normalizeList(payload, keys) {
    if (Array.isArray(payload)) return payload;
    for (var index = 0; index < keys.length; index += 1) {
      if (Array.isArray(payload && payload[keys[index]])) return payload[keys[index]];
    }
    return [];
  }

  function flattenEndpointSource(source) {
    var entries = [];
    if (Array.isArray(source)) entries = source;
    else if (source && typeof source === 'object') {
      Object.keys(source).forEach(function (key) {
        if (Array.isArray(source[key])) entries = entries.concat(source[key]);
      });
    }
    var seen = new Set();
    return entries.filter(function (endpoint) {
      if (!endpoint || typeof endpoint !== 'object') return false;
      var id = asText(endpoint.choice_value || endpoint.value || endpoint.id || endpoint.endpoint_id);
      var key = id || [endpoint.model, endpoint.base_url].join('|');
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return endpoint.is_personal !== true && endpoint.scope !== 'user' && endpoint.owner_type !== 'user';
    });
  }

  function mount(root) {
    if (!root || root.dataset.agentAccessMounted === 'true') return null;
    root.dataset.agentAccessMounted = 'true';
    var isAdmin = root.dataset.agentAccessAdmin === 'true';
    var publicEnabled = root.dataset.agentAccessPublicEnabled !== 'false';
    var summary = normalizeSummary(readJson(root, '[data-agent-access-summary-json]', {}));
    var prices = flattenEndpointSource(readJson(root, '[data-agent-access-prices-json]', []));
    var personalEndpoints = normalizeList(
      readJson(root, '[data-agent-access-personal-endpoints-json]', []), ['endpoints']
    );
    var reviews = normalizeList(
      readJson(root, '[data-agent-access-reviews-json]', []), ['requests', 'applications']
    );
    var classes = normalizeList(
      readJson(root, '[data-agent-access-classes-json]', []), ['classes']
    );
    var loaded = false;

    function updateSummary(next) {
      summary = Object.assign({}, summary, normalizeSummary(next));
      if (typeof summary.public_enabled === 'boolean') publicEnabled = summary.public_enabled;
      root.dataset.agentAccessPublicEnabled = publicEnabled ? 'true' : 'false';
      var fields = {
        '[data-agent-quota-used]': summary.used_amount,
        '[data-agent-quota-remaining]': summary.remaining_amount
      };
      Object.keys(fields).forEach(function (selector) {
        var element = root.querySelector(selector);
        if (element) element.textContent = moneyText(fields[selector]);
      });
      var remaining = Number(summary.remaining_amount);
      var remainingCard = root.querySelector('[data-agent-quota-remaining-card]');
      if (remainingCard) remainingCard.classList.toggle('is-negative', Number.isFinite(remaining) && remaining < 0);
      var notice = root.querySelector('[data-agent-public-notice]');
      if (notice) notice.hidden = publicEnabled;
      var status = root.querySelector('[data-agent-request-status]');
      var pending = summary.pending_request;
      if (status) {
        status.hidden = !pending;
        status.textContent = pending ? '申请审核中' : '';
      }
      var requestForm = root.querySelector('[data-agent-quota-request-form]');
      if (requestForm) {
        Array.prototype.forEach.call(requestForm.elements, function (element) {
          element.disabled = !publicEnabled || !!pending;
        });
      }
      var note = root.querySelector('[data-agent-quota-note]');
      if (note) {
        var noteText = '';
        if (!publicEnabled) noteText = '全站 Agent 已暂停，当前不能创建任务或继续会话。';
        else if (summary.has_account === false) noteText = '你还没有平台额度；申请获批后即可使用全站端点。自有端点不受额度限制。';
        else if (Number.isFinite(remaining) && remaining <= -5) noteText = '额度已达到 -5 元，运行中的任务会被系统强制停止。';
        else if (Number.isFinite(remaining) && remaining < 0) noteText = '余额低于 0 元；全站端点已停用，自有端点仍可使用。';
        note.textContent = noteText;
        note.hidden = !noteText;
      }
      global.dispatchEvent(new global.CustomEvent('numoj:agent-quota-change', {detail: summary}));
    }

    function renderPrices() {
      var list = root.querySelector('[data-agent-rate-list]');
      if (!list) return;
      if (!prices.length) {
        list.innerHTML = '<div class="agent-access-empty">暂无可用的全站端点</div>';
        return;
      }
      list.innerHTML = prices.map(function (endpoint) {
        var id = endpoint.id != null ? endpoint.id : endpoint.endpoint_id;
        return '<article class="agent-rate-row">'
          + '<div class="agent-rate-row-name"><strong>' + escapeHtml(endpoint.model || endpoint.name || ('节点 #' + id)) + '</strong><small>节点 #' + escapeHtml(id) + '</small></div>'
          + '<div class="agent-rate-value"><span>INPUT</span><strong>' + escapeHtml(decimalText(endpoint.input_price_per_million) || '—') + '</strong></div>'
          + '<div class="agent-rate-value"><span>CACHED</span><strong>' + escapeHtml(decimalText(endpoint.cached_input_price_per_million) || '—') + '</strong></div>'
          + '<div class="agent-rate-value"><span>OUTPUT</span><strong>' + escapeHtml(decimalText(endpoint.output_price_per_million) || '—') + '</strong></div>'
          + '</article>';
      }).join('');
    }

    var activeLayer = null;
    var layerOpener = null;
    var pendingDeleteEndpoint = null;
    var modalNode = root.querySelector('#agentAccessModal');
    var modalContent = modalNode && modalNode.querySelector('.modal-content');
    var modalHeader = modalContent && modalContent.querySelector(':scope > .agent-access-modal-header');
    var modalScroll = modalContent && modalContent.querySelector(':scope > .agent-access-modal-scroll');

    function setProtocol(value) {
      var form = root.querySelector('[data-agent-personal-endpoint-form]');
      if (!form) return;
      var protocol = value === 'anthropic' ? 'anthropic' : 'openai';
      form.elements.protocol.value = protocol;
      form.querySelectorAll('[data-agent-protocol-option]').forEach(function (button) {
        var active = button.dataset.agentProtocolOption === protocol;
        button.classList.toggle('is-current', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
      });
    }

    function setMainInert(inert) {
      [modalHeader, modalScroll].forEach(function (node) {
        if (!node) return;
        node.inert = inert;
        if (inert) node.setAttribute('aria-hidden', 'true');
        else node.removeAttribute('aria-hidden');
      });
    }

    function closeLayer(restoreFocus) {
      if (!activeLayer) return;
      var layer = activeLayer;
      var opener = layerOpener;
      activeLayer = null;
      layerOpener = null;
      setMainInert(false);
      layer.hidden = true;
      if (restoreFocus !== false) {
        var target = opener && document.contains(opener)
          ? opener : root.querySelector('[data-agent-personal-endpoint-create]');
        if (target) target.focus();
      }
    }

    function openLayer(layer, opener, focusSelector) {
      if (!layer) return;
      if (activeLayer && activeLayer !== layer) closeLayer(false);
      activeLayer = layer;
      layerOpener = opener || document.activeElement;
      layer.hidden = false;
      var target = layer.querySelector(focusSelector || '[tabindex="-1"], input, button');
      if (target) target.focus({preventScroll: true});
      setMainInert(true);
    }

    function resetPersonalForm() {
      var form = root.querySelector('[data-agent-personal-endpoint-form]');
      if (!form) return;
      form.reset();
      form.elements.endpoint_id.value = '';
      form.elements.api_key.required = true;
      var label = root.querySelector('[data-agent-personal-editor-label]');
      var note = root.querySelector('[data-agent-personal-key-note]');
      form.querySelectorAll('.agent-access-input-shell').forEach(function (shell) {
        shell.classList.remove('is-invalid');
      });
      form.querySelectorAll('[aria-invalid]').forEach(function (field) {
        field.removeAttribute('aria-invalid');
      });
      setProtocol('openai');
      if (label) label.textContent = '新建自定义端点';
      if (note) note.textContent = '密钥只用于你的 Agent 会话。';
      setFeedback(root.querySelector('[data-agent-personal-endpoint-editor-feedback]'), '', false);
    }

    function editPersonalEndpoint(endpoint, opener) {
      var form = root.querySelector('[data-agent-personal-endpoint-form]');
      var layer = root.querySelector('[data-agent-personal-endpoint-layer]');
      if (!form) return;
      resetPersonalForm();
      form.elements.endpoint_id.value = endpoint.id || endpoint.endpoint_id || '';
      form.elements.name.value = endpoint.name || endpoint.label || '';
      form.elements.model.value = endpoint.model || '';
      setProtocol(endpoint.protocol || 'openai');
      form.elements.base_url.value = endpoint.base_url || '';
      form.elements.api_key.value = '';
      form.elements.api_key.required = false;
      var label = root.querySelector('[data-agent-personal-editor-label]');
      var note = root.querySelector('[data-agent-personal-key-note]');
      if (label) label.textContent = '编辑自定义端点';
      if (note) note.textContent = '留空表示继续使用已保存的密钥。';
      openLayer(layer, opener, '[data-agent-personal-editor-label]');
    }

    function endpointUrl(id) {
      return asText(root.dataset.agentAccessPersonalEndpointUrlTemplate)
        .split('__ENDPOINT_ID__').join(encodeURIComponent(id));
    }

    function personalEndpointId(endpoint) {
      return asText(endpoint && (endpoint.id || endpoint.endpoint_id));
    }

    function upsertPersonalEndpoint(endpoint) {
      if (!endpoint || typeof endpoint !== 'object') return false;
      var id = personalEndpointId(endpoint);
      var index = personalEndpoints.findIndex(function (candidate) {
        return personalEndpointId(candidate) === id;
      });
      if (index >= 0) personalEndpoints[index] = endpoint;
      else personalEndpoints.push(endpoint);
      personalEndpoints.sort(function (left, right) {
        return asText(left.model).localeCompare(asText(right.model), 'zh-CN')
          || Number(personalEndpointId(left)) - Number(personalEndpointId(right));
      });
      renderPersonalEndpoints();
      return true;
    }

    function renderPersonalEndpoints() {
      var list = root.querySelector('[data-agent-personal-endpoint-list]');
      if (!list) return;
      if (!personalEndpoints.length) {
        list.innerHTML = '<div class="agent-access-empty">还没有自定义端点。创建后即可使用自己的密钥运行 Agent。</div>';
        return;
      }
      list.innerHTML = personalEndpoints.map(function (endpoint, index) {
        var protocol = endpoint.protocol === 'anthropic' ? 'Anthropic 兼容' : 'OpenAI 兼容';
        var id = endpoint.id || endpoint.endpoint_id || (index + 1);
        var name = endpoint.name || endpoint.label || endpoint.model || '自定义端点';
        var keyState = endpoint.api_key_configured === false ? '密钥未配置' : '密钥已配置';
        return '<article class="agent-personal-endpoint-card" data-personal-endpoint-index="' + index + '">'
          + '<div class="agent-personal-endpoint-main"><div class="agent-personal-endpoint-top"><div>'
          + '<span class="agent-personal-endpoint-number">自有节点 #' + escapeHtml(id) + '</span>'
          + '<h3 class="agent-personal-endpoint-title"><i class="fas fa-cube" aria-hidden="true"></i><span title="' + escapeHtml(name) + '">' + escapeHtml(name) + '</span></h3>'
          + '</div><span class="agent-personal-endpoint-chip">' + protocol + '</span></div>'
          + '<div class="agent-personal-endpoint-url"><small>模型 · ' + escapeHtml(endpoint.model || '未命名') + '</small><span title="' + escapeHtml(endpoint.base_url || '') + '">' + escapeHtml(endpoint.base_url || '未配置地址') + '</span></div></div>'
          + '<footer class="agent-personal-endpoint-foot"><span class="agent-personal-endpoint-state"><i aria-hidden="true"></i>' + keyState + '</span>'
          + '<button type="button" data-personal-action="edit" title="编辑" aria-label="编辑 ' + escapeHtml(name) + '"><i class="fas fa-pen" aria-hidden="true"></i></button>'
          + '<button class="is-danger" type="button" data-personal-action="delete" title="删除" aria-label="删除 ' + escapeHtml(name) + '"><i class="fas fa-trash-alt" aria-hidden="true"></i></button></footer>'
          + '</article>';
      }).join('');
    }

    function renderReviews() {
      var list = root.querySelector('[data-agent-review-list]');
      var count = reviews.length;
      var countNode = root.querySelector('[data-agent-review-count]');
      var badge = root.querySelector('[data-agent-review-badge]');
      if (countNode) countNode.textContent = String(count);
      if (badge) {
        badge.hidden = count < 1;
        badge.textContent = count > 99 ? '99+' : String(count);
      }
      if (!list) return;
      if (!reviews.length) {
        list.innerHTML = '<div class="agent-access-empty">没有待审核申请</div>';
        return;
      }
      list.innerHTML = reviews.map(function (item) {
        var id = item.id || item.request_id;
        var username = item.username || item.user_name || ('用户 #' + item.user_id);
        var className = asText(item.class_name || item.class_label || item.class_en);
        return '<article class="agent-access-review-card" data-review-id="' + escapeHtml(id) + '">'
          + '<header><div><span class="agent-personal-endpoint-number">额度申请 #' + escapeHtml(id) + '</span><h3>' + escapeHtml(username) + '</h3></div><div class="agent-access-review-meta"><strong>' + escapeHtml(moneyText(item.requested_amount)) + '</strong><time>' + escapeHtml(item.created_at || '') + '</time></div></header>'
          + (className ? '<span class="agent-access-review-class"><i class="fas fa-users" aria-hidden="true"></i>' + escapeHtml(className) + '</span>' : '')
          + '<p class="agent-access-review-reason">' + escapeHtml(item.reason || '未填写申请理由') + '</p>'
          + '<form class="agent-access-review-form" novalidate>'
          + '<label class="agent-access-field"><span>批准额度</span><span class="agent-access-input-shell agent-access-money-input"><b>¥</b><input name="approved_amount" type="number" min="0.01" step="0.01" value="' + escapeHtml(decimalText(item.requested_amount)) + '" aria-label="批准金额" required></span></label>'
          + '<label class="agent-access-field"><span>审核意见</span><span class="agent-access-input-shell"><i class="fas fa-pen" aria-hidden="true"></i><input name="review_note" maxlength="1000" placeholder="可选" aria-label="审核意见"></span></label>'
          + '<div class="agent-access-review-actions"><button type="submit" data-review-action="approve">通过申请</button><button type="submit" data-review-action="reject">驳回</button></div></form>'
          + '<p class="agent-access-feedback" data-review-feedback role="status" hidden></p>'
          + '</article>';
      }).join('');
    }

    function classKey(item) {
      return asText(item && (item.class_en || item.key || item.id));
    }

    function classLabel(item) {
      return asText(item && (item.label || item.class_name || item.name || item.class_en)) || '未命名班级';
    }

    function selectedClassGrant() {
      var selected = Array.prototype.map.call(
        root.querySelectorAll('[data-agent-class-grant-options] input:checked'),
        function (input) { return input.value; }
      );
      var userIds = new Set();
      var fallbackCount = 0;
      selected.forEach(function (key) {
        var item = classes.find(function (candidate) { return classKey(candidate) === key; });
        if (!item) return;
        if (Array.isArray(item.user_ids)) {
          item.user_ids.forEach(function (id) { userIds.add(asText(id)); });
        } else {
          fallbackCount += Number(item.user_count || item.student_count || 0);
        }
      });
      return {
        classes: selected,
        users: userIds.size || fallbackCount
      };
    }

    function updateClassGrantPreview() {
      var form = root.querySelector('[data-agent-class-grant-form]');
      if (!form) return;
      var selection = selectedClassGrant();
      var amount = asText(form.elements.amount_rmb.value);
      var total = multiplyDecimal(amount || '0', selection.users) || '0';
      var userNode = root.querySelector('[data-agent-class-grant-users]');
      var totalNode = root.querySelector('[data-agent-class-grant-total]');
      var submit = root.querySelector('[data-agent-class-grant-submit]');
      if (userNode) userNode.textContent = String(selection.users);
      if (totalNode) totalNode.textContent = moneyText(total);
      if (submit) submit.disabled = !selection.classes.length || selection.users < 1
        || !amount || Number(amount) <= 0;
    }

    function renderClasses() {
      var list = root.querySelector('[data-agent-class-grant-options]');
      if (!list) return;
      if (!classes.length) {
        list.innerHTML = '<div class="agent-access-empty">暂无可赠送的班级</div>';
        updateClassGrantPreview();
        return;
      }
      list.innerHTML = classes.map(function (item) {
        var key = classKey(item);
        var count = Array.isArray(item.user_ids)
          ? new Set(item.user_ids.map(asText)).size
          : Number(item.user_count || item.student_count || 0);
        return '<label><input type="checkbox" name="classes" value="' + escapeHtml(key) + '">'
          + '<span><strong>' + escapeHtml(classLabel(item)) + '</strong><small>' + count + ' 位普通用户</small></span>'
          + '<i class="fas fa-check" aria-hidden="true"></i></label>';
      }).join('');
      updateClassGrantPreview();
    }

    function loadSummary() {
      return request(root.dataset.agentAccessSummaryUrl).then(function (payload) {
        updateSummary(payload);
      });
    }

    function loadPrices() {
      return request(root.dataset.agentAccessPricesUrl).then(function (payload) {
        prices = flattenEndpointSource(normalizeList(payload, ['endpoints', 'prices']));
        renderPrices();
      });
    }

    function loadPersonalEndpoints() {
      return request(root.dataset.agentAccessPersonalEndpointsUrl).then(function (payload) {
        personalEndpoints = normalizeList(payload, ['endpoints']);
        renderPersonalEndpoints();
      });
    }

    function loadReviews() {
      return request(root.dataset.agentAccessReviewsUrl).then(function (payload) {
        reviews = normalizeList(payload, ['requests', 'applications']);
        classes = normalizeList(payload, ['classes']);
        var counts = payload && payload.class_user_counts;
        if (counts && typeof counts === 'object') {
          classes = classes.map(function (item) {
            var key = classKey(item);
            return Object.assign({}, item, {
              user_count: item.user_count != null ? item.user_count : counts[key]
            });
          });
        }
        renderReviews();
        renderClasses();
      });
    }

    if (modalNode) modalNode.addEventListener('show.bs.modal', function () {
      if (isAdmin) {
        loadReviews().catch(function (error) {
          var list = root.querySelector('[data-agent-review-list]');
          if (list) list.innerHTML = '<div class="agent-access-empty">' + escapeHtml(error.message) + '</div>';
        });
        return;
      }
      var jobs = [loadSummary(), loadPrices(), loadPersonalEndpoints()];
      Promise.allSettled(jobs).then(function () { loaded = true; });
    });
    if (modalNode) modalNode.addEventListener('hidden.bs.modal', function () {
      closeLayer(false);
      pendingDeleteEndpoint = null;
      resetPersonalForm();
    });

    var requestForm = root.querySelector('[data-agent-quota-request-form]');
    if (requestForm) requestForm.addEventListener('submit', function (event) {
      event.preventDefault();
      var button = root.querySelector('[data-agent-quota-request-submit]');
      var feedback = root.querySelector('[data-agent-quota-request-feedback]');
      if (!publicEnabled || !validateForm(requestForm, feedback)) return;
      button.disabled = true;
      setFeedback(feedback, '正在提交…', false);
      request(root.dataset.agentAccessRequestUrl, {
        method: 'POST',
        body: {
          requested_amount: requestForm.elements.requested_amount.value,
          reason: requestForm.elements.reason.value.trim()
        }
      }).then(function (payload) {
        requestForm.reset();
        updateSummary(payload.summary || Object.assign({}, summary, {
          pending_request: payload.request || payload.application || true
        }));
        setFeedback(feedback, '额度申请已提交。', false);
      }).catch(function (error) {
        button.disabled = false;
        setFeedback(feedback, error.message, true);
      });
    });

    var personalForm = root.querySelector('[data-agent-personal-endpoint-form]');
    if (personalForm) personalForm.addEventListener('submit', function (event) {
      event.preventDefault();
      var id = asText(personalForm.elements.endpoint_id.value);
      var button = root.querySelector('[data-agent-personal-endpoint-save]');
      var feedback = root.querySelector('[data-agent-personal-endpoint-editor-feedback]');
      if (!validateForm(personalForm, feedback)) return;
      button.disabled = true;
      setFeedback(feedback, '正在测试连接并保存…', false);
      request(id ? endpointUrl(id) : root.dataset.agentAccessPersonalEndpointsUrl, {
        method: id ? 'PUT' : 'POST',
        body: {
          name: personalForm.elements.name.value.trim(),
          model: personalForm.elements.model.value.trim(),
          protocol: personalForm.elements.protocol.value,
          base_url: personalForm.elements.base_url.value.trim(),
          api_key: personalForm.elements.api_key.value
        }
      }).then(function (payload) {
        var endpoint = payload && (payload.endpoint || payload.data);
        if (!upsertPersonalEndpoint(endpoint)) loadPersonalEndpoints().catch(function () {});
        button.disabled = false;
        closeLayer(true);
        setFeedback(root.querySelector('[data-agent-personal-endpoint-feedback]'), id ? '端点已更新。' : '端点已创建。', false);
      }).catch(function (error) {
        button.disabled = false;
        setFeedback(feedback, error.message, true);
      });
    });

    if (personalForm) personalForm.addEventListener('input', clearFieldError);

    var createEndpoint = root.querySelector('[data-agent-personal-endpoint-create]');
    if (createEndpoint) createEndpoint.addEventListener('click', function () {
      resetPersonalForm();
      openLayer(root.querySelector('[data-agent-personal-endpoint-layer]'), createEndpoint, '[data-agent-personal-editor-label]');
    });

    var protocolPicker = root.querySelector('[data-agent-protocol-picker]');
    if (protocolPicker) protocolPicker.addEventListener('click', function (event) {
      var option = event.target.closest('[data-agent-protocol-option]');
      if (option) setProtocol(option.dataset.agentProtocolOption);
    });

    root.querySelectorAll('[data-agent-layer-dismiss]').forEach(function (button) {
      button.addEventListener('click', function () { closeLayer(true); });
    });

    root.querySelectorAll('[data-agent-delete-dismiss]').forEach(function (button) {
      button.addEventListener('click', function () {
        pendingDeleteEndpoint = null;
        closeLayer(true);
      });
    });

    if (modalContent) modalContent.addEventListener('keydown', function (event) {
      if (!activeLayer) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        pendingDeleteEndpoint = null;
        closeLayer(true);
        return;
      }
      if (event.key !== 'Tab') return;
      var focusable = Array.prototype.filter.call(
        activeLayer.querySelectorAll('button:not([disabled]):not([tabindex="-1"]), input:not([disabled]):not([type="hidden"]):not([tabindex="-1"]), textarea:not([disabled]):not([tabindex="-1"]), [tabindex]:not([tabindex="-1"])'),
        function (element) { return !element.hidden && element.getClientRects().length > 0; }
      );
      if (!focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      var focusIndex = focusable.indexOf(document.activeElement);
      if (event.shiftKey && focusIndex <= 0) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (focusIndex < 0 || document.activeElement === last)) {
        event.preventDefault();
        first.focus();
      }
    });

    var personalList = root.querySelector('[data-agent-personal-endpoint-list]');
    if (personalList) personalList.addEventListener('click', function (event) {
      var button = event.target.closest('[data-personal-action]');
      var row = button && button.closest('[data-personal-endpoint-index]');
      var endpoint = row && personalEndpoints[Number(row.dataset.personalEndpointIndex)];
      if (!button || !endpoint) return;
      if (button.dataset.personalAction === 'edit') {
        editPersonalEndpoint(endpoint, button);
        return;
      }
      var id = endpoint.id || endpoint.endpoint_id;
      if (!id) return;
      pendingDeleteEndpoint = endpoint;
      var name = root.querySelector('[data-agent-personal-delete-name]');
      if (name) name.textContent = endpoint.name || endpoint.label || endpoint.model || '这个端点';
      setFeedback(root.querySelector('[data-agent-personal-endpoint-delete-feedback]'), '', false);
      openLayer(root.querySelector('[data-agent-personal-delete-layer]'), button, '#agentPersonalEndpointDeleteTitle');
    });

    var deleteConfirm = root.querySelector('[data-agent-personal-endpoint-delete-confirm]');
    if (deleteConfirm) deleteConfirm.addEventListener('click', function () {
      var endpoint = pendingDeleteEndpoint;
      var id = endpoint && (endpoint.id || endpoint.endpoint_id);
      var feedback = root.querySelector('[data-agent-personal-endpoint-delete-feedback]');
      if (!id) return;
      deleteConfirm.disabled = true;
      setFeedback(feedback, '正在删除…', false);
      request(endpointUrl(id), {method: 'DELETE'}).then(function () {
        personalEndpoints = personalEndpoints.filter(function (candidate) {
          return personalEndpointId(candidate) !== asText(id);
        });
        renderPersonalEndpoints();
        deleteConfirm.disabled = false;
        pendingDeleteEndpoint = null;
        closeLayer(true);
        setFeedback(root.querySelector('[data-agent-personal-endpoint-feedback]'), '端点已删除。', false);
      }).catch(function (error) {
        deleteConfirm.disabled = false;
        setFeedback(feedback, error.message, true);
      });
    });

    var reviewList = root.querySelector('[data-agent-review-list]');
    if (reviewList) reviewList.addEventListener('submit', function (event) {
      var form = event.target.closest('.agent-access-review-form');
      if (!form) return;
      event.preventDefault();
      var card = form.closest('[data-review-id]');
      var action = event.submitter && event.submitter.dataset.reviewAction;
      if (!card || !action) return;
      var feedback = card.querySelector('[data-review-feedback]');
      if (action === 'approve' && !validateForm(form, feedback, ['approved_amount'])) return;
      Array.prototype.forEach.call(form.elements, function (element) { element.disabled = true; });
      setFeedback(feedback, '正在处理…', false);
      var url = asText(root.dataset.agentAccessReviewUrlTemplate)
        .split('__REQUEST_ID__').join(encodeURIComponent(card.dataset.reviewId));
      request(url, {
        method: 'POST',
        body: {
          action: action,
          approved_amount: action === 'approve' ? form.elements.approved_amount.value : '0',
          review_note: form.elements.review_note.value.trim()
        }
      }).then(function () {
        reviews = reviews.filter(function (item) {
          return asText(item.id || item.request_id) !== card.dataset.reviewId;
        });
        renderReviews();
      }).catch(function (error) {
        Array.prototype.forEach.call(form.elements, function (element) { element.disabled = false; });
        setFeedback(feedback, error.message, true);
      });
    });
    if (reviewList) reviewList.addEventListener('input', clearFieldError);

    var adminTabs = root.querySelector('[data-agent-admin-tabs]');
    bindTabs(root, adminTabs, '[data-agent-admin-tab]', '[data-agent-admin-panel]', 'agentAdminTab', 'agentAdminPanel');
    bindTabs(root, root.querySelector('[data-agent-user-tabs]'), '[data-agent-user-tab]', '[data-agent-user-panel]', 'agentUserTab', 'agentUserPanel');

    var grantForm = root.querySelector('[data-agent-class-grant-form]');
    if (grantForm) {
      grantForm.addEventListener('input', updateClassGrantPreview);
      grantForm.addEventListener('change', updateClassGrantPreview);
      grantForm.addEventListener('submit', function (event) {
        event.preventDefault();
        var selection = selectedClassGrant();
        var submit = root.querySelector('[data-agent-class-grant-submit]');
        var feedback = root.querySelector('[data-agent-class-grant-feedback]');
        if (!validateForm(grantForm, feedback, ['amount_rmb'])) return;
        if (!selection.classes.length || !selection.users) {
          setFeedback(feedback, '请至少选择一个包含普通用户的班级。', true);
          return;
        }
        submit.disabled = true;
        setFeedback(feedback, '正在赠送…', false);
        request(root.dataset.agentAccessClassGrantUrl, {
          method: 'POST',
          body: {
            classes: selection.classes,
            amount_rmb: grantForm.elements.amount_rmb.value
          }
        }).then(function (payload) {
          var count = Number(payload.granted_user_count != null
            ? payload.granted_user_count : selection.users);
          var total = payload.total_amount != null
            ? payload.total_amount
            : multiplyDecimal(grantForm.elements.amount_rmb.value, count);
          grantForm.reset();
          updateClassGrantPreview();
          setFeedback(feedback, '已向 ' + count + ' 位用户赠送，共 ' + moneyText(total) + '。', false);
        }).catch(function (error) {
          submit.disabled = false;
          setFeedback(feedback, error.message, true);
        });
      });
      grantForm.addEventListener('input', clearFieldError);
    }

    if (requestForm) requestForm.addEventListener('input', clearFieldError);

    updateSummary(summary);
    renderPrices();
    renderPersonalEndpoints();
    if (isAdmin) {
      renderReviews();
      renderClasses();
      loadReviews().catch(function () {});
    }

    return {
      update: updateSummary,
      summary: function () { return Object.assign({}, summary); },
      load: function () {
        if (loaded) return Promise.resolve();
        return isAdmin ? loadReviews() : Promise.all([loadSummary(), loadPrices(), loadPersonalEndpoints()]);
      }
    };
  }

  var api = {
    mount: mount,
    decimalText: decimalText,
    moneyText: moneyText,
    update: function (summary) {
      document.querySelectorAll('[data-agent-access-root]').forEach(function (root) {
        var controller = root.__agentAccessController || mount(root);
        root.__agentAccessController = controller;
        if (controller) controller.update(summary);
      });
    }
  };
  global.NumOJAgentAccess = api;
  document.querySelectorAll('[data-agent-access-root]').forEach(function (root) {
    root.__agentAccessController = mount(root);
  });
}(window));
