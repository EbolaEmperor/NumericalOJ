(function (global) {
  'use strict';

  var PROTOCOL_LABELS = {
    openai: 'OpenAI 兼容',
    anthropic: 'Anthropic 兼容'
  };

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

  function protocolText(value) {
    var protocol = asText(value).toLowerCase();
    if (!protocol) protocol = 'openai';
    return PROTOCOL_LABELS[protocol] || asText(value) + ' 兼容';
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
        var model = endpoint.model || endpoint.name || '未命名模型';
        var protocol = protocolText(endpoint.protocol);
        var logoClass = global.NumojModelFamily
          ? global.NumojModelFamily.iconClass(model)
          : 'fas fa-microchip';
        return '<article class="agent-rate-card">'
          + '<header class="agent-rate-card-header"><span class="agent-rate-logo"><i class="' + escapeHtml(logoClass) + '" data-model-family-logo data-model-name="' + escapeHtml(model) + '" aria-hidden="true"></i></span>'
          + '<div class="agent-rate-card-name"><strong title="' + escapeHtml(model) + '">' + escapeHtml(model) + '</strong><small>' + escapeHtml(protocol) + '</small></div></header>'
          + '<dl class="agent-rate-values" aria-label="节点价格，人民币每百万 Token">'
          + '<div class="agent-rate-value"><dt>INPUT</dt><dd>' + escapeHtml(decimalText(endpoint.input_price_per_million) || '—') + '</dd></div>'
          + '<div class="agent-rate-value"><dt>CACHED</dt><dd>' + escapeHtml(decimalText(endpoint.cached_input_price_per_million) || '—') + '</dd></div>'
          + '<div class="agent-rate-value"><dt>OUTPUT</dt><dd>' + escapeHtml(decimalText(endpoint.output_price_per_million) || '—') + '</dd></div>'
          + '</dl>'
          + '</article>';
      }).join('');
    }

    var activeLayer = null;
    var layerOpener = null;
    var pendingDeleteEndpoint = null;
    var modalNode = root.querySelector('#agentAccessModal');
    var accessModal = modalNode && global.bootstrap
      ? global.bootstrap.Modal.getOrCreateInstance(modalNode) : null;
    var personalModalNode = root.querySelector('#agentPersonalEndpointModal');
    var personalModal = personalModalNode && global.bootstrap
      ? global.bootstrap.Modal.getOrCreateInstance(personalModalNode) : null;
    var personalModalOpener = null;
    var switchingToPersonalModal = false;
    var returningFromPersonalModal = false;
    var modalContent = modalNode && modalNode.querySelector('.modal-content');
    var modalHeader = modalContent && modalContent.querySelector(':scope > .agent-access-modal-header');
    var modalScroll = modalContent && modalContent.querySelector(':scope > .agent-access-modal-scroll');
    var personalForm = root.querySelector('[data-endpoint-editor][data-endpoint-editor-mode="personal"]');
    var personalEditorRevision = 0;
    var personalTestRequestRevision = 0;
    var personalSaveRequestRevision = 0;
    var personalTestToken = '';
    var personalFormFingerprint = '';
    var personalEditor = personalForm && global.NumOJEndpointEditor.mount(personalForm, {
      createKeyNote: '新建端点必须填写 API 密钥。',
      editKeyNote: '留空表示继续使用已保存的密钥。'
    });

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

    function personalEndpointPayload() {
      var payload = personalEditor.values();
      delete payload.name;
      delete payload.input_price_per_million;
      delete payload.cached_input_price_per_million;
      delete payload.output_price_per_million;
      return payload;
    }

    function endpointFingerprint(payload) {
      return JSON.stringify(payload, Object.keys(payload).sort());
    }

    function invalidatePersonalEndpointTest(clearResult) {
      personalTestToken = '';
      personalFormFingerprint = '';
      var save = personalForm && personalForm.querySelector('[data-endpoint-editor-save]');
      if (save) save.disabled = true;
      if (clearResult !== false && personalEditor) personalEditor.clearResult();
    }

    function showPersonalEndpointModal(opener) {
      if (!personalModal || !accessModal) return;
      if (switchingToPersonalModal || returningFromPersonalModal
          || personalModalNode.classList.contains('show')) return;
      personalModalOpener = opener || document.activeElement;
      switchingToPersonalModal = true;
      if (modalNode.classList.contains('show')) {
        modalNode.addEventListener('hidden.bs.modal', function () {
          switchingToPersonalModal = false;
          personalModal.show();
        }, {once: true});
        accessModal.hide();
      } else {
        switchingToPersonalModal = false;
        personalModal.show();
      }
    }

    function resetPersonalForm() {
      if (!personalEditor) return;
      personalEditorRevision += 1;
      personalTestRequestRevision += 1;
      personalSaveRequestRevision += 1;
      setEndpointButtonBusy(personalForm.querySelector('[data-endpoint-editor-test]'), false);
      setEndpointButtonBusy(personalForm.querySelector('[data-endpoint-editor-save]'), false);
      personalEditor.configure({title: '新建端点'});
      personalEditor.reset({protocol: 'openai', category: 'text'});
      invalidatePersonalEndpointTest(false);
    }

    function editPersonalEndpoint(endpoint, opener) {
      if (!personalEditor) return;
      if (switchingToPersonalModal || returningFromPersonalModal
          || personalModalNode.classList.contains('show')) return;
      personalEditorRevision += 1;
      personalTestRequestRevision += 1;
      personalSaveRequestRevision += 1;
      setEndpointButtonBusy(personalForm.querySelector('[data-endpoint-editor-test]'), false);
      setEndpointButtonBusy(personalForm.querySelector('[data-endpoint-editor-save]'), false);
      personalEditor.configure({title: '编辑端点'});
      personalEditor.fill({
        endpoint_id: endpoint.id || endpoint.endpoint_id || '',
        model: endpoint.model || '',
        protocol: endpoint.protocol || 'openai',
        category: endpoint.category || 'text',
        base_url: endpoint.base_url || '',
        thinking_enabled: Boolean(endpoint.thinking_enabled),
        thinking_format: endpoint.thinking_format || 'none'
      });
      invalidatePersonalEndpointTest(false);
      showPersonalEndpointModal(opener);
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
        list.innerHTML = '';
        return;
      }
      list.innerHTML = personalEndpoints.map(function (endpoint, index) {
        var protocol = protocolText(endpoint.protocol);
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
          + '<header><div><span class="agent-personal-endpoint-number">额度申请 #' + escapeHtml(id) + '</span><h3>' + escapeHtml(username) + '</h3></div><div class="agent-access-review-meta"><time>' + escapeHtml(item.created_at || '') + '</time></div></header>'
          + (className ? '<span class="agent-access-review-class"><i class="fas fa-users" aria-hidden="true"></i>' + escapeHtml(className) + '</span>' : '')
          + '<p class="agent-access-review-reason">' + escapeHtml(item.reason || '未填写申请理由') + '</p>'
          + '<form class="agent-access-review-form" novalidate>'
          + '<label class="agent-access-field"><span>赠送额度</span><span class="agent-access-input-shell agent-access-money-input"><b>¥</b><input name="approved_amount" type="number" min="0.01" step="0.01" inputmode="decimal" placeholder="0.00" aria-label="赠送额度" required></span></label>'
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

    function classLogoMarkup(item, className) {
      var classesText = className || 'agent-class-option-logo';
      var cells = item && item.logo && Array.isArray(item.logo.cells) ? item.logo.cells : [];
      if (!cells.length) {
        return '<span class="' + classesText + ' is-placeholder" aria-hidden="true"></span>';
      }
      var rects = cells.filter(function (cell) {
        return Array.isArray(cell) && cell.length >= 2
          && Number.isInteger(Number(cell[0])) && Number.isInteger(Number(cell[1]));
      }).map(function (cell) {
        return '<rect x="' + (Number(cell[0]) + 1) + '" y="' + (Number(cell[1]) + 1)
          + '" width="1" height="1"></rect>';
      });
      return '<span class="' + classesText + '" aria-hidden="true">'
        + '<svg viewBox="0 0 7 7" focusable="false" shape-rendering="crispEdges">'
        + rects.join('') + '</svg></span>';
    }

    function selectedClassInputs() {
      return Array.prototype.slice.call(
        root.querySelectorAll('[data-agent-class-grant-options] input[name="classes"]:checked')
      );
    }

    function syncClassPicker() {
      var selected = selectedClassInputs();
      var label = root.querySelector('[data-agent-class-picker-label]');
      var codes = root.querySelector('[data-agent-class-picker-codes]');
      var logo = root.querySelector('[data-agent-class-picker-logo]');
      if (label) label.textContent = selected.length ? '已选择 ' + selected.length + ' 个班级' : '选择班级';
      if (codes) codes.textContent = selected.length
        ? selected.map(function (input) { return input.value; }).join(' · ')
        : 'MULTIPLE SELECT';
      if (logo) {
        var item = selected.length ? classes.find(function (candidate) {
          return classKey(candidate) === selected[0].value;
        }) : null;
        var holder = document.createElement('div');
        holder.innerHTML = classLogoMarkup(item, 'agent-class-picker-logo');
        var replacement = holder.firstElementChild;
        if (replacement) {
          Array.prototype.forEach.call(logo.attributes, function (attribute) {
            if (attribute.name.indexOf('data-') === 0) replacement.setAttribute(attribute.name, attribute.value);
          });
          logo.replaceWith(replacement);
        }
      }
    }

    function selectedClassGrant() {
      var selected = selectedClassInputs().map(function (input) { return input.value; });
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
      var trigger = root.querySelector('[data-agent-class-picker-trigger]');
      if (!list) return;
      if (!classes.length) {
        list.innerHTML = '<div class="agent-access-empty">暂无可赠送的班级</div>';
        if (trigger) trigger.disabled = true;
        syncClassPicker();
        updateClassGrantPreview();
        return;
      }
      if (trigger) trigger.disabled = false;
      list.innerHTML = classes.map(function (item) {
        var key = classKey(item);
        var searchText = classLabel(item) + ' ' + key;
        return '<label class="agent-class-option" data-agent-class-search="' + escapeHtml(searchText.toLowerCase()) + '">'
          + '<input class="agent-class-checkbox" type="checkbox" name="classes" value="' + escapeHtml(key) + '">'
          + classLogoMarkup(item, 'agent-class-option-logo')
          + '<span class="agent-class-option-copy"><strong>' + escapeHtml(classLabel(item)) + '</strong><small>' + escapeHtml(key) + '</small></span>'
          + '<span class="agent-class-option-state" aria-hidden="true"><i class="fas fa-check"></i></span></label>';
      }).join('');
      syncClassPicker();
      filterClassPicker();
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
      if (returningFromPersonalModal) {
        returningFromPersonalModal = false;
        return;
      }
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
      if (switchingToPersonalModal) return;
      closeLayer(false);
      setClassPickerOpen(false);
      pendingDeleteEndpoint = null;
      resetPersonalForm();
    });
    if (personalModalNode) personalModalNode.addEventListener('shown.bs.modal', function () {
      var title = personalForm && personalForm.querySelector('[data-endpoint-editor-title]');
      if (title) title.focus({preventScroll: true});
    });
    if (personalModalNode) personalModalNode.addEventListener('hidden.bs.modal', function () {
      personalEditorRevision += 1;
      personalTestRequestRevision += 1;
      personalSaveRequestRevision += 1;
      setEndpointButtonBusy(personalTestButton, false);
      setEndpointButtonBusy(personalForm.querySelector('[data-endpoint-editor-save]'), false);
      invalidatePersonalEndpointTest(false);
      if (!accessModal || !document.contains(modalNode)) return;
      var opener = personalModalOpener;
      personalModalOpener = null;
      returningFromPersonalModal = true;
      modalNode.addEventListener('shown.bs.modal', function () {
        var target = opener && document.contains(opener)
          ? opener : root.querySelector('[data-agent-personal-endpoint-create]');
        if (target) target.focus({preventScroll: true});
      }, {once: true});
      accessModal.show();
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

    function setEndpointButtonBusy(button, busy, label) {
      if (!button) return;
      if (busy) {
        if (!button.dataset.idleHtml) button.dataset.idleHtml = button.innerHTML;
        button.disabled = true;
        button.textContent = label;
      } else {
        if (button.dataset.idleHtml) button.innerHTML = button.dataset.idleHtml;
        button.disabled = false;
      }
    }

    var personalTestButton = personalForm && personalForm.querySelector('[data-endpoint-editor-test]');
    if (personalTestButton) personalTestButton.addEventListener('click', function () {
      if (!personalEditor.validate()) return;
      var payload = personalEndpointPayload();
      var testedFingerprint = endpointFingerprint(payload);
      var editorRevision = personalEditorRevision;
      var requestRevision = ++personalTestRequestRevision;
      setEndpointButtonBusy(personalTestButton, true, '测试中…');
      personalEditor.setResult('测试中…', 'pending');
      request(root.dataset.agentAccessPersonalEndpointTestUrl, {
        method: 'POST',
        body: payload
      }).then(function (response) {
        if (requestRevision !== personalTestRequestRevision
            || editorRevision !== personalEditorRevision
            || !personalModalNode.classList.contains('show')) return;
        if (endpointFingerprint(personalEndpointPayload()) !== testedFingerprint) {
          invalidatePersonalEndpointTest(false);
          personalEditor.setResult('字段已经变化，请重新测试连接。', 'error');
          return;
        }
        var test = response.test || response;
        personalTestToken = asText(response.test_token || (test && test.test_token));
        if (!personalTestToken || test.passed === false) {
          invalidatePersonalEndpointTest(false);
          personalEditor.setResult(asText(test.message) || '连接测试失败。', 'error');
          return;
        }
        personalFormFingerprint = testedFingerprint;
        personalEditor.setResult(
          '连接成功'
            + (test.latency_ms != null ? ' · ' + test.latency_ms + ' ms' : '')
            + (test.message ? ' · ' + test.message : ''),
          'ok'
        );
        personalForm.querySelector('[data-endpoint-editor-save]').disabled = false;
      }).catch(function (error) {
        if (requestRevision !== personalTestRequestRevision
            || editorRevision !== personalEditorRevision
            || !personalModalNode.classList.contains('show')) return;
        invalidatePersonalEndpointTest(false);
        personalEditor.setResult(error.message, 'error');
      }).finally(function () {
        if (requestRevision === personalTestRequestRevision) {
          setEndpointButtonBusy(personalTestButton, false);
        }
      });
    });

    if (personalForm) personalForm.addEventListener('input', function () {
      personalEditorRevision += 1;
      invalidatePersonalEndpointTest(true);
    });
    if (personalForm) personalForm.addEventListener('change', function () {
      personalEditorRevision += 1;
      invalidatePersonalEndpointTest(true);
    });

    if (personalForm) personalForm.addEventListener('submit', function (event) {
      event.preventDefault();
      var payload = personalEndpointPayload();
      var id = asText(payload.endpoint_id);
      var button = personalForm.querySelector('[data-endpoint-editor-save]');
      var editorRevision = personalEditorRevision;
      var requestRevision = ++personalSaveRequestRevision;
      if (!personalEditor.validate()) return;
      if (!personalTestToken || personalFormFingerprint !== endpointFingerprint(payload)) {
        invalidatePersonalEndpointTest(false);
        personalEditor.setResult('字段已经变化，请重新测试连接。', 'error');
        return;
      }
      payload.test_token = personalTestToken;
      setEndpointButtonBusy(button, true, '保存中…');
      request(id ? endpointUrl(id) : root.dataset.agentAccessPersonalEndpointsUrl, {
        method: id ? 'PUT' : 'POST',
        body: payload
      }).then(function (response) {
        var endpoint = response && (response.endpoint || response.data);
        if (!upsertPersonalEndpoint(endpoint)) loadPersonalEndpoints().catch(function () {});
        if (requestRevision === personalSaveRequestRevision
            && editorRevision === personalEditorRevision
            && personalModalNode.classList.contains('show')) {
          personalModal.hide();
        }
        setFeedback(root.querySelector('[data-agent-personal-endpoint-feedback]'), id ? '端点已更新。' : '端点已创建。', false);
      }).catch(function (error) {
        if (requestRevision !== personalSaveRequestRevision
            || editorRevision !== personalEditorRevision
            || !personalModalNode.classList.contains('show')) return;
        personalEditor.setResult(error.message, 'error');
      }).finally(function () {
        if (requestRevision !== personalSaveRequestRevision) return;
        setEndpointButtonBusy(button, false);
        if (!personalTestToken
            || personalFormFingerprint !== endpointFingerprint(personalEndpointPayload())) {
          button.disabled = true;
        }
      });
    });

    var createEndpoint = root.querySelector('[data-agent-personal-endpoint-create]');
    if (createEndpoint) createEndpoint.addEventListener('click', function () {
      if (switchingToPersonalModal || returningFromPersonalModal
          || personalModalNode.classList.contains('show')) return;
      resetPersonalForm();
      showPersonalEndpointModal(createEndpoint);
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

    var classPicker = root.querySelector('[data-agent-class-picker]');
    var classPickerTrigger = root.querySelector('[data-agent-class-picker-trigger]');
    var classPickerPanel = root.querySelector('[data-agent-class-picker-panel]');
    var classPickerSearch = root.querySelector('[data-agent-class-picker-search]');
    var classPickerOptions = root.querySelector('[data-agent-class-grant-options]');
    var classPickerEmpty = root.querySelector('[data-agent-class-picker-empty]');

    function setClassPickerOpen(open) {
      if (!classPicker || !classPickerPanel || !classPickerTrigger) return;
      classPicker.classList.toggle('is-open', open);
      classPickerPanel.hidden = !open;
      classPickerTrigger.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open && classPickerSearch) window.setTimeout(function () { classPickerSearch.focus(); }, 0);
    }

    function filterClassPicker() {
      var query = asText(classPickerSearch && classPickerSearch.value).toLowerCase();
      var shown = 0;
      if (classPickerOptions) {
        classPickerOptions.querySelectorAll('.agent-class-option').forEach(function (option) {
          var hit = !query || asText(option.dataset.agentClassSearch).indexOf(query) !== -1;
          option.classList.toggle('is-hidden', !hit);
          if (hit) shown += 1;
        });
      }
      if (classPickerEmpty) classPickerEmpty.hidden = shown > 0;
    }

    if (classPickerTrigger) classPickerTrigger.addEventListener('click', function () {
      setClassPickerOpen(!classPicker.classList.contains('is-open'));
    });
    if (classPickerSearch) classPickerSearch.addEventListener('input', filterClassPicker);
    if (classPickerOptions) classPickerOptions.addEventListener('change', function (event) {
      if (!event.target.matches('input[name="classes"]')) return;
      syncClassPicker();
      updateClassGrantPreview();
    });
    var selectAllClasses = root.querySelector('[data-agent-class-picker-all]');
    if (selectAllClasses) selectAllClasses.addEventListener('click', function () {
      classPickerOptions.querySelectorAll('.agent-class-option:not(.is-hidden) input[name="classes"]')
        .forEach(function (input) { input.checked = true; });
      syncClassPicker();
      updateClassGrantPreview();
    });
    var clearAllClasses = root.querySelector('[data-agent-class-picker-none]');
    if (clearAllClasses) clearAllClasses.addEventListener('click', function () {
      classPickerOptions.querySelectorAll('input[name="classes"]')
        .forEach(function (input) { input.checked = false; });
      syncClassPicker();
      updateClassGrantPreview();
    });
    var finishClassPicker = root.querySelector('[data-agent-class-picker-done]');
    if (finishClassPicker) finishClassPicker.addEventListener('click', function () {
      setClassPickerOpen(false);
      classPickerTrigger.focus();
    });
    root.addEventListener('click', function (event) {
      if (classPicker && classPicker.classList.contains('is-open') && !classPicker.contains(event.target)) {
        setClassPickerOpen(false);
      }
    });
    root.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && classPicker && classPicker.classList.contains('is-open')) {
        event.preventDefault();
        event.stopPropagation();
        setClassPickerOpen(false);
        classPickerTrigger.focus();
      }
    });

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
          syncClassPicker();
          filterClassPicker();
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
