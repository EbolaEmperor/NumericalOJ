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
        '[data-agent-quota-total]': summary.total_amount,
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
      var meter = root.querySelector('[data-agent-fab-balance]');
      if (meter) meter.textContent = decimalText(summary.remaining_amount) || '—';
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
        if (!publicEnabled) note.textContent = '全站 Agent 已暂停，当前不能创建任务或继续会话。';
        else if (summary.has_account === false) note.textContent = '你还没有平台额度；申请获批后即可使用全站端点。自有端点不受额度限制。';
        else if (Number.isFinite(remaining) && remaining <= -5) note.textContent = '额度已达到 -5 元，运行中的任务会被系统强制停止。';
        else if (Number.isFinite(remaining) && remaining < 0) note.textContent = '余额低于 0 元；全站端点已停用，自有端点仍可使用。';
        else note.textContent = '使用全站端点时，每次模型请求完成后实时扣减。';
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

    function resetPersonalForm() {
      var form = root.querySelector('[data-agent-personal-endpoint-form]');
      if (!form) return;
      form.reset();
      form.elements.endpoint_id.value = '';
      var cancel = root.querySelector('[data-agent-personal-endpoint-cancel]');
      var label = root.querySelector('[data-agent-personal-editor-label]');
      if (cancel) cancel.hidden = true;
      if (label) label.textContent = '添加端点';
    }

    function editPersonalEndpoint(endpoint) {
      var form = root.querySelector('[data-agent-personal-endpoint-form]');
      var editor = root.querySelector('[data-agent-personal-endpoint-editor]');
      if (!form) return;
      form.elements.endpoint_id.value = endpoint.id || endpoint.endpoint_id || '';
      form.elements.name.value = endpoint.name || endpoint.label || '';
      form.elements.model.value = endpoint.model || '';
      form.elements.protocol.value = endpoint.protocol || 'openai';
      form.elements.base_url.value = endpoint.base_url || '';
      form.elements.api_key.value = '';
      var cancel = root.querySelector('[data-agent-personal-endpoint-cancel]');
      var label = root.querySelector('[data-agent-personal-editor-label]');
      if (cancel) cancel.hidden = false;
      if (label) label.textContent = '编辑端点';
      if (editor) editor.open = true;
      form.elements.name.focus();
    }

    function endpointUrl(id) {
      return asText(root.dataset.agentAccessPersonalEndpointUrlTemplate)
        .split('__ENDPOINT_ID__').join(encodeURIComponent(id));
    }

    function renderPersonalEndpoints() {
      var list = root.querySelector('[data-agent-personal-endpoint-list]');
      if (!list) return;
      if (!personalEndpoints.length) {
        list.innerHTML = '<div class="agent-access-empty">还没有自有端点。添加后即可绕过平台额度使用。</div>';
        return;
      }
      list.innerHTML = personalEndpoints.map(function (endpoint, index) {
        var protocol = endpoint.protocol === 'anthropic' ? 'Anthropic 兼容' : 'OpenAI 兼容';
        return '<article class="agent-personal-endpoint-row" data-personal-endpoint-index="' + index + '">'
          + '<i class="fas fa-key" aria-hidden="true"></i>'
          + '<div><strong>' + escapeHtml(endpoint.name || endpoint.label || endpoint.model || '自有端点') + '</strong><small>' + escapeHtml(endpoint.model || '') + ' · ' + protocol + '</small></div>'
          + '<menu><button type="button" data-personal-action="edit" title="编辑" aria-label="编辑端点"><i class="fas fa-pen" aria-hidden="true"></i></button>'
          + '<button class="is-danger" type="button" data-personal-action="delete" title="删除" aria-label="删除端点"><i class="fas fa-trash-alt" aria-hidden="true"></i></button></menu>'
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
        return '<article class="agent-access-review-card" data-review-id="' + escapeHtml(id) + '">'
          + '<header><div><h3>' + escapeHtml(username) + '</h3><strong>' + escapeHtml(moneyText(item.requested_amount)) + '</strong></div><time>' + escapeHtml(item.created_at || '') + '</time></header>'
          + '<p class="agent-access-review-reason">' + escapeHtml(item.reason || '未填写申请理由') + '</p>'
          + '<form class="agent-access-review-form"><input name="approved_amount" type="number" min="0.01" step="0.01" value="' + escapeHtml(decimalText(item.requested_amount)) + '" aria-label="批准金额" required>'
          + '<input name="review_note" maxlength="1000" placeholder="审核意见（可选）" aria-label="审核意见">'
          + '<button type="submit" data-review-action="approve">通过</button><button type="submit" formnovalidate data-review-action="reject">驳回</button></form>'
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

    var modalNode = root.querySelector('#agentAccessModal');
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

    var requestForm = root.querySelector('[data-agent-quota-request-form]');
    if (requestForm) requestForm.addEventListener('submit', function (event) {
      event.preventDefault();
      if (!requestForm.reportValidity() || !publicEnabled) return;
      var button = root.querySelector('[data-agent-quota-request-submit]');
      var feedback = root.querySelector('[data-agent-quota-request-feedback]');
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
      if (!personalForm.reportValidity()) return;
      var id = asText(personalForm.elements.endpoint_id.value);
      var button = root.querySelector('[data-agent-personal-endpoint-save]');
      var feedback = root.querySelector('[data-agent-personal-endpoint-feedback]');
      button.disabled = true;
      setFeedback(feedback, '正在保存…', false);
      request(id ? endpointUrl(id) : root.dataset.agentAccessPersonalEndpointsUrl, {
        method: id ? 'PUT' : 'POST',
        body: {
          name: personalForm.elements.name.value.trim(),
          model: personalForm.elements.model.value.trim(),
          protocol: personalForm.elements.protocol.value,
          base_url: personalForm.elements.base_url.value.trim(),
          api_key: personalForm.elements.api_key.value
        }
      }).then(function () {
        setFeedback(feedback, id ? '端点已更新，正在刷新…' : '端点已添加，正在刷新…', false);
        global.location.reload();
      }).catch(function (error) {
        button.disabled = false;
        setFeedback(feedback, error.message, true);
      });
    });

    var cancelEdit = root.querySelector('[data-agent-personal-endpoint-cancel]');
    if (cancelEdit) cancelEdit.addEventListener('click', resetPersonalForm);

    var personalList = root.querySelector('[data-agent-personal-endpoint-list]');
    if (personalList) personalList.addEventListener('click', function (event) {
      var button = event.target.closest('[data-personal-action]');
      var row = button && button.closest('[data-personal-endpoint-index]');
      var endpoint = row && personalEndpoints[Number(row.dataset.personalEndpointIndex)];
      if (!button || !endpoint) return;
      if (button.dataset.personalAction === 'edit') {
        editPersonalEndpoint(endpoint);
        return;
      }
      var id = endpoint.id || endpoint.endpoint_id;
      if (!id || !global.confirm('确定删除这个自有端点？')) return;
      button.disabled = true;
      request(endpointUrl(id), {method: 'DELETE'}).then(function () {
        global.location.reload();
      }).catch(function (error) {
        button.disabled = false;
        setFeedback(root.querySelector('[data-agent-personal-endpoint-feedback]'), error.message, true);
      });
    });

    var reviewList = root.querySelector('[data-agent-review-list]');
    if (reviewList) reviewList.addEventListener('submit', function (event) {
      var form = event.target.closest('.agent-access-review-form');
      if (!form) return;
      event.preventDefault();
      var card = form.closest('[data-review-id]');
      var action = event.submitter && event.submitter.dataset.reviewAction;
      if (!card || !action || (action === 'approve' && !form.reportValidity())) return;
      Array.prototype.forEach.call(form.elements, function (element) { element.disabled = true; });
      var feedback = card.querySelector('[data-review-feedback]');
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

    var adminTabs = root.querySelector('[data-agent-admin-tabs]');
    if (adminTabs) adminTabs.addEventListener('click', function (event) {
      var button = event.target.closest('[data-agent-admin-tab]');
      if (!button) return;
      var name = button.dataset.agentAdminTab;
      root.querySelectorAll('[data-agent-admin-tab]').forEach(function (candidate) {
        var active = candidate === button;
        candidate.classList.toggle('is-current', active);
        candidate.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      root.querySelectorAll('[data-agent-admin-panel]').forEach(function (panel) {
        panel.hidden = panel.dataset.agentAdminPanel !== name;
      });
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
        if (!grantForm.reportValidity() || !selection.classes.length || !selection.users) return;
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
    }

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
