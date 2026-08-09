(function (global) {
  'use strict';

  var root = document.querySelector('[data-agent-home]');
  if (!root) return;

  var HARNESS_LABELS = {
    claude_code: 'Claude Code',
    codex: 'Codex',
    opencode: 'OpenCode',
    pi: 'Pi'
  };
  var HARNESS_LOGOS = {
    claude_code: 'claude-code',
    codex: 'codex',
    opencode: 'opencode',
    pi: 'pi'
  };
  var PROTOCOL_LABELS = {
    openai: 'OpenAI 兼容',
    anthropic: 'Anthropic 兼容'
  };
  var CATEGORY_LABELS = {
    text: '纯文本',
    vision: '视觉理解',
    omni: '全模态',
    embedding: '向量'
  };
  function asText(value) {
    return value == null ? '' : String(value).trim();
  }

  function canonicalHarness(value) {
    var normalized = asText(value).toLowerCase().replace(/-/g, '_');
    return normalized === 'open_code' ? 'opencode' : normalized;
  }

  function harnessIcon(value) {
    var logo = HARNESS_LOGOS[canonicalHarness(value)];
    return logo ? 'harness-logo harness-logo--' + logo : 'fas fa-terminal';
  }

  function readJson(selector, fallback) {
    var node = root.querySelector(selector);
    if (!node) return fallback;
    try {
      return JSON.parse(node.textContent || '');
    } catch (_error) {
      return fallback;
    }
  }

  function normalizeHarness(item) {
    if (typeof item === 'string') {
      return {
        value: item,
        label: HARNESS_LABELS[canonicalHarness(item)] || item
      };
    }
    if (!item || typeof item !== 'object') return null;
    var value = asText(item.value || item.key || item.harness || item.id);
    if (!value) return null;
    return {
      value: value,
      label: asText(item.label || item.name) || HARNESS_LABELS[canonicalHarness(value)] || value
    };
  }

  function normalizeEndpoint(item) {
    if (!item || typeof item !== 'object') return null;
    var id = asText(item.id != null ? item.id : item.endpoint_id);
    if (!id) return null;
    return {
      id: id,
      model: asText(item.model || item.label || item.name) || '节点 #' + id,
      protocol: asText(item.protocol).toLowerCase(),
      category: asText(item.category).toLowerCase()
    };
  }

  function endpointMeta(endpoint) {
    return [
      '节点 #' + endpoint.id,
      PROTOCOL_LABELS[endpoint.protocol] || endpoint.protocol,
      CATEGORY_LABELS[endpoint.category] || endpoint.category
    ].filter(Boolean).join(' · ');
  }

  function formatBytes(value) {
    var bytes = Number(value || 0);
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(bytes < 10240 ? 1 : 0) + ' KB';
    return (bytes / 1024 / 1024).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0) + ' MB';
  }

  function paintAvatars(scope) {
    var identicon = global.NumojIdenticon;
    if (!identicon) return;
    (scope || document).querySelectorAll('[data-avatar-seed]').forEach(function (avatar) {
      var seed = avatar.getAttribute('data-avatar-seed') || 'numericaloj';
      identicon.paint(
        avatar,
        identicon.cellsForSeed(seed),
        avatar.getAttribute('data-avatar-label') || seed
      );
    });
  }

  function initComposer() {
    var form = root.querySelector('[data-agent-create-form]');
    var textarea = root.querySelector('[data-agent-message]');
    var input = root.querySelector('[data-agent-attachment-input]');
    var strip = root.querySelector('[data-agent-attachments]');
    var submit = root.querySelector('[data-agent-create-submit]');
    var feedback = root.querySelector('[data-agent-create-feedback]');
    var harnessChoice = root.querySelector('[data-agent-harness-choice] [data-rk-choice]');
    var endpointChoice = root.querySelector('[data-agent-endpoint-choice] [data-rk-choice]');
    if (!form || !textarea || !input || !strip || !submit || !global.ChoicePicker) return;

    var rawHarnesses = readJson('[data-agent-harnesses-json]', []);
    var rawEndpoints = readJson('[data-agent-endpoints-json]', {});
    var preference = readJson('[data-agent-preference-json]', {});
    var harnesses = (Array.isArray(rawHarnesses) ? rawHarnesses : [])
      .map(normalizeHarness).filter(Boolean);
    var endpointsByHarness = {};
    var files = [];
    var submitting = false;
    var endpointController = null;

    harnesses.forEach(function (harness) {
      var canonical = canonicalHarness(harness.value);
      var entries = rawEndpoints[harness.value]
        || rawEndpoints[canonical]
        || rawEndpoints[canonical.replace(/_/g, '-')]
        || [];
      endpointsByHarness[harness.value] = (Array.isArray(entries) ? entries : [])
        .map(normalizeEndpoint).filter(Boolean);
    });

    function feedbackMessage(message, error) {
      if (!feedback) return;
      feedback.textContent = message || '';
      feedback.hidden = !message;
      feedback.classList.toggle('is-error', error === true);
    }

    function selectedValue(choice) {
      var inputNode = choice && choice.querySelector('.rk-choice-value');
      return inputNode ? asText(inputNode.value) : '';
    }

    function updateReadyState() {
      var ready = !!asText(textarea.value)
        && !!selectedValue(harnessChoice)
        && !!selectedValue(endpointChoice);
      submit.disabled = submitting || !ready;
    }

    function renderEndpoints(harness, preferredId) {
      var endpoints = endpointsByHarness[harness] || [];
      var selected = endpoints.some(function (endpoint) {
        return endpoint.id === asText(preferredId);
      }) ? asText(preferredId) : (endpoints[0] ? endpoints[0].id : '');
      endpointController = global.ChoicePicker.configure(
        endpointChoice,
        endpoints.map(function (endpoint) {
          return {
            value: endpoint.id,
            label: endpoint.model,
            icon: 'fa-microchip',
            model: endpoint.model,
            meta: endpointMeta(endpoint)
          };
        }),
        selected,
        {disabled: submitting || endpoints.length === 0}
      );
      if (!endpoints.length) feedbackMessage('该 Harness 暂无兼容的模型节点。', true);
      else feedbackMessage('', false);
      updateReadyState();
    }

    var preferredHarness = asText(preference.harness);
    if (!harnesses.some(function (harness) { return harness.value === preferredHarness; })) {
      preferredHarness = (harnesses.find(function (harness) {
        return (endpointsByHarness[harness.value] || []).length > 0;
      }) || harnesses[0] || {}).value || '';
    }

    var harnessController = global.ChoicePicker.create({
      picker: harnessChoice,
      input: harnessChoice && harnessChoice.querySelector('.rk-choice-value'),
      trigger: harnessChoice && harnessChoice.querySelector('.rk-choice-trigger'),
      menu: harnessChoice && harnessChoice.querySelector('.rk-choice-menu'),
      label: harnessChoice && harnessChoice.querySelector('[data-rk-choice-label]'),
      icon: harnessChoice && harnessChoice.querySelector('[data-rk-choice-icon]'),
      onChange: function (value) { renderEndpoints(value, ''); }
    });
    if (harnessController) {
      harnessController = global.ChoicePicker.configure(
        harnessChoice,
        harnesses.map(function (harness) {
          return {
            value: harness.value,
            label: harness.label,
            icon: harnessIcon(harness.value)
          };
        }),
        preferredHarness,
        {disabled: harnesses.length === 0}
      );
    }
    renderEndpoints(preferredHarness, preference.endpoint_id);
    global.ChoicePicker.init(root);
    var endpointInput = endpointChoice && endpointChoice.querySelector('.rk-choice-value');
    if (endpointInput) endpointInput.addEventListener('change', updateReadyState);

    function resizeTextarea() {
      textarea.style.height = 'auto';
      textarea.style.height = Math.min(280, Math.max(104, textarea.scrollHeight)) + 'px';
    }

    function fileKey(file) {
      return [file.name, file.size, file.lastModified].join(':');
    }

    function renderFiles() {
      strip.replaceChildren();
      strip.hidden = files.length === 0;
      files.forEach(function (file, index) {
        var chip = document.createElement('span');
        chip.className = 'agent-attachment-chip';

        var icon = document.createElement('i');
        icon.className = file.type && file.type.indexOf('image/') === 0
          ? 'fas fa-image' : 'fas fa-paperclip';
        icon.setAttribute('aria-hidden', 'true');

        var copy = document.createElement('span');
        copy.className = 'agent-attachment-chip-copy';
        var name = document.createElement('strong');
        name.textContent = file.name;
        name.title = file.name;
        var size = document.createElement('small');
        size.textContent = formatBytes(file.size);
        copy.append(name, size);

        var remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'agent-attachment-remove';
        remove.setAttribute('aria-label', '移除附件 ' + file.name);
        remove.innerHTML = '<i class="fas fa-times" aria-hidden="true"></i>';
        remove.addEventListener('click', function () {
          files.splice(index, 1);
          renderFiles();
        });
        chip.append(icon, copy, remove);
        strip.appendChild(chip);
      });
    }

    function addFiles(fileList) {
      var existing = new Set(files.map(fileKey));
      Array.prototype.forEach.call(fileList || [], function (file) {
        if (!file || existing.has(fileKey(file))) return;
        existing.add(fileKey(file));
        files.push(file);
      });
      renderFiles();
    }

    function setSubmitting(value) {
      submitting = value === true;
      form.classList.toggle('is-submitting', submitting);
      textarea.disabled = submitting;
      input.disabled = submitting;
      if (harnessController) harnessController.setDisabled(submitting || harnesses.length === 0);
      if (endpointController) endpointController.setDisabled(
        submitting || !(endpointsByHarness[selectedValue(harnessChoice)] || []).length
      );
      submit.innerHTML = submitting
        ? '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>'
        : '<i class="fas fa-arrow-up" aria-hidden="true"></i>';
      updateReadyState();
    }

    input.addEventListener('change', function () {
      addFiles(input.files);
      input.value = '';
    });
    textarea.addEventListener('input', function () {
      resizeTextarea();
      updateReadyState();
      if (asText(textarea.value)) feedbackMessage('', false);
    });
    textarea.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && (event.metaKey || event.ctrlKey) && !submit.disabled) {
        event.preventDefault();
        if (typeof form.requestSubmit === 'function') form.requestSubmit(submit);
      }
    });

    ['dragenter', 'dragover'].forEach(function (name) {
      form.addEventListener(name, function (event) {
        if (!event.dataTransfer || Array.prototype.indexOf.call(event.dataTransfer.types, 'Files') < 0) return;
        event.preventDefault();
        event.dataTransfer.dropEffect = 'copy';
        form.classList.add('is-dragging');
      });
    });
    ['dragleave', 'drop'].forEach(function (name) {
      form.addEventListener(name, function (event) {
        if (name === 'drop') event.preventDefault();
        form.classList.remove('is-dragging');
      });
    });
    form.addEventListener('drop', function (event) {
      if (event.dataTransfer) addFiles(event.dataTransfer.files);
    });

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (submitting || submit.disabled) return;
      if (!asText(textarea.value)) {
        textarea.focus();
        return;
      }
      var body = new FormData(form);
      body.delete(input.name);
      files.forEach(function (file) { body.append(input.name, file, file.name); });
      feedbackMessage('', false);
      setSubmitting(true);
      global.fetch(form.action, {
        method: 'POST',
        body: body,
        headers: {'Accept': 'application/json'},
        credentials: 'same-origin'
      }).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (payload) {
          if (!response.ok || !payload || !payload.detail_url) {
            throw new Error(asText(payload && payload.message) || '创建会话失败（HTTP ' + response.status + '）');
          }
          return payload;
        });
      }).then(function (payload) {
        global.location.assign(payload.detail_url);
      }).catch(function (error) {
        setSubmitting(false);
        feedbackMessage(error && error.message ? error.message : '创建会话失败，请稍后重试。', true);
      });
    });

    resizeTextarea();
    updateReadyState();
  }

  paintAvatars(root);
  initComposer();
}(window));
