(function (global) {
  'use strict';

  var HARNESS_LABELS = {
    claude_code: 'Claude Code',
    codex: 'Codex',
    opencode: 'OpenCode',
    pi: 'Pi'
  };
  var PROTOCOL_LABELS = {
    openai: 'OpenAI 兼容',
    anthropic: 'Anthropic 兼容'
  };
  var CATEGORY_LABELS = {
    omni: '全模态',
    text: '纯文本',
    vision: '视觉理解'
  };
  var HARNESS_LOGOS = {
    claude_code: 'claude-code',
    codex: 'codex',
    opencode: 'opencode',
    pi: 'pi'
  };

  function asText(value) {
    return value == null ? '' : String(value).trim();
  }

  function canonicalHarness(value) {
    var normalized = asText(value).toLowerCase().replace(/-/g, '_');
    if (normalized === 'open_code') return 'opencode';
    return normalized;
  }

  function harnessLogoClass(value) {
    var key = HARNESS_LOGOS[canonicalHarness(value)];
    return key ? 'harness-logo harness-logo--' + key : 'fas fa-terminal';
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
    var rawId = item.id != null ? item.id : item.endpoint_id;
    var id = asText(rawId);
    var numericId = Number(id);
    if (!id || !Number.isSafeInteger(numericId) || numericId <= 0) return null;
    return {
      id: id,
      numericId: numericId,
      model: asText(item.model) || '节点 #' + id,
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

  function requestJson(url, options) {
    return global.fetch(url, options).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (payload) {
        if (!response.ok || !payload || payload.success !== true) {
          throw new Error(asText(payload && payload.message) || '请求失败（' + response.status + '）');
        }
        return payload;
      });
    });
  }

  function addQuery(url, key, value) {
    return url + (url.indexOf('?') >= 0 ? '&' : '?') +
      encodeURIComponent(key) + '=' + encodeURIComponent(value);
  }

  function AgentLauncher(root) {
    this.root = root;
    this.taskKind = asText(root.getAttribute('data-task-kind'));
    this.optionsUrl = asText(root.getAttribute('data-options-url'));
    this.submitUrl = asText(root.getAttribute('data-submit-url'));
    this.feedback = root.querySelector('[data-agent-launch-feedback]');
    this.submitButton = root.querySelector('[data-agent-launch-submit]');
    this.submitIdleHtml = this.submitButton ? this.submitButton.innerHTML : '';
    this.harnessChoice = root.querySelector('[data-agent-choice="harness"]');
    this.endpointChoice = root.querySelector('[data-agent-choice="endpoint"]');
    this.solutionFileInput = root.querySelector('[data-agent-solution-file]');
    this.solutionFilePicker = root.querySelector('[data-agent-solution-picker]');
    this.solutionFileTitle = root.querySelector('.agent-launch-file-title');
    this.solutionFileName = root.querySelector('[data-agent-solution-file-name]');
    this.solutionFileAction = root.querySelector('[data-agent-solution-file-action]');
    this.harnesses = [];
    this.endpointsByHarness = {};
    this.loading = false;
    this.submitting = false;
    this.completed = false;
    this.loadGeneration = 0;

    var self = this;
    this.harnessPicker = this.createPicker(this.harnessChoice, function (value) {
      self.renderEndpoints(value, '');
    });
    this.endpointPicker = this.createPicker(this.endpointChoice, function () {
      self.updateReadyState();
      if (self.selectedEndpoint()) self.setFeedback('', '');
    });
    this.bindSolutionFile();

    if (this.submitButton) {
      this.submitButton.addEventListener('click', function () { self.submit(); });
    }
    root.addEventListener('show.bs.modal', function () {
      self.completed = false;
      self.loadOptions();
    });
    root.addEventListener('hidden.bs.modal', function () {
      if (global.ChoicePicker) global.ChoicePicker.closeAll(null);
    });
  }

  AgentLauncher.prototype.createPicker = function (choice, onChange) {
    if (!choice || !global.ChoicePicker) return null;
    return global.ChoicePicker.create({
      picker: choice,
      input: choice.querySelector('[data-agent-choice-input]'),
      trigger: choice.querySelector('.rk-choice-trigger'),
      menu: choice.querySelector('.rk-choice-menu'),
      label: choice.querySelector('[data-rk-choice-label]'),
      icon: choice.querySelector('[data-rk-choice-icon]'),
      onChange: onChange
    });
  };

  AgentLauncher.prototype.choiceParts = function (choice) {
    return {
      input: choice && choice.querySelector('[data-agent-choice-input]'),
      label: choice && choice.querySelector('[data-rk-choice-label]'),
      icon: choice && choice.querySelector('[data-rk-choice-icon]'),
      menu: choice && choice.querySelector('.rk-choice-menu')
    };
  };

  AgentLauncher.prototype.setChoicePlaceholder = function (choice, picker, label, iconClass, disabled) {
    var parts = this.choiceParts(choice);
    if (choice && global.ChoicePicker) {
      picker = global.ChoicePicker.configure(choice, [], '', {disabled: disabled === true});
    }
    if (parts.input) parts.input.value = '';
    if (parts.label) parts.label.textContent = label;
    if (parts.icon) parts.icon.className = iconClass;
  };

  AgentLauncher.prototype.setLoadingState = function () {
    this.loading = true;
    this.setChoicePlaceholder(
      this.harnessChoice,
      this.harnessPicker,
      '正在加载…',
      'fas fa-circle-notch fa-spin',
      true
    );
    this.setChoicePlaceholder(
      this.endpointChoice,
      this.endpointPicker,
      '正在加载…',
      'fas fa-circle-notch fa-spin',
      true
    );
    this.setFeedback('正在读取可用的 Harness 和 LLM 节点…', 'loading');
    this.updateReadyState();
  };

  AgentLauncher.prototype.normalizeOptions = function (payload) {
    var rawHarnesses = Array.isArray(payload.harnesses) ? payload.harnesses : [];
    this.harnesses = rawHarnesses.map(normalizeHarness).filter(Boolean);
    this.endpointsByHarness = {};
    var rawMap = payload.endpoints_by_harness && typeof payload.endpoints_by_harness === 'object'
      ? payload.endpoints_by_harness : {};
    var self = this;
    this.harnesses.forEach(function (harness) {
      var canonical = canonicalHarness(harness.value);
      var entries = rawMap[harness.value] || rawMap[canonical] || rawMap[canonical.replace(/_/g, '-')];
      self.endpointsByHarness[harness.value] = (Array.isArray(entries) ? entries : [])
        .map(normalizeEndpoint)
        .filter(Boolean);
    });
  };

  AgentLauncher.prototype.endpointsFor = function (harness) {
    return this.endpointsByHarness[harness] || [];
  };

  AgentLauncher.prototype.loadOptions = function () {
    var self = this;
    var generation = ++this.loadGeneration;
    this.setLoadingState();
    if (!this.optionsUrl || !this.taskKind) {
      this.finishLoadError('缺少 Agent 启动配置。');
      return;
    }
    requestJson(addQuery(this.optionsUrl, 'task_kind', this.taskKind), {
      method: 'GET',
      cache: 'no-store',
      headers: {'Accept': 'application/json'}
    }).then(function (payload) {
      if (generation !== self.loadGeneration) return;
      self.normalizeOptions(payload || {});
      var preference = payload && payload.preference && typeof payload.preference === 'object'
        ? payload.preference : {};
      self.renderLoadedOptions(preference);
    }).catch(function (error) {
      if (generation !== self.loadGeneration) return;
      self.finishLoadError(error && error.message ? error.message : '无法读取 Agent 配置。');
    });
  };

  AgentLauncher.prototype.renderLoadedOptions = function (preference) {
    this.harnessPicker = global.ChoicePicker.configure(
      this.harnessChoice,
      this.harnesses.map(function (harness) {
        return {
          value: harness.value,
          label: harness.label,
          icon: harnessLogoClass(harness.value)
        };
      }),
      '',
      {disabled: false}
    );

    if (!this.harnesses.length) {
      this.finishLoadError('当前没有可用的 Harness。');
      return;
    }

    var preferredHarness = asText(preference.harness);
    var selectedHarness = this.harnesses.find(function (harness) {
      return harness.value === preferredHarness;
    });
    if (!selectedHarness || !this.endpointsFor(selectedHarness.value).length) {
      selectedHarness = this.harnesses.find(function (harness) {
        return this.endpointsFor(harness.value).length > 0;
      }, this) || this.harnesses[0];
    }

    this.loading = false;
    this.harnessPicker.setDisabled(false);
    this.harnessPicker.setValue(selectedHarness.value, false);
    this.renderEndpoints(selectedHarness.value, asText(preference.endpoint_id));
  };

  AgentLauncher.prototype.renderEndpoints = function (harness, preferredId) {
    var endpoints = this.endpointsFor(harness);

    if (!endpoints.length) {
      this.setChoicePlaceholder(
        this.endpointChoice,
        this.endpointPicker,
        '无兼容节点',
        'fas fa-unlink',
        true
      );
      this.setFeedback('该 Harness 暂无兼容的 LLM 节点，请选择其他 Harness。', 'error');
      this.updateReadyState();
      return;
    }

    var selected = endpoints.find(function (endpoint) { return endpoint.id === asText(preferredId); }) || endpoints[0];
    this.endpointPicker = global.ChoicePicker.configure(
      this.endpointChoice,
      endpoints.map(function (endpoint) {
        return {
          value: endpoint.id,
          label: endpoint.model,
          icon: 'fa-microchip',
          model: endpoint.model,
          meta: endpointMeta(endpoint)
        };
      }),
      selected.id,
      {disabled: false}
    );
    this.setFeedback('', '');
    this.updateReadyState();
  };

  AgentLauncher.prototype.finishLoadError = function (message) {
    this.loading = false;
    this.setChoicePlaceholder(
      this.harnessChoice,
      this.harnessPicker,
      '暂不可用',
      'fas fa-exclamation-triangle',
      true
    );
    this.setChoicePlaceholder(
      this.endpointChoice,
      this.endpointPicker,
      '暂不可用',
      'fas fa-exclamation-triangle',
      true
    );
    this.setFeedback(message, 'error');
    this.updateReadyState();
  };

  AgentLauncher.prototype.selectedHarness = function () {
    return this.harnessPicker ? asText(this.harnessPicker.value()) : '';
  };

  AgentLauncher.prototype.selectedEndpoint = function () {
    var harness = this.selectedHarness();
    var endpointId = this.endpointPicker ? asText(this.endpointPicker.value()) : '';
    return this.endpointsFor(harness).find(function (endpoint) { return endpoint.id === endpointId; }) || null;
  };

  AgentLauncher.prototype.updateReadyState = function () {
    if (!this.submitButton) return;
    var missingSolution = this.taskKind === 'testdata' && !this.selectedSolutionFile();
    this.submitButton.disabled = this.loading || this.submitting || this.completed ||
      !this.selectedHarness() || !this.selectedEndpoint() || missingSolution;
  };

  AgentLauncher.prototype.setFeedback = function (message, kind) {
    if (!this.feedback) return;
    this.feedback.classList.remove('is-loading', 'is-error', 'is-success');
    if (!message) {
      this.feedback.textContent = '';
      this.feedback.hidden = true;
      return;
    }
    this.feedback.textContent = message;
    this.feedback.hidden = false;
    if (kind) this.feedback.classList.add('is-' + kind);
  };

  AgentLauncher.prototype.bindSolutionFile = function () {
    if (!this.solutionFileInput) return;
    var self = this;
    this.solutionFileInput.addEventListener('change', function () {
      self.updateSolutionFileState();
      self.updateReadyState();
    });
    this.updateSolutionFileState();
  };

  AgentLauncher.prototype.selectedSolutionFile = function () {
    if (!this.solutionFileInput || !this.solutionFileInput.files) return null;
    return this.solutionFileInput.files.length ? this.solutionFileInput.files[0] : null;
  };

  AgentLauncher.prototype.updateSolutionFileState = function () {
    var file = this.selectedSolutionFile();
    if (this.solutionFilePicker) this.solutionFilePicker.classList.toggle('has-file', Boolean(file));
    if (this.solutionFileTitle) this.solutionFileTitle.textContent = file ? '已选择正解' : '选择正解文件';
    if (this.solutionFileName) this.solutionFileName.textContent = file ? file.name : '尚未选择文件';
    if (this.solutionFileAction) this.solutionFileAction.textContent = file ? '重新选择' : '选择文件';
  };

  AgentLauncher.prototype.buildPayload = function () {
    var harness = this.selectedHarness();
    var endpoint = this.selectedEndpoint();
    if (!harness || !endpoint) {
      throw new Error('请先选择可用的 Harness 和 LLM 节点。');
    }
    var payload = {
      harness: harness,
      endpoint_id: endpoint.numericId
    };
    if (this.taskKind !== 'testdata') return payload;

    var countInput = this.root.querySelector('#agentTestPointCount');
    var requirementInput = this.root.querySelector('#agentDataRequirement');
    var solutionFile = this.selectedSolutionFile();
    var count = Number(countInput && countInput.value);
    var requirement = requirementInput ? requirementInput.value : '';
    if (!Number.isInteger(count) || count < 1) {
      if (countInput) countInput.focus();
      throw new Error('测试点数量必须是正整数。');
    }
    if (!solutionFile) {
      if (this.solutionFileInput) this.solutionFileInput.focus();
      throw new Error('请选择正解文件。');
    }
    payload.test_point_count = count;
    payload.data_requirement = requirement;
    payload.standard_solution = solutionFile;
    return payload;
  };

  AgentLauncher.prototype.buildRequestOptions = function (payload) {
    var options = {
      method: 'POST',
      headers: {'Accept': 'application/json'}
    };
    if (this.taskKind === 'testdata') {
      var formData = new global.FormData();
      formData.append('harness', payload.harness);
      formData.append('endpoint_id', String(payload.endpoint_id));
      formData.append('test_point_count', String(payload.test_point_count));
      formData.append('data_requirement', payload.data_requirement);
      formData.append('standard_solution', payload.standard_solution, payload.standard_solution.name);
      options.body = formData;
      return options;
    }
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
    return options;
  };

  AgentLauncher.prototype.setSubmitting = function (submitting) {
    this.submitting = submitting;
    if (this.submitButton) {
      this.submitButton.innerHTML = submitting
        ? '<span class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>启动中…'
        : this.submitIdleHtml;
    }
    if (this.harnessPicker) this.harnessPicker.setDisabled(submitting);
    if (this.endpointPicker) this.endpointPicker.setDisabled(submitting || !this.endpointsFor(this.selectedHarness()).length);
    if (this.solutionFileInput) this.solutionFileInput.disabled = submitting;
    if (this.solutionFilePicker) this.solutionFilePicker.classList.toggle('is-disabled', submitting);
    this.updateReadyState();
  };

  AgentLauncher.prototype.submit = function () {
    var payload;
    try {
      payload = this.buildPayload();
    } catch (error) {
      this.setFeedback(error.message, 'error');
      return;
    }
    if (!this.submitUrl || this.submitting) return;

    var self = this;
    this.setFeedback('', '');
    this.setSubmitting(true);
    requestJson(this.submitUrl, this.buildRequestOptions(payload)).then(function (result) {
      self.setSubmitting(false);
      self.completed = true;
      self.updateReadyState();
      if (result.view_url) {
        global.location.href = result.view_url;
        return;
      }
      var taskSuffix = result.task_id ? '（Task ID: ' + result.task_id + '）' : '';
      self.setFeedback('任务已启动' + taskSuffix + '。', 'success');
    }).catch(function (error) {
      self.setSubmitting(false);
      self.setFeedback(error && error.message ? error.message : '请求失败，请稍后再试。', 'error');
    });
  };

  function init() {
    var roots = Array.prototype.slice.call(document.querySelectorAll('[data-agent-launch-modal]'));
    if (!roots.length) return;
    if (!global.ChoicePicker) {
      roots.forEach(function (root) {
        var feedback = root.querySelector('[data-agent-launch-feedback]');
        if (!feedback) return;
        feedback.textContent = '选择器组件加载失败，请刷新页面后重试。';
        feedback.classList.add('is-error');
        feedback.hidden = false;
      });
      return;
    }
    roots.forEach(function (root) { new AgentLauncher(root); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})(window);
