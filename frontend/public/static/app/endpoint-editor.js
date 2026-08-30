(function (global) {
  'use strict';

  var DEFAULT_PROTOCOLS = [
    {value: 'openai', label: 'OpenAI 兼容', icon: 'fa-code'},
    {value: 'anthropic', label: 'Anthropic 兼容', icon: 'fa-brain'}
  ];
  var DEFAULT_CATEGORIES = [
    {value: 'omni', label: '全模态', icon: 'fa-layer-group'},
    {value: 'text', label: '纯文本', icon: 'fa-font'},
    {value: 'vision', label: '视觉理解', icon: 'fa-eye'},
    {value: 'embedding', label: 'Embedding', icon: 'fa-vector-square'}
  ];
  var DEFAULT_CONTEXT_WINDOW_TOKENS = 384000;
  var DEFAULT_MAX_OUTPUT_TOKENS = 32000;

  function entries(items, fallback) {
    return (items || fallback).map(function (item) {
      return typeof item === 'string' ? {value: item, label: item} : item;
    });
  }

  function mount(form, options) {
    if (typeof form === 'string') form = document.querySelector(form);
    if (!form) return null;
    if (form.__endpointEditorController) {
      if (options) form.__endpointEditorController.configure(options);
      return form.__endpointEditorController;
    }

    var settings = Object.assign({mode: form.dataset.endpointEditorMode || 'global'}, options || {});
    var protocolPicker = form.querySelector('[data-endpoint-editor-choice="protocol"]');
    var categoryPicker = form.querySelector('[data-endpoint-editor-choice="category"]');
    var thinking = form.querySelector('[data-endpoint-editor-thinking]');
    var thinkingField = form.querySelector('[data-endpoint-editor-thinking-field]');
    var result = form.querySelector('[data-endpoint-editor-result]');
    var keyNote = form.querySelector('[data-endpoint-editor-key-note]');
    var peakPricing = form.querySelector('[data-endpoint-editor-peak-pricing]');
    var peakToggle = form.querySelector('[data-endpoint-editor-peak-toggle]');
    var peakFields = form.querySelector('[data-endpoint-editor-peak-fields]');
    var protocolController;
    var categoryController;
    var editing = false;

    function choiceValue(name, value) {
      var controller = name === 'protocol' ? protocolController : categoryController;
      var input = form.elements[name];
      if (controller) controller.setValue(value, false);
      else if (input) input.value = value;
    }

    function setThinking(enabled) {
      var category = form.elements.category.value || 'text';
      var active = Boolean(enabled) && category !== 'embedding';
      form.elements.thinking_enabled.value = active ? 'true' : 'false';
      form.elements.thinking_format.value = active
        ? (form.elements.protocol.value === 'anthropic' ? 'thinking_type' : 'enable_thinking') : 'none';
      thinking.setAttribute('aria-checked', active ? 'true' : 'false');
      thinking.querySelector('b').textContent = active ? '开启' : '关闭';
      thinkingField.hidden = category === 'embedding';
    }

    function deriveThinking(preserve) {
      if (form.elements.category.value === 'embedding' && form.elements.protocol.value !== 'openai') {
        choiceValue('protocol', 'openai');
      }
      setThinking(preserve && form.elements.thinking_enabled.value === 'true');
    }

    function setPeakPricing(enabled) {
      if (!peakPricing || !peakToggle || !peakFields) return;
      var active = Boolean(enabled);
      form.elements.peak_pricing_enabled.value = active ? 'true' : 'false';
      peakToggle.setAttribute('aria-checked', active ? 'true' : 'false');
      peakToggle.querySelector('b').textContent = active ? '开启' : '关闭';
      peakFields.hidden = !active;
      ['peak_time_ranges', 'peak_input_price_per_million', 'peak_cached_input_price_per_million', 'peak_output_price_per_million'].forEach(function (name) {
        if (form.elements[name]) form.elements[name].required = active;
      });
    }

    function clearFieldErrors() {
      Array.prototype.forEach.call(form.querySelectorAll('.is-invalid, [aria-invalid="true"]'), function (node) {
        node.classList.remove('is-invalid'); node.removeAttribute('aria-invalid');
      });
    }

    function setResult(message, tone) {
      result.textContent = String(message || '');
      result.className = 'numoj-endpoint-editor__result wide' + (tone ? ' is-' + tone : '');
      result.hidden = !message;
    }

    function clearResult() { setResult('', ''); }

    function updateKeyState() {
      form.elements.api_key.required = !editing;
      keyNote.textContent = editing
        ? (settings.editKeyNote || '留空则保留现有 API 密钥。')
        : (settings.createKeyNote || '新建端点必须填写 API 密钥。');
    }

    function configure(next) {
      settings = Object.assign(settings, next || {});
      protocolController = global.ChoicePicker.configure(
        protocolPicker, entries(settings.protocols, DEFAULT_PROTOCOLS),
        form.elements.protocol.value || settings.defaultProtocol || 'openai'
      );
      if (categoryPicker) {
        categoryController = global.ChoicePicker.configure(
          categoryPicker, entries(settings.categories, DEFAULT_CATEGORIES),
          form.elements.category.value || settings.defaultCategory || 'text'
        );
      }
      if (settings.title) form.querySelector('[data-endpoint-editor-title]').textContent = settings.title;
      updateKeyState();
      deriveThinking(true);
      return controller;
    }

    function reset(initial) {
      form.reset(); editing = false; clearFieldErrors(); clearResult();
      initial = initial || {};
      form.elements.endpoint_id.value = '';
      choiceValue('protocol', initial.protocol || settings.defaultProtocol || 'openai');
      choiceValue('category', initial.category || settings.defaultCategory || 'text');
      ['name', 'model', 'base_url'].forEach(function (name) {
        if (form.elements[name] && !form.elements[name].disabled) form.elements[name].value = initial[name] || '';
      });
      form.elements.context_window_tokens.value = initial.context_window_tokens != null
        ? initial.context_window_tokens : DEFAULT_CONTEXT_WINDOW_TOKENS;
      form.elements.max_output_tokens.value = initial.max_output_tokens != null
        ? initial.max_output_tokens : DEFAULT_MAX_OUTPUT_TOKENS;
      ['input_price_per_million', 'cached_input_price_per_million', 'output_price_per_million'].forEach(function (name) {
        form.elements[name].value = initial[name] != null ? initial[name] : '';
      });
      ['peak_time_ranges', 'peak_input_price_per_million', 'peak_cached_input_price_per_million', 'peak_output_price_per_million'].forEach(function (name) {
        if (form.elements[name]) form.elements[name].value = initial[name] != null ? initial[name] : '';
      });
      setPeakPricing(initial.peak_pricing_enabled === true || initial.peak_pricing_enabled === 'true');
      updateKeyState(); setThinking(Boolean(initial.thinking_enabled));
      return controller;
    }

    function fill(value) {
      value = value || {}; reset(); editing = Boolean(value.endpoint_id || value.id);
      form.elements.endpoint_id.value = value.endpoint_id || value.id || '';
      choiceValue('protocol', value.protocol || 'openai'); choiceValue('category', value.category || 'text');
      ['name', 'model', 'base_url', 'context_window_tokens', 'max_output_tokens', 'input_price_per_million', 'cached_input_price_per_million', 'output_price_per_million', 'peak_time_ranges', 'peak_input_price_per_million', 'peak_cached_input_price_per_million', 'peak_output_price_per_million'].forEach(function (name) {
        if (form.elements[name] && !form.elements[name].disabled && value[name] != null) form.elements[name].value = value[name];
      });
      if (value.context_window_tokens == null) {
        form.elements.context_window_tokens.value = DEFAULT_CONTEXT_WINDOW_TOKENS;
      }
      if (value.max_output_tokens == null) {
        form.elements.max_output_tokens.value = DEFAULT_MAX_OUTPUT_TOKENS;
      }
      form.elements.api_key.value = ''; updateKeyState(); setThinking(Boolean(value.thinking_enabled));
      setPeakPricing(value.peak_pricing_enabled === true || value.peak_pricing_enabled === 'true'); clearResult();
      return controller;
    }

    function values() {
      var id = form.elements.endpoint_id.value;
      var result = {
        endpoint_id: id ? Number(id) : undefined,
        name: form.elements.name && !form.elements.name.disabled ? form.elements.name.value.trim() : '',
        model: form.elements.model.value.trim(), protocol: form.elements.protocol.value,
        category: form.elements.category.value, base_url: form.elements.base_url.value.trim(),
        api_key: form.elements.api_key.value,
        context_window_tokens: form.elements.context_window_tokens.value.trim(),
        max_output_tokens: form.elements.max_output_tokens.value.trim(),
        thinking_enabled: form.elements.thinking_enabled.value === 'true',
        thinking_format: form.elements.thinking_format.value,
        input_price_per_million: form.elements.input_price_per_million.value.trim(),
        cached_input_price_per_million: form.elements.cached_input_price_per_million.value.trim(),
        output_price_per_million: form.elements.output_price_per_million.value.trim()
      };
      if (peakPricing) {
        result.peak_pricing_enabled = form.elements.peak_pricing_enabled.value === 'true';
        result.peak_time_ranges = form.elements.peak_time_ranges.value.trim();
        result.peak_input_price_per_million = form.elements.peak_input_price_per_million.value.trim();
        result.peak_cached_input_price_per_million = form.elements.peak_cached_input_price_per_million.value.trim();
        result.peak_output_price_per_million = form.elements.peak_output_price_per_million.value.trim();
      }
      return result;
    }

    function validate() {
      clearFieldErrors(); clearResult();
      var fields = Array.prototype.slice.call(form.querySelectorAll('input[required]:not(:disabled)'));
      var invalid = fields.find(function (input) {
        if (!input.value.trim()) return true;
        if (input.type === 'url') { try { return !/^https?:$/.test(new URL(input.value).protocol); } catch (_) { return true; } }
        if (input.type === 'number') return !Number.isFinite(Number(input.value)) || Number(input.value) < 0;
        return false;
      });
      if (!invalid && !editing && !form.elements.api_key.value.trim()) invalid = form.elements.api_key;
      var contextTokens = Number(form.elements.context_window_tokens.value);
      var outputTokens = Number(form.elements.max_output_tokens.value);
      if (!invalid && (!Number.isInteger(contextTokens) || contextTokens <= 0 || contextTokens > 2147483647)) {
        invalid = form.elements.context_window_tokens;
      }
      if (!invalid && (!Number.isInteger(outputTokens) || outputTokens <= 0 || outputTokens > 2147483647 || outputTokens > contextTokens)) {
        invalid = form.elements.max_output_tokens;
      }
      if (invalid) {
        invalid.classList.add('is-invalid'); invalid.setAttribute('aria-invalid', 'true');
        setResult(invalid.name === 'api_key' ? '新建端点必须填写 API 密钥。' : '请检查并补全端点配置。', 'error');
        invalid.focus(); return false;
      }
      return true;
    }

    function applyTestedLimits(value) {
      value = value || {};
      if (value.context_window_tokens != null) {
        form.elements.context_window_tokens.value = value.context_window_tokens;
      }
      if (value.max_output_tokens != null) {
        form.elements.max_output_tokens.value = value.max_output_tokens;
      }
      return controller;
    }

    var controller = {form: form, configure: configure, reset: reset, fill: fill, values: values,
      validate: validate, applyTestedLimits: applyTestedLimits, setResult: setResult,
      clearResult: clearResult, setThinking: setThinking};
    form.__endpointEditorController = controller;
    thinking.addEventListener('click', function () {
      setThinking(form.elements.thinking_enabled.value !== 'true');
      form.elements.thinking_enabled.dispatchEvent(new Event('change', {bubbles: true}));
    });
    if (peakToggle) peakToggle.addEventListener('click', function () {
      setPeakPricing(form.elements.peak_pricing_enabled.value !== 'true');
      form.elements.peak_pricing_enabled.dispatchEvent(new Event('change', {bubbles: true}));
    });
    form.addEventListener('change', function (event) {
      if (event.target.name === 'protocol' || event.target.name === 'category') deriveThinking(true);
    });
    form.addEventListener('input', function (event) { event.target.classList.remove('is-invalid'); event.target.removeAttribute('aria-invalid'); });
    configure(settings); reset(settings.initialValues);
    return controller;
  }

  global.NumOJEndpointEditor = Object.freeze({mount: mount});
})(window);
