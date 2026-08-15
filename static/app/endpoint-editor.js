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
      ['input_price_per_million', 'cached_input_price_per_million', 'output_price_per_million'].forEach(function (name) {
        form.elements[name].value = initial[name] != null ? initial[name] : '';
      });
      updateKeyState(); setThinking(Boolean(initial.thinking_enabled));
      return controller;
    }

    function fill(value) {
      value = value || {}; reset(); editing = Boolean(value.endpoint_id || value.id);
      form.elements.endpoint_id.value = value.endpoint_id || value.id || '';
      choiceValue('protocol', value.protocol || 'openai'); choiceValue('category', value.category || 'text');
      ['name', 'model', 'base_url', 'input_price_per_million', 'cached_input_price_per_million', 'output_price_per_million'].forEach(function (name) {
        if (form.elements[name] && !form.elements[name].disabled && value[name] != null) form.elements[name].value = value[name];
      });
      form.elements.api_key.value = ''; updateKeyState(); setThinking(Boolean(value.thinking_enabled)); clearResult();
      return controller;
    }

    function values() {
      var id = form.elements.endpoint_id.value;
      return {
        endpoint_id: id ? Number(id) : undefined,
        name: form.elements.name && !form.elements.name.disabled ? form.elements.name.value.trim() : '',
        model: form.elements.model.value.trim(), protocol: form.elements.protocol.value,
        category: form.elements.category.value, base_url: form.elements.base_url.value.trim(),
        api_key: form.elements.api_key.value,
        thinking_enabled: form.elements.thinking_enabled.value === 'true',
        thinking_format: form.elements.thinking_format.value,
        input_price_per_million: form.elements.input_price_per_million.value.trim(),
        cached_input_price_per_million: form.elements.cached_input_price_per_million.value.trim(),
        output_price_per_million: form.elements.output_price_per_million.value.trim()
      };
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
      if (invalid) {
        invalid.classList.add('is-invalid'); invalid.setAttribute('aria-invalid', 'true');
        setResult(invalid.name === 'api_key' ? '新建端点必须填写 API 密钥。' : '请检查并补全端点配置。', 'error');
        invalid.focus(); return false;
      }
      return true;
    }

    var controller = {form: form, configure: configure, reset: reset, fill: fill, values: values,
      validate: validate, setResult: setResult, clearResult: clearResult, setThinking: setThinking};
    form.__endpointEditorController = controller;
    thinking.addEventListener('click', function () {
      setThinking(form.elements.thinking_enabled.value !== 'true');
      form.elements.thinking_enabled.dispatchEvent(new Event('change', {bubbles: true}));
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
