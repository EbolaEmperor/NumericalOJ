(function () {
  var primaryEditor = document.getElementById('ajeEditor');
  if (!primaryEditor) return;
  var modalEl = document.getElementById('ajeEditModal');
  var modal = (modalEl && window.bootstrap) ? new bootstrap.Modal(modalEl) : null;
  var activeManager = null;
  var editIndex = null;
  var editHarness = document.getElementById('ajeEditHarness');
  var editBaseUrlWrap = document.getElementById('ajeEditBaseUrlWrap');
  var editBaseUrlLabel = document.getElementById('ajeEditBaseUrlLabel');
  var editBaseUrl = document.getElementById('ajeEditBaseUrl');
  var editApiKey = document.getElementById('ajeEditApiKey');
  var editModel = document.getElementById('ajeEditModel');
  var editConcurrency = document.getElementById('ajeEditConcurrency');
  var editStatus = document.getElementById('ajeEditStatus');
  var editDelete = document.getElementById('ajeEditDelete');
  var editApply = document.getElementById('ajeEditApply');
  var harnessPickerCtrl = null;
  var statusPickerCtrl = null;
  var orchPickerCtrl = null;
  function clampNumber(value, min, max, fallback){
    var n = parseInt(value, 10);
    if (!Number.isFinite(n)) n = fallback;
    if (!Number.isFinite(n)) n = min;
    return Math.max(min, Math.min(max, n));
  }
  function initTimeoutControls(){
    document.querySelectorAll('[data-timeout-control]').forEach(function(ctrl){
      var input = ctrl.querySelector('input');
      if (!input) return;
      var min = parseInt(ctrl.getAttribute('data-min'), 10) || 1;
      var max = parseInt(ctrl.getAttribute('data-max'), 10) || 7200;
      var step = parseInt(ctrl.getAttribute('data-step'), 10) || 60;
      function normalize(){
        input.value = String(clampNumber(input.value, min, max, min));
      }
      ctrl.querySelectorAll('[data-timeout-delta]').forEach(function(btn){
        btn.addEventListener('click', function(){
          if (input.disabled) return;
          var delta = parseInt(btn.getAttribute('data-timeout-delta'), 10) || step;
          var current = clampNumber(input.value, min, max, min);
          input.value = String(clampNumber(current + delta, min, max, min));
          input.dispatchEvent(new Event('change', {bubbles:true}));
        });
      });
      input.addEventListener('input', function(){
        input.value = input.value.replace(/[^\d]/g, '');
      });
      input.addEventListener('blur', normalize);
      normalize();
    });
    var form = document.getElementById('rankingEditForm');
    if (form && !form.__ajeTimeoutBound) {
      form.__ajeTimeoutBound = true;
      form.addEventListener('submit', function(){
        document.querySelectorAll('[data-timeout-control]').forEach(function(ctrl){
          var input = ctrl.querySelector('input');
          if (!input || input.disabled) return;
          var min = parseInt(ctrl.getAttribute('data-min'), 10) || 1;
          var max = parseInt(ctrl.getAttribute('data-max'), 10) || 7200;
          input.value = String(clampNumber(input.value, min, max, min));
        });
      });
    }
  }
  function normalizeStatus(e){
    var raw = e && e.status ? String(e.status).toLowerCase() : (e && e.enabled ? 'enabled' : 'disabled');
    return (raw === 'paused' || raw === 'disabled') ? raw : 'enabled';
  }
  function statusLabel(s){
    s = normalizeStatus({status:s});
    if (s === 'paused') return '暂停';
    if (s === 'disabled') return '停用';
    return '启用';
  }
  function statusClass(s){
    s = normalizeStatus({status:s});
    if (s === 'paused') return ' paused';
    if (s === 'disabled') return ' off';
    return '';
  }
  function isEnabled(e){ return normalizeStatus(e) === 'enabled'; }
  function fromServer(list){
    return (list || []).map(function (e) {
      return {id: e.id, harness: e.harness || 'claude_code',
              base_url: e.base_url || '', model: e.model || '',
              concurrency_limit: e.concurrency_limit || 1,
              status: normalizeStatus(e), enabled: normalizeStatus(e) === 'enabled',
              has_key: !!e.has_key, api_key: ''};
    });
  }
  initTimeoutControls();
  function esc(s){var d=document.createElement('div');d.textContent=(s==null?'':String(s));return d.innerHTML;}
  function defaultEndpoint(){
    return {id:null, harness:'claude_code', base_url:'', model:'', concurrency_limit:1, status:'enabled', enabled:true, has_key:false, api_key:''};
  }
  function harnessLabel(h){
    if (h === 'codex') return 'Codex';
    if (h === 'opencode') return 'opencode';
    if (h === 'pi') return 'Pi';
    return 'Claude Code';
  }
  function harnessIcon(h){
    var key = (h === 'codex' || h === 'opencode' || h === 'pi') ? h : 'claude-code';
    return 'harness-logo harness-logo--' + key;
  }
  function createChoicePicker(config){
    return window.ChoicePicker.create({
      input: config.inputId,
      picker: config.pickerId,
      trigger: config.triggerId,
      menu: config.menuId,
      label: config.labelId,
      icon: config.iconId,
      onChange: config.onChange,
      dispatchChange: false,
      notifyByDefault: true,
      notifyOnInit: true
    });
  }
  function modelText(e){
    if ((e.model || '').trim()) return e.model;
    return '';
  }
  function usesFixedOpenCodeEndpoint(manager, harness){
    return harness === 'opencode' && (!manager || manager.poolKind === 'primary');
  }
  function endpointText(manager, e){
    if (usesFixedOpenCodeEndpoint(manager, e.harness)) return '';
    return (e.base_url || '').trim() || '未填写 Base URL';
  }
  function keyText(e){
    if ((e.api_key || '').trim()) return '新 Key 待保存';
    return e.has_key ? 'Key 已配置' : 'Key 未配置';
  }
  function endpointPayload(manager){
    return manager.eps.map(function(e){
      return {id:e.id, harness:e.harness || 'claude_code',
        base_url:(e.base_url||'').trim(), api_key:(e.api_key||'').trim(),
        model:(e.model||'').trim(), concurrency_limit:parseInt(e.concurrency_limit)||1,
        status:normalizeStatus(e), enabled:isEnabled(e)};
    });
  }
  function endpointDirtyState(manager){
    return manager.eps.map(function(e){
      return {
        harness:e.harness || 'claude_code',
        base_url:(e.base_url || '').trim(),
        api_key:(e.api_key || '').trim(),
        has_key:!!e.has_key,
        model:(e.model || '').trim(),
        concurrency_limit:parseInt(e.concurrency_limit, 10) || 1,
        status:normalizeStatus(e)
      };
    });
  }
  function managerSignature(manager){
    return JSON.stringify(manager.dirtyState(manager));
  }
  function syncManagerDirty(manager){
    if (!manager || manager.suspendDirty || manager.savedSignature == null) return;
    var dirty = managerSignature(manager) !== manager.savedSignature;
    var next = dirty ? 'true' : 'false';
    if (manager.root.getAttribute('data-ranking-dirty') === next) return;
    manager.root.setAttribute('data-ranking-dirty', next);
    window.dispatchEvent(new CustomEvent('ranking:dirty-state-change', {
      detail:{source:manager.source, root:manager.root, dirty:dirty}
    }));
  }
  function totalConc(manager){
    return manager.eps.reduce(function(sum, endpoint){
      return sum + (isEnabled(endpoint) ? (parseInt(endpoint.concurrency_limit, 10) || 0) : 0);
    }, 0);
  }
  function updateHead(manager){
    manager.countLabel.textContent = manager.eps.length + ' 个端点';
    manager.totalValue.textContent = totalConc(manager);
  }
  function renderManager(manager){
    if (!manager.eps.length){
      manager.editor.innerHTML = '<div class="aje-empty">暂无端点</div>';
      updateHead(manager);
      syncManagerDirty(manager);
      return;
    }
    var h = '';
    manager.eps.forEach(function(e, i){
      var harness = e.harness || 'claude_code';
      var st = normalizeStatus(e);
      h += '<div class="aje-card' + statusClass(st) + '" data-i="' + i + '">' +
        '<div class="aje-card-top">' +
          '<div class="aje-harness"><i class="' + harnessIcon(harness) + '" aria-hidden="true"></i><span>' + esc(harnessLabel(harness)) + '</span></div>' +
          '<span class="aje-state">' + statusLabel(st) + '</span>' +
        '</div>' +
        '<div class="aje-card-main">' +
          '<div class="aje-model" title="' + esc(modelText(e)) + '">' + esc(modelText(e)) + '</div>' +
          '<div class="aje-url" title="' + esc(endpointText(manager, e)) + '">' + esc(endpointText(manager, e)) + '</div>' +
        '</div>' +
        '<div class="aje-card-meta">' +
          '<span class="aje-chip"><i class="fas fa-gauge-high"></i>并发 ' + (parseInt(e.concurrency_limit)||1) + '</span>' +
          '<span class="aje-chip"><i class="fas fa-key"></i>' + esc(keyText(e)) + '</span>' +
          (!e.id ? '<span class="aje-chip"><i class="fas fa-circle-plus"></i>未保存</span>' : '') +
          '<button type="button" class="aje-edit-btn" data-edit="' + i + '" title="编辑端点" aria-label="编辑端点"><i class="fas fa-pen"></i></button>' +
        '</div>' +
      '</div>';
    });
    manager.editor.innerHTML = h;
    updateHead(manager);
    syncManagerDirty(manager);
  }
  function applyHarnessMode(){
    var h = editHarness.value || 'claude_code';
    var fixedOpenCode = usesFixedOpenCodeEndpoint(activeManager, h);
    var openAiCompatible = h === 'codex' || h === 'pi' ||
      (h === 'opencode' && !fixedOpenCode);
    editBaseUrlWrap.style.display = fixedOpenCode ? 'none' : '';
    editBaseUrlLabel.textContent = openAiCompatible ? 'Base URL（OpenAI 兼容）' : 'Base URL（Anthropic 兼容）';
    editBaseUrl.placeholder = openAiCompatible ? 'https://.../v1' : 'https://.../anthropic';
    editModel.placeholder = '';
  }
  function openEditor(manager, index){
    activeManager = manager;
    editIndex = (typeof index === 'number') ? index : null;
    var e = editIndex === null ? defaultEndpoint() : manager.eps[editIndex];
    document.getElementById('ajeEditModalLabel').textContent =
      (editIndex === null ? '添加' : '编辑') + manager.endpointName;
    editHarness.value = e.harness || 'claude_code';
    editBaseUrl.value = e.base_url || '';
    editApiKey.value = e.api_key || '';
    editApiKey.placeholder = e.has_key ? '已配置' : '请输入 API Key';
    editModel.value = e.model || '';
    editConcurrency.value = parseInt(e.concurrency_limit) || 1;
    if (harnessPickerCtrl) harnessPickerCtrl.setValue(e.harness || 'claude_code');
    else editHarness.value = e.harness || 'claude_code';
    if (statusPickerCtrl) statusPickerCtrl.setValue(normalizeStatus(e));
    else editStatus.value = normalizeStatus(e);
    editDelete.style.display = editIndex === null ? 'none' : '';
    applyHarnessMode();
    if (modal) modal.show();
  }
  function setHint(manager, kind, text){
    manager.hint.style.color = kind === 'error' ? '#b03a2e' : (kind === 'ok' ? '#1f7a4d' : '#70757c');
    manager.hint.textContent = text || '';
  }
  function saveManager(manager){
    var payload;
    try {
      payload = manager.buildPayload(manager);
    } catch (error) {
      setHint(manager, 'error', error && error.message ? error.message : '配置不完整');
      return;
    }
    var submittedSignature = managerSignature(manager);
    setHint(manager, 'pending', '保存中…');
    manager.saveBtn.disabled = true;
    fetch(manager.saveUrl, {
      method:'POST', credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
      body:JSON.stringify(payload)
    }).then(function(response){ return response.json(); }).then(function(data){
      manager.saveBtn.disabled = false;
      if (!data.success){ setHint(manager, 'error', data.message || '保存失败'); return; }
      if (managerSignature(manager) !== submittedSignature) {
        // 请求发出后又有编辑时，只承认本次提交的旧快照，不用响应覆盖新输入，
        // 也不把后续修改错误地标为已保存。
        manager.savedSignature = submittedSignature;
        syncManagerDirty(manager);
        setHint(manager, 'ok', '已保存；还有新的修改未保存');
        return;
      }
      manager.suspendDirty = true;
      manager.eps = fromServer(manager.readEndpoints(data));
      renderManager(manager);
      if (typeof manager.afterSave === 'function') manager.afterSave(data);
      manager.savedSignature = managerSignature(manager);
      manager.suspendDirty = false;
      syncManagerDirty(manager);
      setHint(manager, 'ok', '已保存');
    }).catch(function(){
      manager.saveBtn.disabled = false;
      setHint(manager, 'error', '网络错误');
    });
  }
  function createPoolManager(config){
    var manager = {
      editor:document.getElementById(config.editorId),
      root:document.getElementById(config.rootId),
      addBtn:document.getElementById(config.addId),
      saveBtn:document.getElementById(config.saveId),
      hint:document.getElementById(config.hintId),
      countLabel:document.getElementById(config.countId),
      totalValue:document.getElementById(config.totalId),
      poolKind:config.poolKind || 'primary',
      endpointName:config.endpointName || '端点',
      saveUrl:config.saveUrl,
      eps:fromServer(config.endpoints),
      buildPayload:config.buildPayload,
      dirtyState:config.dirtyState,
      source:config.source,
      readEndpoints:config.readEndpoints,
      afterSave:config.afterSave,
      savedSignature:null,
      suspendDirty:false
    };
    if (!manager.root || !manager.editor || !manager.addBtn || !manager.saveBtn ||
        !manager.hint || typeof manager.dirtyState !== 'function') return null;
    manager.editor.addEventListener('click', function(ev){
      var btn = ev.target.closest('[data-edit]');
      if (!btn) return;
      openEditor(manager, parseInt(btn.getAttribute('data-edit'), 10));
    });
    manager.addBtn.addEventListener('click', function(){ openEditor(manager, null); });
    manager.saveBtn.addEventListener('click', function(){ saveManager(manager); });
    manager.root.addEventListener('input', function(){ syncManagerDirty(manager); });
    manager.root.addEventListener('change', function(){ syncManagerDirty(manager); });
    renderManager(manager);
    manager.savedSignature = managerSignature(manager);
    syncManagerDirty(manager);
    return manager;
  }
  if (modalEl) {
    modalEl.addEventListener('hidden.bs.modal', function(){ window.ChoicePicker.closeAll(null); });
  }
  editApply.addEventListener('click', function(){
    if (!activeManager) return;
    var h = editHarness.value || 'claude_code';
    var old = editIndex === null ? defaultEndpoint() : activeManager.eps[editIndex];
    var st = normalizeStatus({status: (statusPickerCtrl ? statusPickerCtrl.value() : editStatus.value) || 'enabled'});
    var next = {
      id: old.id || null,
      harness: h,
      base_url: usesFixedOpenCodeEndpoint(activeManager, h) ? '' : (editBaseUrl.value || '').trim(),
      model: (editModel.value || '').trim(),
      concurrency_limit: Math.max(1, parseInt(editConcurrency.value, 10) || 1),
      status: st,
      enabled: st === 'enabled',
      has_key: !!old.has_key || !!(editApiKey.value || '').trim(),
      api_key: (editApiKey.value || '').trim()
    };
    if (editIndex === null) activeManager.eps.push(next);
    else activeManager.eps[editIndex] = next;
    renderManager(activeManager);
    if (modal) modal.hide();
  });
  editDelete.addEventListener('click', function(){
    if (!activeManager || editIndex === null) return;
    activeManager.eps.splice(editIndex, 1);
    renderManager(activeManager);
    if (modal) modal.hide();
  });
  harnessPickerCtrl = createChoicePicker({
    inputId:'ajeEditHarness', pickerId:'ajeHarnessPicker', triggerId:'ajeHarnessTrigger',
    menuId:'ajeHarnessMenu', labelId:'ajeHarnessLabel', iconId:'ajeHarnessIcon',
    onChange:function(){ applyHarnessMode(); }
  });
  statusPickerCtrl = createChoicePicker({
    inputId:'ajeEditStatus', pickerId:'ajeStatusPicker', triggerId:'ajeStatusTrigger',
    menuId:'ajeStatusMenu', labelId:'ajeStatusLabel', iconId:'ajeStatusIcon'
  });
  orchPickerCtrl = createChoicePicker({
    inputId:'ajeOrchestrationMode', pickerId:'ajeOrchestrationPicker', triggerId:'ajeOrchestrationTrigger',
    menuId:'ajeOrchestrationMenu', labelId:'ajeOrchestrationLabel', iconId:'ajeOrchestrationIcon',
    onChange:function(){ if (primaryManager) syncManagerDirty(primaryManager); }
  });
  var primaryManager = createPoolManager({
    rootId:'agentJudgeConfigCard', source:'primary-endpoints',
    editorId:'ajeEditor', addId:'ajeAddBtn', saveId:'ajeSaveBtn', hintId:'ajeHint',
    countId:'ajeCountLabel', totalId:'ajeTotalValue', endpointName:'端点',
    poolKind:'primary',
    endpoints:window.__AJ_ENDPOINTS__, saveUrl:window.__SAVE_AJ_ENDPOINTS_URL__,
    readEndpoints:function(data){ return data.endpoints || []; },
    dirtyState:function(manager){
      var orchEl = document.getElementById('ajeOrchestrationMode');
      var orchMode = orchPickerCtrl ? orchPickerCtrl.value() : (orchEl ? (orchEl.value || 'single') : 'single');
      var finalizeInput = document.getElementById('reverseFinalizeTimeout');
      var modeInput = document.getElementById('scoringModeSelect');
      var answerTimeout = document.getElementById('ajeTimeout');
      var state = {
        timeout_seconds:clampNumber(answerTimeout ? answerTimeout.value : 1800, 60, 7200, 1800),
        endpoints:endpointDirtyState(manager)
      };
      if (finalizeInput && modeInput && modeInput.value === 'reverse_judge') {
        state.reverse_judge_finalize_timeout_seconds =
          clampNumber(finalizeInput.value, 30, 7200, 180);
      }
      if (orchEl || orchPickerCtrl) state.orchestration_mode = orchMode;
      return state;
    },
    buildPayload:function(manager){
    var orchEl = document.getElementById('ajeOrchestrationMode');
    var orchMode = orchPickerCtrl ? orchPickerCtrl.value() : (orchEl ? (orchEl.value || 'single') : 'single');
    var finalizeInput = document.getElementById('reverseFinalizeTimeout');
    var modeInput = document.getElementById('scoringModeSelect');
    var answerTimeout = document.getElementById('ajeTimeout');
    var payload = { timeout_seconds: clampNumber(answerTimeout ? answerTimeout.value : 1800, 60, 7200, 1800),
      endpoints:endpointPayload(manager) };
    if (finalizeInput && modeInput && modeInput.value === 'reverse_judge') {
      payload.reverse_judge_finalize_timeout_seconds = clampNumber(finalizeInput.value, 30, 7200, 180);
    }
    if (orchEl || orchPickerCtrl) {
      payload.orchestration_mode = orchMode;
      payload.agent_judge_orchestration_mode = orchMode;
    }
    return payload;
    },
    afterSave:function(data){
      var finalizeInput = document.getElementById('reverseFinalizeTimeout');
      if (orchPickerCtrl && data.orchestration_mode) orchPickerCtrl.setValue(data.orchestration_mode);
      if (finalizeInput && data.reverse_judge_finalize_timeout_seconds) {
        finalizeInput.value = data.reverse_judge_finalize_timeout_seconds;
      }
    }
  });
  var qualityEnabled = document.getElementById('qgeEnabled');
  var qualityPrompt = document.getElementById('qgePrompt');
  var qualityManager = createPoolManager({
    rootId:'qualityGateConfigCard', source:'quality-gate',
    editorId:'qgeEditor', addId:'qgeAddBtn', saveId:'qgeSaveBtn', hintId:'qgeHint',
    countId:'qgeCountLabel', totalId:'qgeTotalValue', endpointName:'质量门禁端点',
    poolKind:'quality_gate',
    endpoints:window.__QUALITY_GATE_ENDPOINTS__, saveUrl:window.__SAVE_QUALITY_GATE_URL__,
    readEndpoints:function(data){ return data.quality_gate_endpoints || data.endpoints || []; },
    dirtyState:function(manager){
      return {
        enabled:!!(qualityEnabled && qualityEnabled.checked),
        prompt:qualityPrompt ? qualityPrompt.value.trim() : '',
        endpoints:endpointDirtyState(manager)
      };
    },
    buildPayload:function(manager){
      var enabled = !!(qualityEnabled && qualityEnabled.checked);
      var prompt = qualityPrompt ? qualityPrompt.value.trim() : '';
      if (enabled && !prompt) throw new Error('请填写审核标准');
      if (enabled && !manager.eps.some(isEnabled)) throw new Error('请配置至少一个启用端点');
      return {enabled:enabled, prompt:prompt, endpoints:endpointPayload(manager)};
    },
    afterSave:function(data){
      if (qualityEnabled) qualityEnabled.checked = !!data.enabled;
      if (qualityPrompt && typeof data.prompt === 'string') qualityPrompt.value = data.prompt;
    }
  });
  void primaryManager;
  void qualityManager;
})();
