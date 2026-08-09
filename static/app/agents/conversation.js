(function (global) {
  'use strict';

  var root = document.querySelector('[data-agent-session]');
  if (!root) return;

  var sessionId = String(root.dataset.sessionId || '');
  var currentTaskId = String(root.dataset.currentTaskId || '');
  var running = root.dataset.running === 'true';
  var legacySession = root.dataset.legacy === 'true';
  var canResume = root.dataset.canResume === 'true';
  var retryAvailable = root.dataset.canRetry === 'true';
  var nativeSessionId = asText(root.dataset.nativeSessionId).trim();
  var liveGeneration = 0;
  var stream = null;
  var pollingTimer = null;
  var workspaceTimer = null;
  var currentState = readJson('[data-agent-current-state-json]', {});
  var blocked = root.dataset.blocked === 'true'
    || isBlockedStatus(currentState && currentState.status);

  var conversationScroll = root.querySelector('[data-agent-conversation-scroll]');
  var turnsRoot = root.querySelector('[data-agent-turns]');
  var liveTurn = root.querySelector('[data-agent-live-turn]');
  var liveDetails = root.querySelector('[data-agent-live-details]');
  var liveTrace = root.querySelector('[data-agent-live-trace]');
  var liveConclusion = root.querySelector('[data-agent-live-conclusion]');
  var liveSummary = root.querySelector('[data-agent-live-summary]');
  var liveMark = root.querySelector('[data-agent-live-mark]');
  var statusChip = root.querySelector('[data-agent-status-chip]');
  var statusLabel = root.querySelector('[data-agent-status-label]');
  var sessionTitle = root.querySelector('[data-agent-session-title]');
  var usageInput = root.querySelector('[data-agent-usage-input]');
  var usageCached = root.querySelector('[data-agent-usage-cached]');
  var usageOutput = root.querySelector('[data-agent-usage-output]');
  var usageCost = root.querySelector('[data-agent-usage-cost]');
  var resumeForm = root.querySelector('[data-agent-resume-form]');
  var resumeMessage = root.querySelector('[data-agent-resume-message]');
  var resumeFile = root.querySelector('[data-agent-resume-file]');
  var resumeAttachments = root.querySelector('[data-agent-resume-attachments]');
  var resumeSend = root.querySelector('[data-agent-resume-send]');
  var stopButton = root.querySelector('[data-agent-stop]');
  var resumeFeedback = root.querySelector('[data-agent-resume-feedback]');
  var workspacePane = root.querySelector('[data-agent-workspace]');
  var workspaceTree = root.querySelector('[data-agent-workspace-tree]');
  var workspaceSync = root.querySelector('[data-agent-workspace-sync]');
  var filePane = root.querySelector('[data-agent-file-pane]');
  var fileSurface = root.querySelector('[data-agent-file-surface]');
  var fileName = root.querySelector('[data-agent-file-name]');
  var fileIcon = root.querySelector('[data-agent-file-icon]');
  var fileDownload = root.querySelector('[data-agent-file-download]');
  var conversationSplitter = root.querySelector('[data-agent-splitter="conversation"]');
  var workspaceSplitter = root.querySelector('[data-agent-splitter="workspace"]');

  var resumeFiles = [];
  var resumePending = false;
  var stopPending = false;
  var traceSignature = '';
  var treeSignature = '';
  var workspaceFetchGeneration = 0;
  var fileFetchGeneration = 0;
  var selectedPath = '';
  var fileAbortController = null;
  var monacoEditor = null;
  var monacoModel = null;
  var monacoSemanticProviders = Object.create(null);
  var modelDocumentIds = new WeakMap();
  var imageCleanup = null;
  var filePreviewReturnFocus = null;

  var STATUS = {
    pending: {label: '等待中', className: 'pending'},
    running: {label: '运行中', className: 'running'},
    completed: {label: '已完成', className: 'completed'},
    failed: {label: '失败', className: 'failed'},
    canceled: {label: '已停止', className: 'canceled'},
    cancelled: {label: '已停止', className: 'cancelled'},
    cleanupfailed: {label: '清理失败，需管理员处理', className: 'cleanupfailed'},
    cleanup_failed: {label: '清理失败，需管理员处理', className: 'cleanupfailed'}
  };

  function asText(value) {
    return value == null ? '' : String(value);
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

  function statusKey(value) {
    return asText(value || 'completed').trim().toLowerCase();
  }

  function isRunningStatus(value) {
    var key = statusKey(value);
    return key === 'pending' || key === 'running';
  }

  function isBlockedStatus(value) {
    var key = statusKey(value);
    return key === 'cleanupfailed' || key === 'cleanup_failed';
  }

  function isFinishedState(state) {
    return !!state && !isRunningStatus(state.status);
  }

  function paintSessionAvatars() {
    var identicon = global.NumojIdenticon;
    if (!identicon) return;
    root.querySelectorAll('[data-agent-session-avatar]').forEach(function (avatar) {
      var seed = avatar.getAttribute('data-avatar-seed') || 'numericaloj';
      var label = avatar.getAttribute('data-avatar-label') || seed;
      identicon.paint(avatar, identicon.cellsForSeed(seed), label);
    });
  }

  function formatMeasuredValue(value) {
    if (!Number.isFinite(value) || value < 0) return '—';
    if (value === 0) return '0.00';
    return value >= 1 ? value.toFixed(2) : value.toPrecision(2);
  }

  function formatTokenCount(tokens) {
    if (!Number.isFinite(tokens) || tokens < 0) return '—';
    if (tokens < 10000) return formatMeasuredValue(tokens / 1000) + ' K';
    return formatMeasuredValue(tokens / 1000000) + ' M';
  }

  function setUsageValue(element, value) {
    if (element && element.textContent !== value) element.textContent = value;
  }

  function renderHeaderTokenUsage(usage) {
    usage = usage && typeof usage === 'object' ? usage : null;
    if (!usage) {
      [usageInput, usageCached, usageOutput, usageCost].forEach(function (element) {
        setUsageValue(element, '—');
      });
      return;
    }

    var inputTokens = Number(usage.input_total_tokens);
    var cachedTokens = Number(usage.input_cached_tokens);
    var outputTokens = Number(usage.output_tokens);
    var cachedPercent = inputTokens > 0 && cachedTokens >= 0
      ? Math.min(100, cachedTokens / inputTokens * 100)
      : 0;
    setUsageValue(usageInput, formatTokenCount(inputTokens));
    setUsageValue(usageCached, cachedPercent.toFixed(2) + '%');
    setUsageValue(usageOutput, formatTokenCount(outputTokens));

    var hasCost = usage.cost_rmb !== null
      && usage.cost_rmb !== undefined
      && usage.cost_rmb !== ''
      && Number.isFinite(Number(usage.cost_rmb))
      && Number(usage.cost_rmb) >= 0;
    setUsageValue(
      usageCost,
      hasCost ? formatMeasuredValue(Number(usage.cost_rmb)) + ' RMB' : '—'
    );
  }

  function taskUrl(template, taskId) {
    return asText(template).split('__TASK_ID__').join(encodeURIComponent(taskId));
  }

  function queryUrl(base, values) {
    var url = new URL(base, global.location.origin);
    Object.keys(values || {}).forEach(function (key) {
      var value = values[key];
      if (value !== null && value !== undefined && value !== '') {
        url.searchParams.set(key, String(value));
      }
    });
    return url.toString();
  }

  function createElement(tag, className, text) {
    var element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }

  function setServerHtml(element, html) {
    if (!element) return;
    if (global.NumericalOJMarkdownRenderer) {
      global.NumericalOJMarkdownRenderer.clear(element);
    }
    element.innerHTML = asText(html);
    element.setAttribute('data-numoj-markdown', '');
    element.classList.add('numoj-markdown');
    if (global.NumericalOJMarkdownRenderer) {
      global.NumericalOJMarkdownRenderer.enhance(element);
    } else if (global.MathJax && typeof global.MathJax.typesetPromise === 'function') {
      global.MathJax.typesetPromise([element]).catch(function () {});
    }
  }

  function enhanceMarkdown(scope) {
    if (global.NumericalOJMarkdownRenderer) {
      global.NumericalOJMarkdownRenderer.enhanceAll(scope || root);
    }
  }

  function mathLoader(label, size) {
    var holder = createElement('div', 'agent-working-placeholder');
    if (global.MathCurveLoader && typeof global.MathCurveLoader.markup === 'function') {
      holder.innerHTML = global.MathCurveLoader.markup(label, size || 'sm');
      global.MathCurveLoader.hydrate(holder);
    } else {
      holder.textContent = label;
    }
    return holder;
  }

  function scrollToLatest(behavior) {
    if (!conversationScroll) return;
    global.requestAnimationFrame(function () {
      conversationScroll.scrollTo({
        top: conversationScroll.scrollHeight,
        behavior: behavior || 'auto'
      });
    });
  }

  function setResumeFeedback(message, isError) {
    if (!resumeFeedback) return;
    resumeFeedback.textContent = message || '';
    resumeFeedback.hidden = !message;
    resumeFeedback.classList.toggle('is-error', isError === true);
  }

  function setStatus(value) {
    var key = statusKey(value);
    var item = STATUS[key] || {label: asText(value || '状态未知'), className: key || 'completed'};
    if (statusLabel) statusLabel.textContent = item.label;
    if (statusChip) {
      Array.prototype.slice.call(statusChip.classList).forEach(function (className) {
        if (className.indexOf('agent-status-chip--') === 0) statusChip.classList.remove(className);
      });
      statusChip.classList.add('agent-status-chip--' + item.className);
      statusChip.setAttribute('aria-label', item.label);
    }
  }

  function updateSendState() {
    if (!resumeSend || !resumeMessage) return;
    resumeSend.disabled = running || blocked || resumePending || !resumeMessage.value.trim();
  }

  function updateRetryState() {
    var retryBlocked = legacySession || !canResume
      || isBlockedStatus(currentState && currentState.status);
    root.querySelectorAll('[data-agent-retry-last]').forEach(function (button) {
      var expectedTaskId = asText(button.dataset.agentExpectedTaskId).trim();
      var available = retryAvailable && expectedTaskId === currentTaskId
        && !running && !retryBlocked;
      button.hidden = !available;
      button.disabled = !available || resumePending;
    });
  }

  function setRunning(value, stateStatus, nextNativeSessionId) {
    running = value === true;
    var discoveredNativeSessionId = asText(nextNativeSessionId).trim();
    if (discoveredNativeSessionId) {
      nativeSessionId = discoveredNativeSessionId;
      root.dataset.nativeSessionId = nativeSessionId;
    }
    if (stateStatus) {
      blocked = isBlockedStatus(stateStatus)
        || !canResume
        || legacySession
        || (!running && !nativeSessionId);
    }
    root.dataset.running = running ? 'true' : 'false';
    root.dataset.blocked = blocked ? 'true' : 'false';
    if (resumeForm) resumeForm.classList.toggle('is-running', running);
    if (resumeForm) resumeForm.classList.toggle('is-blocked', blocked);
    if (resumeMessage) resumeMessage.disabled = running || blocked || resumePending;
    if (resumeFile) resumeFile.disabled = running || blocked || resumePending;
    if (stopButton) stopButton.hidden = !running;
    if (liveMark) liveMark.hidden = !running;
    if (stateStatus) setStatus(stateStatus);
    updateSendState();
    updateRetryState();
  }

  function traceMessages(state) {
    var trace = state && state.execution_trace && typeof state.execution_trace === 'object'
      ? state.execution_trace : (state && state.trace && typeof state.trace === 'object' ? state.trace : {});
    var messages = trace.trace_messages || trace.messages || (state && state.messages) || [];
    return Array.isArray(messages) ? messages : [];
  }

  function messageKind(message) {
    return statusKey(message && (message.kind || message.type) || 'assistant');
  }

  function isRichTraceKind(kind) {
    return kind === 'assistant' || kind === 'thinking' || kind === 'reasoning';
  }

  function traceEvent(message) {
    var kind = messageKind(message);
    var resultKind = kind === 'tool_result' || kind === 'tool-result';
    var resultError = resultKind && message && message.is_error === true;
    var visualKind = resultKind ? (resultError ? 'error' : 'result') : kind.replace(/_/g, '-');
    var row = createElement('section', 'agent-trace-event agent-trace-event--' + visualKind);
    var icon = createElement('span', 'agent-trace-event-icon');
    var iconClass = 'fas fa-comment-alt';
    if (kind === 'thinking' || kind === 'reasoning') iconClass = 'fas fa-circle-notch';
    else if (kind === 'tool' || kind === 'tool_call') iconClass = 'fas fa-terminal';
    else if (resultKind) iconClass = resultError ? 'fas fa-exclamation-triangle' : 'fas fa-check';
    else if (kind === 'subagent') iconClass = 'fas fa-code-branch';
    var glyph = createElement('i', iconClass);
    glyph.setAttribute('aria-hidden', 'true');
    icon.appendChild(glyph);

    var body = createElement('div');
    var title = '';
    if (kind === 'thinking' || kind === 'reasoning') title = '思考';
    else if (kind === 'tool' || kind === 'tool_call') title = asText(message.title || message.name || message.tool_name || '工具调用');
    else if (resultKind) title = asText(message.title || (resultError ? '工具执行失败' : '工具结果'));
    else if (kind === 'subagent') title = asText(message.title || message.name || '子 Agent');
    if (title) body.appendChild(createElement('strong', '', title));

    var html = message && message.html;
    var content = asText(message && (
      message.text != null ? message.text
        : message.content != null ? message.content
          : message.input != null ? message.input
            : message.output
    ));
    if (html && isRichTraceKind(kind)) {
      var copy = createElement('div', 'agent-trace-copy numoj-markdown');
      setServerHtml(copy, html);
      body.appendChild(copy);
    } else if (kind === 'assistant') {
      body.appendChild(createElement('div', 'agent-trace-copy', content));
    } else {
      body.appendChild(createElement('pre', '', content));
    }
    row.append(icon, body);
    return row;
  }

  function renderTrace(state) {
    if (!liveTrace) return;
    var messages = traceMessages(state);
    var signature = JSON.stringify(messages.map(function (message) {
      return [message.kind, message.type, message.title, message.name, message.is_error, message.text, message.content, message.html];
    }));
    if (signature === traceSignature) return;
    traceSignature = signature;
    liveTrace.replaceChildren();
    if (!messages.length && isRunningStatus(state && state.status)) {
      liveTrace.appendChild(mathLoader('Agent 正在工作', 'sm'));
      return;
    }
    if (!messages.length) {
      liveTrace.appendChild(createElement('div', 'agent-workspace-empty', '本轮没有可展示的工作详情。'));
      return;
    }
    messages.forEach(function (message) {
      liveTrace.appendChild(traceEvent(message || {}));
    });
    enhanceMarkdown(liveTrace);
  }

  function conclusionFromState(state) {
    var trace = state && state.execution_trace && typeof state.execution_trace === 'object'
      ? state.execution_trace : {};
    var html = state && (state.conclusion_html || state.final_response_html)
      || trace.conclusion_html || trace.final_response_html;
    if (html) return {html: asText(html), text: ''};
    var text = state && (state.conclusion || state.final_response)
      || trace.conclusion || trace.final_response;
    if (text) return {html: '', text: asText(text)};
    var messages = traceMessages(state).filter(function (message) {
      return messageKind(message) === 'assistant';
    });
    var last = messages[messages.length - 1];
    return last ? {html: asText(last.html), text: asText(last.text || last.content)} : null;
  }

  function renderConclusionInto(element, state) {
    if (!element) return;
    var conclusion = conclusionFromState(state);
    element.hidden = false;
    if (conclusion && conclusion.html) {
      setServerHtml(element, conclusion.html);
    } else {
      if (global.NumericalOJMarkdownRenderer) {
        global.NumericalOJMarkdownRenderer.clear(element);
      }
      element.replaceChildren();
      var text = conclusion && conclusion.text;
      element.appendChild(createElement(
        'p', '', text || (statusKey(state && state.status) === 'completed'
          ? '任务已完成。' : asText(state && state.message || '任务已结束。'))
      ));
    }
  }

  function renderConclusion(state) {
    renderConclusionInto(liveConclusion, state);
  }

  function historicalResponse(state) {
    var response = createElement('section', 'agent-response');
    var messages = traceMessages(state);
    if (messages.length) {
      var details = createElement('details', 'agent-turn-details');
      var summary = document.createElement('summary');
      var summaryLabel = createElement('span');
      var caret = createElement('i', 'fas fa-chevron-right');
      caret.setAttribute('aria-hidden', 'true');
      summaryLabel.append(caret, document.createTextNode('工作详情'));
      summary.appendChild(summaryLabel);
      var trace = createElement('div', 'agent-turn-trace');
      messages.forEach(function (message) {
        trace.appendChild(traceEvent(message || {}));
      });
      details.append(summary, trace);
      response.appendChild(details);
    }
    var conclusion = createElement('div', 'agent-conclusion numoj-markdown');
    conclusion.setAttribute('data-numoj-markdown', '');
    renderConclusionInto(conclusion, state);
    response.appendChild(conclusion);
    return response;
  }

  function directResponse(turn) {
    if (!turn) return null;
    for (var index = 0; index < turn.children.length; index += 1) {
      var child = turn.children[index];
      if (child.classList && child.classList.contains('agent-response')) return child;
    }
    return null;
  }

  function archiveLiveResponse() {
    if (!turnsRoot || !liveTurn || !currentState || isRunningStatus(currentState.status)) {
      return false;
    }
    var target = null;
    for (var index = turnsRoot.children.length - 1; index >= 0; index -= 1) {
      var candidate = turnsRoot.children[index];
      if (candidate === liveTurn || !candidate.classList.contains('agent-turn')) continue;
      target = candidate;
      break;
    }
    if (!target || directResponse(target)) return false;
    target.appendChild(historicalResponse(currentState));
    target.dataset.agentResponseArchived = 'true';
    liveTurn.hidden = true;
    enhanceMarkdown(target);
    return true;
  }

  function resetLiveResponse() {
    traceSignature = '';
    if (liveTrace) liveTrace.replaceChildren(mathLoader('Agent 正在工作', 'sm'));
    if (liveConclusion) {
      if (global.NumericalOJMarkdownRenderer) {
        global.NumericalOJMarkdownRenderer.clear(liveConclusion);
      }
      liveConclusion.replaceChildren();
      liveConclusion.hidden = true;
    }
    if (liveDetails) liveDetails.open = true;
    if (liveSummary) liveSummary.textContent = 'Agent 正在工作';
    if (liveTurn) liveTurn.hidden = false;
  }

  function isCurrent(taskId, generation, activeStream) {
    if (taskId !== currentTaskId || generation !== liveGeneration) return false;
    return !activeStream || stream === activeStream;
  }

  function applyState(state, expectedTaskId, generation) {
    if (!state || typeof state !== 'object') return;
    if (expectedTaskId && !isCurrent(expectedTaskId, generation)) return;
    currentState = state;
    var nextTitle = asText(state.title).trim();
    if (nextTitle && sessionTitle) {
      sessionTitle.textContent = nextTitle;
      sessionTitle.title = nextTitle;
    }
    renderHeaderTokenUsage(state.session_token_usage);
    var stateIsRunning = isRunningStatus(state.status);
    setRunning(stateIsRunning, state.status, state.native_session_id);
    if (liveTurn) liveTurn.hidden = false;
    if (liveSummary) liveSummary.textContent = stateIsRunning ? 'Agent 正在工作' : '工作详情';
    renderTrace(state);
    if (stateIsRunning) {
      if (liveDetails) liveDetails.open = true;
      if (liveConclusion) liveConclusion.hidden = true;
    } else {
      if (liveDetails) liveDetails.open = false;
      renderConclusion(state);
      stopLiveUpdates();
    }
    scheduleWorkspaceRefresh(stateIsRunning ? 1800 : 0);
  }

  function stopLiveUpdates() {
    if (stream) {
      stream.close();
      stream = null;
    }
    if (pollingTimer) {
      global.clearTimeout(pollingTimer);
      pollingTimer = null;
    }
  }

  function fetchState(taskId, generation) {
    return global.fetch(taskUrl(root.dataset.statusUrlTemplate, taskId), {
      headers: {'Accept': 'application/json'},
      credentials: 'same-origin',
      cache: 'no-store',
      mathCurveLoader: false
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (payload) {
        if (!response.ok || !payload || !payload.state) {
          throw new Error(asText(payload && payload.message) || '无法读取任务状态');
        }
        return payload.state;
      });
    }).then(function (state) {
      applyState(state, taskId, generation);
      return state;
    });
  }

  function startPolling(taskId, generation) {
    if (!isCurrent(taskId, generation)) return;
    fetchState(taskId, generation).then(function (state) {
      if (!isCurrent(taskId, generation) || isFinishedState(state)) return;
      pollingTimer = global.setTimeout(function () { startPolling(taskId, generation); }, 2200);
    }).catch(function () {
      if (!isCurrent(taskId, generation)) return;
      pollingTimer = global.setTimeout(function () { startPolling(taskId, generation); }, 3200);
    });
  }

  function parseStreamState(event, taskId, generation) {
    try {
      applyState(JSON.parse(event.data), taskId, generation);
    } catch (_error) {
      setResumeFeedback('实时状态数据异常，正在重试。', true);
    }
  }

  function startStream(taskId) {
    taskId = asText(taskId).trim();
    if (!taskId) return;
    currentTaskId = taskId;
    root.dataset.currentTaskId = taskId;
    liveGeneration += 1;
    var generation = liveGeneration;
    stopLiveUpdates();
    setRunning(true, 'running');
    if (liveTurn) liveTurn.hidden = false;
    if (liveDetails) liveDetails.open = true;
    if (liveConclusion) liveConclusion.hidden = true;
    if (liveSummary) liveSummary.textContent = 'Agent 正在工作';
    if (!global.EventSource) {
      startPolling(taskId, generation);
      return;
    }
    var activeStream = new global.EventSource(taskUrl(root.dataset.streamUrlTemplate, taskId));
    stream = activeStream;
    activeStream.addEventListener('status', function (event) {
      if (!isCurrent(taskId, generation, activeStream)) return;
      parseStreamState(event, taskId, generation);
    });
    activeStream.addEventListener('done', function (event) {
      if (!isCurrent(taskId, generation, activeStream)) return;
      parseStreamState(event, taskId, generation);
      activeStream.close();
      if (stream === activeStream) stream = null;
    });
    activeStream.addEventListener('error', function () {
      if (!isCurrent(taskId, generation, activeStream)) return;
      if (activeStream.readyState === global.EventSource.CLOSED) {
        activeStream.close();
        if (stream === activeStream) stream = null;
        startPolling(taskId, generation);
      }
    });
  }

  function createRetryButton(taskId) {
    var button = createElement('button', 'agent-message-retry');
    button.type = 'button';
    button.dataset.agentRetryLast = '';
    button.dataset.agentExpectedTaskId = asText(taskId).trim();
    button.title = '重试';
    button.setAttribute('aria-label', '重试上一条消息');
    button.innerHTML = '<i class="fas fa-redo-alt" aria-hidden="true"></i>';
    return button;
  }

  function appendOptimisticUserMessage(
    message, files, messageHtml, savedAttachments, taskId
  ) {
    if (!turnsRoot) return;
    var turn = createElement('article', 'agent-turn');
    turn.setAttribute('data-agent-turn', '');
    turn.dataset.agentTaskId = asText(taskId).trim();
    var user = createElement('section', 'agent-user-message');
    var messageRow = createElement('div', 'agent-user-message-row');
    var bubble = createElement('div', 'agent-user-bubble');
    if (messageHtml) setServerHtml(bubble, messageHtml);
    else bubble.textContent = message;
    messageRow.append(createRetryButton(taskId), bubble);
    user.appendChild(messageRow);
    var attachmentItems = Array.isArray(savedAttachments) && savedAttachments.length
      ? savedAttachments : files;
    if (attachmentItems.length) {
      var attachments = createElement('div', 'agent-message-attachments');
      attachmentItems.forEach(function (file) {
        var path = asText(file.path || file.workspace_path);
        var name = asText(file.name || file.filename) || path.split('/').pop() || '附件';
        var item = createElement('span', 'agent-message-attachment');
        var icon = createElement('i', 'fas fa-paperclip');
        icon.setAttribute('aria-hidden', 'true');
        item.appendChild(icon);
        if (path) {
          var preview = createElement('button', '', name);
          preview.type = 'button';
          preview.dataset.agentOpenFile = path;
          item.appendChild(preview);
          var download = createElement('a');
          download.href = downloadFileUrl(path);
          download.download = name;
          download.title = '下载 ' + name;
          download.innerHTML = '<i class="fas fa-download" aria-hidden="true"></i>';
          item.appendChild(download);
        } else {
          item.appendChild(createElement('span', '', name));
        }
        attachments.appendChild(item);
      });
      user.appendChild(attachments);
    }
    turn.appendChild(user);
    if (liveTurn) turnsRoot.insertBefore(turn, liveTurn);
    else turnsRoot.appendChild(turn);
    updateRetryState();
  }

  function renderResumeFiles() {
    if (!resumeAttachments) return;
    resumeAttachments.replaceChildren();
    resumeAttachments.hidden = resumeFiles.length === 0;
    resumeFiles.forEach(function (file, index) {
      var chip = createElement('span', 'agent-resume-file-chip');
      var icon = createElement('i', file.type.indexOf('image/') === 0 ? 'fas fa-image' : 'fas fa-paperclip');
      icon.setAttribute('aria-hidden', 'true');
      var name = createElement('span', '', file.name);
      name.title = file.name;
      var remove = createElement('button');
      remove.type = 'button';
      remove.setAttribute('aria-label', '移除附件 ' + file.name);
      remove.innerHTML = '<i class="fas fa-times" aria-hidden="true"></i>';
      remove.addEventListener('click', function () {
        resumeFiles.splice(index, 1);
        renderResumeFiles();
      });
      chip.append(icon, name, remove);
      resumeAttachments.appendChild(chip);
    });
  }

  function addResumeFiles(fileList) {
    var keys = new Set(resumeFiles.map(function (file) {
      return [file.name, file.size, file.lastModified].join(':');
    }));
    Array.prototype.forEach.call(fileList || [], function (file) {
      var key = [file.name, file.size, file.lastModified].join(':');
      if (!file || keys.has(key)) return;
      keys.add(key);
      resumeFiles.push(file);
    });
    renderResumeFiles();
  }

  function resizeResumeMessage() {
    if (!resumeMessage) return;
    resumeMessage.style.height = 'auto';
    resumeMessage.style.height = Math.min(180, Math.max(48, resumeMessage.scrollHeight)) + 'px';
  }

  function setResumePending(value) {
    resumePending = value === true;
    if (resumeForm) resumeForm.classList.toggle('is-submitting', resumePending);
    if (resumeMessage) resumeMessage.disabled = running || blocked || resumePending;
    if (resumeFile) resumeFile.disabled = running || blocked || resumePending;
    if (resumeSend) {
      resumeSend.innerHTML = resumePending
        ? '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>'
        : '<i class="fas fa-arrow-up" aria-hidden="true"></i>';
    }
    updateSendState();
    updateRetryState();
  }

  function removeTurnByTaskId(taskId) {
    if (!turnsRoot || !taskId) return;
    Array.prototype.slice.call(turnsRoot.querySelectorAll('[data-agent-turn]'))
      .forEach(function (turn) {
        if (asText(turn.dataset.agentTaskId).trim() === taskId) turn.remove();
      });
  }

  function dispatchAgentTurn(options) {
    var retrying = options.retrying === true;
    setResumeFeedback('', false);
    setResumePending(true);
    global.fetch(resumeForm.action, {
      method: 'POST',
      body: options.body,
      headers: {'Accept': 'application/json'},
      credentials: 'same-origin',
      mathCurveLoader: false
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (payload) {
        if (!response.ok || !payload || payload.success === false) {
          var error = new Error(
            asText(payload && payload.message) || '发送失败（HTTP ' + response.status + '）'
          );
          error.detailUrl = asText(payload && payload.detail_url).trim();
          throw error;
        }
        return payload;
      });
    }).then(function (payload) {
      if (payload.detail_url) {
        global.location.assign(payload.detail_url);
        return;
      }
      var taskId = asText(payload.task_id || payload.current_task_id).trim();
      if (!taskId) {
        global.location.reload();
        return;
      }
      archiveLiveResponse();
      if (retrying) {
        removeTurnByTaskId(
          asText(payload.replaced_task_id || options.expectedTaskId).trim()
        );
      }
      retryAvailable = true;
      root.dataset.canRetry = 'true';
      appendOptimisticUserMessage(
        asText(payload.user_message || options.message),
        options.files || [],
        payload.user_message_html,
        payload.attachments,
        taskId
      );
      if (!retrying) {
        resumeMessage.value = '';
        resumeFiles = [];
        renderResumeFiles();
        resizeResumeMessage();
      }
      setResumePending(false);
      resetLiveResponse();
      startStream(taskId);
      if (payload.state) applyState(payload.state, taskId, liveGeneration);
      scrollToLatest('smooth');
    }).catch(function (error) {
      setResumePending(false);
      if (error && error.detailUrl) {
        global.location.assign(error.detailUrl);
        return;
      }
      setResumeFeedback(
        error && error.message ? error.message : '发送失败，请稍后重试。',
        true
      );
    });
  }

  function bindResumeComposer() {
    if (!resumeForm || !resumeMessage || !resumeFile) return;
    resumeMessage.addEventListener('input', function () {
      resizeResumeMessage();
      updateSendState();
      if (resumeMessage.value.trim()) setResumeFeedback('', false);
    });
    resumeMessage.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && (event.metaKey || event.ctrlKey) && !resumeSend.disabled) {
        event.preventDefault();
        resumeForm.requestSubmit(resumeSend);
      }
    });
    resumeFile.addEventListener('change', function () {
      addResumeFiles(resumeFile.files);
      resumeFile.value = '';
    });

    ['dragenter', 'dragover'].forEach(function (eventName) {
      resumeForm.addEventListener(eventName, function (event) {
        if (running || blocked || !event.dataTransfer || Array.prototype.indexOf.call(event.dataTransfer.types, 'Files') < 0) return;
        event.preventDefault();
        event.dataTransfer.dropEffect = 'copy';
        resumeForm.classList.add('is-dragging');
      });
    });
    ['dragleave', 'drop'].forEach(function (eventName) {
      resumeForm.addEventListener(eventName, function (event) {
        if (eventName === 'drop') event.preventDefault();
        resumeForm.classList.remove('is-dragging');
      });
    });
    resumeForm.addEventListener('drop', function (event) {
      if (!running && !blocked && event.dataTransfer) addResumeFiles(event.dataTransfer.files);
    });

    resumeForm.addEventListener('submit', function (event) {
      event.preventDefault();
      if (running || blocked || resumePending || !resumeMessage.value.trim()) return;
      var message = resumeMessage.value.trim();
      var submittedFiles = resumeFiles.slice();
      var body = new FormData(resumeForm);
      body.delete(resumeFile.name);
      submittedFiles.forEach(function (file) {
        body.append(resumeFile.name, file, file.name);
      });
      dispatchAgentTurn({
        body: body,
        message: message,
        files: submittedFiles,
        retrying: false
      });
    });
    resizeResumeMessage();
    updateSendState();
  }

  function bindRetryButton() {
    if (!turnsRoot || !resumeForm) return;
    turnsRoot.addEventListener('click', function (event) {
      var button = event.target.closest('[data-agent-retry-last]');
      if (!button || button.disabled || button.hidden || running || resumePending) return;
      var expectedTaskId = asText(button.dataset.agentExpectedTaskId).trim();
      if (!expectedTaskId || expectedTaskId !== currentTaskId) {
        setResumeFeedback('会话状态已变化，请刷新后重试。', true);
        return;
      }
      var body = new FormData();
      body.append('retry_last', '1');
      body.append('expected_task_id', expectedTaskId);
      dispatchAgentTurn({
        body: body,
        message: '',
        files: [],
        retrying: true,
        expectedTaskId: expectedTaskId
      });
    });
  }

  function bindStopButton() {
    if (!stopButton) return;
    stopButton.addEventListener('click', function () {
      if (!currentTaskId || !running || stopPending) return;
      stopPending = true;
      stopButton.disabled = true;
      stopButton.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span><span>停止中</span>';
      var taskId = currentTaskId;
      var generation = liveGeneration;
      global.fetch(taskUrl(root.dataset.cancelUrlTemplate, taskId), {
        method: 'POST',
        headers: {'Accept': 'application/json'},
        credentials: 'same-origin',
        mathCurveLoader: false
      }).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (payload) {
          if (!payload || !payload.state) {
            throw new Error(asText(payload && payload.message) || '停止任务失败');
          }
          return {
            state: payload.state,
            warning: response.ok && payload.success !== false ? '' : asText(payload.message)
          };
        });
      }).then(function (result) {
        stopPending = false;
        stopButton.disabled = false;
        stopButton.innerHTML = '<i class="fas fa-stop" aria-hidden="true"></i><span>停止</span>';
        applyState(result.state, taskId, generation);
        if (result.warning) setResumeFeedback(result.warning, true);
      }).catch(function (error) {
        stopPending = false;
        stopButton.disabled = false;
        stopButton.innerHTML = '<i class="fas fa-stop" aria-hidden="true"></i><span>停止</span>';
        setResumeFeedback(error && error.message ? error.message : '停止任务失败。', true);
      });
    });
  }

  function humanSize(value) {
    var bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(bytes < 10240 ? 1 : 0) + 'K';
    return (bytes / 1024 / 1024).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0) + 'M';
  }

  function nodePath(node) {
    return asText(node && (node.path || node.relative_path || node.name));
  }

  function nodeName(node) {
    var path = nodePath(node);
    return asText(node && (node.name || node.filename)) || path.split('/').pop() || path;
  }

  function nodeIsDirectory(node) {
    var type = statusKey(node && (node.type || node.kind));
    return type === 'directory' || type === 'dir' || type === 'folder' || Array.isArray(node && node.children);
  }

  function flatTree(entries) {
    var rootNode = {name: '', path: '', type: 'directory', children: []};
    var directories = {'': rootNode};
    entries.forEach(function (entry) {
      if (typeof entry === 'string') entry = {path: entry, type: 'file'};
      if (!entry || typeof entry !== 'object') return;
      var path = nodePath(entry).replace(/^\/+|\/+$/g, '');
      if (!path) return;
      var parts = path.split('/').filter(Boolean);
      var parentPath = '';
      parts.forEach(function (part, index) {
        var pathHere = parentPath ? parentPath + '/' + part : part;
        var last = index === parts.length - 1;
        var directory = !last || nodeIsDirectory(entry);
        if (directory) {
          if (!directories[pathHere]) {
            var directoryNode = {name: part, path: pathHere, type: 'directory', children: []};
            directories[parentPath].children.push(directoryNode);
            directories[pathHere] = directoryNode;
          }
        } else {
          directories[parentPath].children.push(Object.assign({}, entry, {
            name: entry.name || part,
            path: pathHere,
            type: 'file'
          }));
        }
        if (directory) parentPath = pathHere;
      });
    });
    return rootNode.children;
  }

  function treeEntries(payload) {
    var raw = Array.isArray(payload) ? payload
      : payload && (payload.tree || payload.entries || payload.files || payload.children) || [];
    if (!Array.isArray(raw)) return [];
    var nested = raw.some(function (entry) { return Array.isArray(entry && entry.children); });
    return nested ? raw : flatTree(raw);
  }

  function fileIconClass() {
    // 文件预览类型由服务端读取实际内容后决定；目录树不能仅凭扩展名误导用户。
    return 'fas fa-file';
  }

  function expandedTreePaths() {
    var paths = new Set();
    if (!workspaceTree) return paths;
    workspaceTree.querySelectorAll('details[data-tree-path][open]').forEach(function (item) {
      paths.add(item.dataset.treePath);
    });
    return paths;
  }

  function treeNode(node, depth, openPaths) {
    var path = nodePath(node);
    var name = nodeName(node);
    if (nodeIsDirectory(node)) {
      var details = createElement('details', 'agent-tree-directory');
      details.dataset.treePath = path;
      details.open = depth === 0 || openPaths.has(path);
      var summary = document.createElement('summary');
      var chevron = createElement('i', 'fas fa-chevron-right agent-tree-chevron');
      chevron.setAttribute('aria-hidden', 'true');
      var icon = createElement('i', 'fas fa-folder agent-tree-icon');
      icon.setAttribute('aria-hidden', 'true');
      summary.append(chevron, icon, createElement('span', 'agent-tree-label', name));
      var children = createElement('div', 'agent-tree-children');
      (Array.isArray(node.children) ? node.children : []).forEach(function (child) {
        children.appendChild(treeNode(child, depth + 1, openPaths));
      });
      details.append(summary, children);
      return details;
    }

    var button = createElement('button', 'agent-tree-file');
    button.type = 'button';
    button.dataset.agentOpenFile = path;
    button.title = path;
    button.classList.toggle('is-active', path === selectedPath);
    var spacer = createElement('span');
    var fileIcon = createElement('i', fileIconClass(path) + ' agent-tree-icon');
    fileIcon.setAttribute('aria-hidden', 'true');
    button.append(spacer, fileIcon, createElement('span', 'agent-tree-label', name));
    if (node.size !== undefined && node.size !== null) {
      button.appendChild(createElement('small', 'agent-tree-size', humanSize(node.size)));
    }
    return button;
  }

  function renderWorkspace(payload) {
    if (!workspaceTree) return;
    var entries = treeEntries(payload);
    var signature = JSON.stringify(entries);
    if (signature === treeSignature) return;
    treeSignature = signature;
    var openPaths = expandedTreePaths();
    workspaceTree.replaceChildren();
    if (!entries.length) {
      workspaceTree.appendChild(createElement('div', 'agent-workspace-empty', 'Workspace 还是空的。'));
      return;
    }
    entries.forEach(function (node) {
      workspaceTree.appendChild(treeNode(node, 0, openPaths));
    });
  }

  function setWorkspaceSync(state, title) {
    if (!workspaceSync) return;
    workspaceSync.classList.remove('is-syncing', 'is-error');
    var icon = workspaceSync.querySelector('i');
    if (state === 'syncing') {
      workspaceSync.classList.add('is-syncing');
      if (icon) icon.className = 'fas fa-sync-alt';
    } else if (state === 'error') {
      workspaceSync.classList.add('is-error');
      if (icon) icon.className = 'fas fa-exclamation-triangle';
    } else if (icon) {
      icon.className = 'fas fa-check';
    }
    workspaceSync.title = title || '';
  }

  function refreshWorkspace() {
    if (!workspaceTree || !root.dataset.workspaceTreeUrl) return Promise.resolve();
    var generation = ++workspaceFetchGeneration;
    setWorkspaceSync('syncing', '正在同步 Workspace');
    return global.fetch(root.dataset.workspaceTreeUrl, {
      headers: {'Accept': 'application/json'},
      credentials: 'same-origin',
      cache: 'no-store',
      mathCurveLoader: false
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (payload) {
        if (!response.ok || !payload || payload.success === false) {
          throw new Error(asText(payload && payload.message) || '无法读取 Workspace');
        }
        return payload;
      });
    }).then(function (payload) {
      if (generation !== workspaceFetchGeneration) return;
      renderWorkspace(payload);
      setWorkspaceSync('ready', 'Workspace 已同步');
    }).catch(function (error) {
      if (generation !== workspaceFetchGeneration) return;
      setWorkspaceSync('error', error.message || 'Workspace 同步失败');
      if (!treeSignature) {
        workspaceTree.replaceChildren(createElement(
          'div', 'agent-workspace-error', error.message || '无法读取 Workspace'
        ));
      }
    });
  }

  function scheduleWorkspaceRefresh(delay) {
    if (workspaceTimer) return;
    workspaceTimer = global.setTimeout(function tick() {
      workspaceTimer = null;
      refreshWorkspace().finally(function () {
        if (running) scheduleWorkspaceRefresh(2800);
      });
    }, Math.max(0, delay || 0));
  }

  function disposeFilePreview() {
    fileFetchGeneration += 1;
    if (fileAbortController) {
      fileAbortController.abort();
      fileAbortController = null;
    }
    if (imageCleanup) {
      imageCleanup();
      imageCleanup = null;
    }
    if (monacoEditor) {
      monacoEditor.dispose();
      monacoEditor = null;
    }
    if (monacoModel) {
      monacoModel.dispose();
      monacoModel = null;
    }
    if (fileSurface && global.NumericalOJMarkdownRenderer) {
      global.NumericalOJMarkdownRenderer.clear(fileSurface);
    }
  }

  function stableDocumentId(path) {
    var value = sessionId + '\u0000' + path;
    function hash(seed) {
      var result = seed >>> 0;
      for (var index = 0; index < value.length; index += 1) {
        result ^= value.charCodeAt(index);
        result = Math.imul(result, 16777619);
      }
      return (result >>> 0).toString(16).padStart(8, '0');
    }
    return 'aw-' + hash(2166136261) + '-' + hash(2246822519);
  }

  function ensureSemanticProvider(monaco, spec) {
    var supported = ['c', 'cpp', 'python', 'matlab'];
    if (!spec.language || supported.indexOf(spec.language) < 0 || !global.NumOJSemanticTokens) return;
    if (monacoSemanticProviders[spec.language]) return;
    monacoSemanticProviders[spec.language] = true;
    global.NumOJSemanticTokens.register(monaco, {
      context: 'agent-workspace',
      language: spec.language,
      monacoLanguage: spec.monacoLanguage,
      documentId: function (model) { return modelDocumentIds.get(model) || ''; }
    }).then(function (disposable) {
      monacoSemanticProviders[spec.language] = disposable || true;
    }).catch(function (error) {
      delete monacoSemanticProviders[spec.language];
      console.warn('Agent Workspace 语言服务初始化失败，已保留 TextMate 着色。', error);
    });
  }

  function encodedMonacoPath(path) {
    return path.split('/').filter(Boolean).map(function (part) {
      return encodeURIComponent(part);
    }).join('/');
  }

  async function renderCode(content, path, explicitLanguage, generation) {
    var runtime = global.NumOJCodeEditorRuntime;
    var filenameSpec = runtime ? runtime.forFilename(path) : null;
    var spec = explicitLanguage && runtime
      ? runtime.forLanguage(explicitLanguage)
      : (filenameSpec || {language: null, monacoLanguage: 'plaintext'});
    if (
      filenameSpec && filenameSpec.language
      && (!spec.language || filenameSpec.language === 'jsx' || filenameSpec.language === 'tsx')
    ) {
      spec = filenameSpec;
    }
    var host = createElement('div', 'agent-file-code');
    fileSurface.replaceChildren(host);
    var monaco = await Promise.resolve(global.NumOJMonacoReady);
    if (generation !== fileFetchGeneration) return;
    if (!monaco || !monaco.editor || !runtime) {
      fileSurface.replaceChildren(createElement('pre', 'agent-file-code-fallback', content));
      return;
    }
    var theme = await runtime.prepareMonaco(monaco);
    if (generation !== fileFetchGeneration) return;
    var uri = monaco.Uri.parse(
      'file:///agent-workspace/' + encodeURIComponent(sessionId) + '/' + encodedMonacoPath(path)
    );
    monacoModel = monaco.editor.createModel(asText(content), spec.monacoLanguage, uri);
    modelDocumentIds.set(monacoModel, stableDocumentId(path));
    monacoEditor = monaco.editor.create(host, runtime.monacoOptions({
      model: monacoModel,
      theme: theme,
      readOnly: true,
      domReadOnly: true,
      ariaLabel: path + '，只读文件预览',
      renderValidationDecorations: 'on',
      fontSize: 12.5,
      lineHeight: 20,
      wordWrap: 'off'
    }));
    ensureSemanticProvider(monaco, spec);
    global.requestAnimationFrame(function () {
      if (monacoEditor) monacoEditor.layout();
    });
  }

  function imageViewer(url, path) {
    var stage = createElement('div', 'agent-file-image-stage');
    var image = document.createElement('img');
    image.alt = path;
    image.draggable = false;
    image.src = url;
    var toolbar = createElement('div', 'agent-image-toolbar');
    var zoomOut = createElement('button');
    var output = document.createElement('output');
    var zoomIn = createElement('button');
    var reset = createElement('button');
    zoomOut.type = zoomIn.type = reset.type = 'button';
    zoomOut.title = '缩小';
    zoomIn.title = '放大';
    reset.title = '适应宽度';
    zoomOut.innerHTML = '<i class="fas fa-minus" aria-hidden="true"></i>';
    zoomIn.innerHTML = '<i class="fas fa-plus" aria-hidden="true"></i>';
    reset.innerHTML = '<i class="fas fa-expand" aria-hidden="true"></i>';
    toolbar.append(zoomOut, output, zoomIn, reset);
    stage.append(image, toolbar);

    var zoom = 1;
    var offsetX = 0;
    var offsetY = 0;
    var pointer = null;
    var startX = 0;
    var startY = 0;

    function apply() {
      image.style.width = (zoom * 100) + '%';
      image.style.height = 'auto';
      image.style.transform = 'translate(' + offsetX + 'px, ' + offsetY + 'px)';
      output.value = Math.round(zoom * 100) + '%';
      output.textContent = output.value;
    }

    function setZoom(value) {
      zoom = Math.min(8, Math.max(0.25, value));
      if (zoom <= 1) {
        offsetX = 0;
        offsetY = 0;
      }
      apply();
    }

    zoomOut.addEventListener('click', function () { setZoom(zoom / 1.2); });
    zoomIn.addEventListener('click', function () { setZoom(zoom * 1.2); });
    reset.addEventListener('click', function () {
      zoom = 1;
      offsetX = offsetY = 0;
      apply();
    });
    stage.addEventListener('wheel', function (event) {
      event.preventDefault();
      setZoom(zoom * (event.deltaY < 0 ? 1.12 : 1 / 1.12));
    }, {passive: false});
    stage.addEventListener('pointerdown', function (event) {
      if (event.target.closest('.agent-image-toolbar') || zoom <= 1) return;
      pointer = event.pointerId;
      startX = event.clientX - offsetX;
      startY = event.clientY - offsetY;
      stage.setPointerCapture(pointer);
      stage.classList.add('is-panning');
    });
    stage.addEventListener('pointermove', function (event) {
      if (pointer !== event.pointerId) return;
      offsetX = event.clientX - startX;
      offsetY = event.clientY - startY;
      apply();
    });
    function endPointer(event) {
      if (pointer !== event.pointerId) return;
      pointer = null;
      stage.classList.remove('is-panning');
    }
    stage.addEventListener('pointerup', endPointer);
    stage.addEventListener('pointercancel', endPointer);
    apply();
    imageCleanup = function () { image.src = ''; };
    return stage;
  }

  function rawFileUrl(path) {
    return queryUrl(root.dataset.workspaceFileUrl, {path: path, raw: 1});
  }

  function downloadFileUrl(path) {
    return queryUrl(root.dataset.workspaceFileUrl, {path: path, download: 1});
  }

  function previewKind(metadata, path) {
    var kind = statusKey(metadata.preview_kind || metadata.kind || metadata.preview_type);
    if (['code', 'markdown', 'pdf', 'image', 'text', 'unsupported'].indexOf(kind) >= 0) return kind;
    var mime = statusKey(metadata.mime_type || metadata.mime);
    if (mime.indexOf('image/') === 0) return 'image';
    if (mime === 'application/pdf') return 'pdf';
    var extension = (path.split('.').pop() || '').toLowerCase();
    if (extension === 'md' || extension === 'markdown') return 'markdown';
    if (global.NumOJCodeEditorRuntime && global.NumOJCodeEditorRuntime.forFilename(path).language) return 'code';
    return metadata.is_text === true ? 'text' : 'unsupported';
  }

  function fetchRawText(path, signal) {
    return global.fetch(rawFileUrl(path), {
      credentials: 'same-origin',
      signal: signal,
      cache: 'no-store',
      mathCurveLoader: false
    }).then(function (response) {
      if (!response.ok) throw new Error('读取文件失败（HTTP ' + response.status + '）');
      return response.text();
    });
  }

  function renderFile(metadata, path, generation, signal) {
    var kind = previewKind(metadata, path);
    var content = metadata.content != null ? metadata.content : metadata.text;
    if (fileIcon) fileIcon.className = fileIconClass(path);
    if (kind === 'code') {
      return Promise.resolve(content == null ? fetchRawText(path, signal) : content).then(function (value) {
        if (generation !== fileFetchGeneration) return;
        return renderCode(value, path, metadata.language, generation);
      });
    }
    if (kind === 'markdown') {
      var html = metadata.html || metadata.content_html || metadata.rendered_html;
      if (html) {
        var markdown = createElement('article', 'agent-file-markdown numoj-markdown');
        fileSurface.replaceChildren(markdown);
        setServerHtml(markdown, html);
        return Promise.resolve();
      }
      return Promise.resolve(content == null ? fetchRawText(path, signal) : content).then(function (value) {
        if (generation !== fileFetchGeneration) return;
        fileSurface.replaceChildren(createElement('pre', 'agent-file-text', value));
      });
    }
    if (kind === 'pdf') {
      var frame = createElement('iframe', 'agent-file-pdf');
      frame.title = path;
      frame.referrerPolicy = 'no-referrer';
      frame.src = metadata.raw_url || rawFileUrl(path);
      fileSurface.replaceChildren(frame);
      return Promise.resolve();
    }
    if (kind === 'image') {
      fileSurface.replaceChildren(imageViewer(metadata.raw_url || rawFileUrl(path), path));
      return Promise.resolve();
    }
    if (kind === 'text') {
      return Promise.resolve(content == null ? fetchRawText(path, signal) : content).then(function (value) {
        if (generation !== fileFetchGeneration) return;
        fileSurface.replaceChildren(createElement('pre', 'agent-file-text', value));
      });
    }
    var unsupported = createElement('div', 'agent-file-unsupported');
    var unsupportedIcon = createElement('i', 'fas fa-file-circle-question');
    unsupportedIcon.setAttribute('aria-hidden', 'true');
    unsupported.append(unsupportedIcon, createElement('strong', '', '无法预览的文件格式'));
    fileSurface.replaceChildren(unsupported);
    return Promise.resolve();
  }

  function setSelectedTreeFile(path) {
    selectedPath = path;
    if (!workspaceTree) return;
    workspaceTree.querySelectorAll('[data-agent-open-file]').forEach(function (button) {
      button.classList.toggle('is-active', button.dataset.agentOpenFile === path);
    });
  }

  function initializeFileLayout() {
    if (global.matchMedia('(max-width: 991.98px)').matches) return;
    root.style.gridTemplateColumns = '';
    updateSplitterAria();
  }

  function mobileFilePreview() {
    return global.matchMedia('(max-width: 991.98px)').matches;
  }

  function syncFilePaneAccessibility() {
    if (!filePane || filePane.hidden) return;
    if (mobileFilePreview()) {
      filePane.setAttribute('role', 'dialog');
      filePane.setAttribute('aria-modal', 'true');
      filePane.setAttribute('aria-label', '文件预览');
      filePane.tabIndex = -1;
    } else {
      filePane.removeAttribute('role');
      filePane.removeAttribute('aria-modal');
      filePane.setAttribute('aria-label', '文件预览');
      filePane.removeAttribute('tabindex');
    }
  }

  function openFile(path) {
    path = asText(path).trim();
    if (!path || !filePane || !fileSurface) return;
    var wasFilePaneHidden = filePane.hidden;
    if (
      wasFilePaneHidden
      && global.HTMLElement
      && document.activeElement instanceof global.HTMLElement
    ) {
      filePreviewReturnFocus = document.activeElement;
    }
    disposeFilePreview();
    var generation = fileFetchGeneration;
    fileAbortController = new AbortController();
    setSelectedTreeFile(path);
    root.classList.add('has-file');
    filePane.hidden = false;
    syncFilePaneAccessibility();
    conversationSplitter.hidden = false;
    if (fileName) {
      fileName.textContent = path.split('/').pop() || path;
      fileName.title = path;
    }
    if (fileDownload) fileDownload.href = downloadFileUrl(path);
    fileSurface.replaceChildren(mathLoader('正在读取文件', 'sm'));
    if (wasFilePaneHidden) initializeFileLayout();
    if (mobileFilePreview()) {
      var closeButton = root.querySelector('[data-agent-file-close]');
      if (closeButton) global.requestAnimationFrame(function () { closeButton.focus(); });
    }

    global.fetch(queryUrl(root.dataset.workspaceFileUrl, {path: path}), {
      headers: {'Accept': 'application/json'},
      credentials: 'same-origin',
      cache: 'no-store',
      signal: fileAbortController.signal,
      mathCurveLoader: false
    }).then(function (response) {
      var contentType = asText(response.headers.get('Content-Type')).toLowerCase();
      if (contentType.indexOf('application/json') >= 0) {
        return response.json().catch(function () { return {}; }).then(function (payload) {
          if (!response.ok || !payload || payload.success === false) {
            throw new Error(asText(payload && payload.message) || '无法读取文件');
          }
          return payload.file && typeof payload.file === 'object' ? payload.file : payload;
        });
      }
      if (!response.ok) throw new Error('无法读取文件（HTTP ' + response.status + '）');
      return response.blob().then(function (blob) {
        return {preview_kind: blob.type.indexOf('image/') === 0 ? 'image' : 'text', mime_type: blob.type};
      });
    }).then(function (metadata) {
      if (generation !== fileFetchGeneration) return;
      return renderFile(metadata || {}, path, generation, fileAbortController.signal);
    }).catch(function (error) {
      if (generation !== fileFetchGeneration || error.name === 'AbortError') return;
      var holder = createElement('div', 'agent-file-error');
      var icon = createElement('i', 'fas fa-exclamation-triangle');
      icon.setAttribute('aria-hidden', 'true');
      holder.append(icon, createElement('strong', '', error.message || '无法读取文件'));
      fileSurface.replaceChildren(holder);
    });
  }

  function closeFile() {
    disposeFilePreview();
    setSelectedTreeFile('');
    root.classList.remove('has-file');
    root.style.gridTemplateColumns = '';
    filePane.hidden = true;
    filePane.removeAttribute('role');
    filePane.removeAttribute('aria-modal');
    filePane.removeAttribute('tabindex');
    conversationSplitter.hidden = true;
    updateSplitterAria();
    if (filePreviewReturnFocus && filePreviewReturnFocus.isConnected) {
      filePreviewReturnFocus.focus();
    }
    filePreviewReturnFocus = null;
  }

  function trapMobileFilePreviewFocus(event) {
    if (!filePane || filePane.hidden || !mobileFilePreview()) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      closeFile();
      return;
    }
    if (event.key !== 'Tab') return;
    var focusable = Array.prototype.slice.call(filePane.querySelectorAll(
      'a[href], button:not([disabled]), iframe, [tabindex]:not([tabindex="-1"])'
    )).filter(function (element) {
      return !element.hidden && element.getClientRects().length > 0;
    });
    if (!focusable.length) {
      event.preventDefault();
      filePane.focus();
      return;
    }
    var first = focusable[0];
    var last = focusable[focusable.length - 1];
    if (event.shiftKey && (document.activeElement === first || !filePane.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !filePane.contains(document.activeElement))) {
      event.preventDefault();
      first.focus();
    }
  }

  function layoutMonaco() {
    if (monacoEditor) global.requestAnimationFrame(function () { monacoEditor.layout(); });
  }

  function paneWidths() {
    var rootRect = root.getBoundingClientRect();
    var workspaceWidth = workspacePane.getBoundingClientRect().width;
    var conversationWidth = root.querySelector('.agent-conversation-pane').getBoundingClientRect().width;
    var fileWidth = filePane && !filePane.hidden ? filePane.getBoundingClientRect().width : 0;
    return {total: rootRect.width, workspace: workspaceWidth, conversation: conversationWidth, file: fileWidth};
  }

  function clamp(value, minimum, maximum) {
    return Math.min(maximum, Math.max(minimum, value));
  }

  function applyPaneWidths(conversationWidth, workspaceWidth) {
    if (global.matchMedia('(max-width: 991.98px)').matches) return;
    var total = root.getBoundingClientRect().width;
    if (root.classList.contains('has-file')) {
      var workspace = clamp(workspaceWidth, 160, Math.max(160, total * 0.36));
      var remaining = total - workspace - 10;
      var conversation = clamp(conversationWidth, 280, Math.max(280, remaining - 280));
      var file = Math.max(280, remaining - conversation);
      root.style.gridTemplateColumns = conversation + 'px 5px ' + file + 'px 5px ' + workspace + 'px';
    } else {
      var sidebar = clamp(workspaceWidth, 190, Math.max(190, total * 0.43));
      root.style.gridTemplateColumns = 'minmax(0, 1fr) 5px ' + sidebar + 'px';
    }
    updateSplitterAria();
    layoutMonaco();
  }

  function updateSplitterAria() {
    if (global.matchMedia('(max-width: 991.98px)').matches) return;
    var widths = paneWidths();
    if (workspaceSplitter) {
      workspaceSplitter.setAttribute('aria-valuenow', String(Math.round(widths.workspace / widths.total * 100)));
    }
    if (conversationSplitter && root.classList.contains('has-file')) {
      conversationSplitter.setAttribute('aria-valuenow', String(Math.round(widths.conversation / widths.total * 100)));
    }
  }

  function bindSplitter(splitter, kind) {
    if (!splitter) return;
    var pointerId = null;

    splitter.addEventListener('pointerdown', function (event) {
      if (global.matchMedia('(max-width: 991.98px)').matches) return;
      pointerId = event.pointerId;
      splitter.setPointerCapture(pointerId);
      splitter.classList.add('is-dragging');
      event.preventDefault();
    });
    splitter.addEventListener('pointermove', function (event) {
      if (pointerId !== event.pointerId) return;
      var rect = root.getBoundingClientRect();
      var widths = paneWidths();
      if (kind === 'workspace') {
        applyPaneWidths(widths.conversation, rect.right - event.clientX);
      } else {
        applyPaneWidths(event.clientX - rect.left, widths.workspace);
      }
    });
    function finish(event) {
      if (pointerId !== event.pointerId) return;
      pointerId = null;
      splitter.classList.remove('is-dragging');
    }
    splitter.addEventListener('pointerup', finish);
    splitter.addEventListener('pointercancel', finish);
    splitter.addEventListener('keydown', function (event) {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      var direction = event.key === 'ArrowRight' ? 1 : -1;
      var widths = paneWidths();
      if (kind === 'workspace') {
        applyPaneWidths(widths.conversation, widths.workspace - direction * 16);
      } else {
        applyPaneWidths(widths.conversation + direction * 16, widths.workspace);
      }
    });
  }

  function bindWorkspaceAndFiles() {
    root.addEventListener('click', function (event) {
      var target = event.target.closest('[data-agent-open-file]');
      if (!target) return;
      event.preventDefault();
      openFile(target.dataset.agentOpenFile);
      root.classList.remove('workspace-open');
      var toggle = root.querySelector('[data-agent-workspace-toggle]');
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
    });
    var closeButton = root.querySelector('[data-agent-file-close]');
    if (closeButton) closeButton.addEventListener('click', closeFile);
    var workspaceToggle = root.querySelector('[data-agent-workspace-toggle]');
    var workspaceClose = root.querySelector('[data-agent-workspace-close]');
    if (workspaceToggle) {
      workspaceToggle.addEventListener('click', function () {
        var open = !root.classList.contains('workspace-open');
        root.classList.toggle('workspace-open', open);
        workspaceToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
    }
    if (workspaceClose) workspaceClose.addEventListener('click', function () {
      root.classList.remove('workspace-open');
      if (workspaceToggle) workspaceToggle.setAttribute('aria-expanded', 'false');
    });
    document.addEventListener('keydown', trapMobileFilePreviewFocus);
    bindSplitter(conversationSplitter, 'conversation');
    bindSplitter(workspaceSplitter, 'workspace');
    global.addEventListener('resize', function () {
      if (global.matchMedia('(max-width: 991.98px)').matches) {
        root.style.gridTemplateColumns = '';
      } else {
        var widths = paneWidths();
        applyPaneWidths(widths.conversation, widths.workspace);
      }
      syncFilePaneAccessibility();
      layoutMonaco();
    });
  }

  bindResumeComposer();
  bindRetryButton();
  bindStopButton();
  bindWorkspaceAndFiles();
  paintSessionAvatars();
  renderHeaderTokenUsage(currentState && currentState.session_token_usage);
  enhanceMarkdown(root);
  var initialWorkspace = readJson('[data-agent-initial-workspace-json]', []);
  if (Array.isArray(initialWorkspace) && initialWorkspace.length) {
    renderWorkspace({tree: initialWorkspace});
  }
  scheduleWorkspaceRefresh(0);
  if (currentTaskId && running && currentState && Object.keys(currentState).length) {
    applyState(currentState, '', liveGeneration);
  }
  if (currentTaskId && running) startStream(currentTaskId);
  setRunning(
    running,
    currentState.status || root.dataset.status || (running ? 'running' : 'completed')
  );
  scrollToLatest('auto');

  global.addEventListener('beforeunload', function () {
    stopLiveUpdates();
    if (workspaceTimer) global.clearTimeout(workspaceTimer);
    disposeFilePreview();
  });
}(window));
