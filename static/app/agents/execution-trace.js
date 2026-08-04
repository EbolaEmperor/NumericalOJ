(function () {
  if (window.AgentExecutionTrace) return;

  var THINKING_WORDS = [
    'Thinking', 'Pondering', 'Reasoning', 'Analyzing', 'Deliberating',
    'Ruminating', 'Cogitating', 'Contemplating', 'Mulling', 'Noodling',
    'Percolating', 'Reflecting', 'Synthesizing', 'Exploring'
  ];

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"]/g, function (char) {
      return {'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;'}[char];
    });
  }

  function typesetMath(targets) {
    if (window.MathJax && typeof window.MathJax.typesetPromise === 'function') {
      var roots = Array.isArray(targets) ? targets : (targets ? [targets] : undefined);
      if (!roots || roots.length) window.MathJax.typesetPromise(roots).catch(function () {});
    }
  }

  function createRenderer(defaultOptions) {
    var defaults = defaultOptions || {};
    var currentRoot = null;
    var currentScope = '';
    var thinkingWord = '';
    var traceExpanded = false;
    var messageOrder = [];
    var messageRecords = Object.create(null);
    var latestTrace = {};
    var latestContext = {};
    var openDetails = Object.create(null);

    function option(context, trace, name, fallback) {
      if (context && context[name] != null) return context[name];
      if (trace && trace[name] != null) return trace[name];
      if (defaults[name] != null) return defaults[name];
      return fallback;
    }

    function messageField(message, context, trace, name) {
      if (message && message[name] != null) return message[name];
      return option(context, trace, name, '');
    }

    function scopeKey(context, trace) {
      return String(option(context, trace, 'scope', 'default'));
    }

    function traceIdentity(context, trace) {
      return [
        scopeKey(context, trace),
        'source:' + String(option(context, trace, 'source', '')),
        'phase:' + String(option(context, trace, 'phase', ''))
      ].join('|');
    }

    function messageKey(message, index, context, trace) {
      var line = messageField(message, context, trace, 'line');
      var offset = messageField(message, context, trace, 'offset');
      var source = String(messageField(message, context, trace, 'source'));
      var eventIndex = messageField(message, context, trace, 'event_index');
      if (source !== '' && offset !== '') {
        return [
          scopeKey(context, trace), 'msg', message.kind || 'assistant',
          'source:' + source, 'offset:' + String(offset),
          'event:' + String(eventIndex === '' ? index : eventIndex)
        ].join('|');
      }
      var parts = [
        traceIdentity(context, trace),
        'msg',
        message.kind || 'assistant',
        'source:' + source,
        'phase:' + String(messageField(message, context, trace, 'phase')),
        offset === '' ? 'line:' + String(line) : 'offset:' + String(offset)
      ];
      if (line === '' && offset === '') parts.push('idx:' + index);
      parts.push(message.title || '', message.meta || '', String(message.text || '').slice(0, 120));
      return parts.join('|');
    }

    function detailAttr(key) {
      key = String(defaults.keyPrefix || 'agent-trace') + '|' + key;
      return ' data-agent-trace-open-key="' + esc(key) + '" data-rj-open-key="' + esc(key) + '"';
    }

    function remember(root) {
      if (!root) return;
      root.querySelectorAll('details[data-agent-trace-open-key]').forEach(function (element) {
        openDetails[element.getAttribute('data-agent-trace-open-key')] = !!element.open;
      });
    }

    function restore(root) {
      if (!root) return;
      root.querySelectorAll('details[data-agent-trace-open-key]').forEach(function (element) {
        var key = element.getAttribute('data-agent-trace-open-key');
        if (Object.prototype.hasOwnProperty.call(openDetails, key)) element.open = !!openDetails[key];
      });
    }

    function messageKind(message) {
      if (message.kind === 'subagent') return 'subagent';
      if (message.kind === 'thinking') return 'thinking';
      if (message.kind === 'tool') return 'tool';
      if (message.kind === 'tool_result') return 'tool_result';
      return 'assistant';
    }

    function messageIcon(kind) {
      if (kind === 'subagent') return 'fa-diagram-project';
      if (kind === 'thinking') return 'fa-brain';
      if (kind === 'tool') return 'fa-screwdriver-wrench';
      if (kind === 'tool_result') return 'fa-square-check';
      return 'fa-comment-dots';
    }

    function previewText(message) {
      var text = String(message && message.text || '').replace(/\s+/g, ' ').trim();
      if (!text) return '';
      return text.length > 80 ? text.slice(0, 80) + '...' : text;
    }

    function safeRichHtml(value) {
      var template = document.createElement('template');
      template.innerHTML = String(value || '');
      template.content.querySelectorAll('[id], [name]').forEach(function (element) {
        element.removeAttribute('id');
        element.removeAttribute('name');
      });
      return template.innerHTML;
    }

    function messageBody(message, kind) {
      if ((kind === 'assistant' || kind === 'thinking') && message.html) {
        return '<div class="rj-msg-body rj-md">' + safeRichHtml(message.html) + '</div>';
      }
      if (kind === 'tool' || kind === 'subagent') {
        var className = message.format === 'json' ? 'rj-tool-json' : 'rj-tool-text';
        return '<div class="rj-msg-body ' + className + '">' + esc(message.text || '') + '</div>';
      }
      if (kind === 'tool_result') {
        return '<div class="rj-msg-body rj-tool-result-text">' + esc(message.text || '') + '</div>';
      }
      return '<div class="rj-msg-body">' + esc(message.text || '') + '</div>';
    }

    function summaryHtml(message, kind, icon) {
      var title = message.title || (kind === 'tool' ? '工具调用' :
        (kind === 'tool_result' ? '工具结果' : (kind === 'subagent' ? '派出 subagent' : '思考片段')));
      var preview = previewText(message);
      return '<span class="rj-summary-main"><span class="rj-msg-title"><i class="fas ' + icon + '"></i>' + esc(title) + '</span>' +
        (preview ? '<span class="rj-summary-preview">' + esc(preview) + '</span>' : '') +
        '</span><span class="rj-summary-meta">' + esc(message.meta || '') + '</span>';
    }

    function messageHtml(message, index, context, trace) {
      var kind = messageKind(message);
      var icon = messageIcon(kind);
      var key = messageKey(message, index, context, trace);
      var messageKeyAttr = ' data-agent-trace-message-key="' + esc(key) + '"';
      var keyAttr = detailAttr(key);
      if (kind === 'thinking') {
        return '<details class="rj-msg thinking"' + messageKeyAttr + keyAttr + '>' +
          '<summary class="rj-thinking-summary">' + summaryHtml(message, kind, icon) + '</summary>' +
          messageBody(message, kind) + '</details>';
      }
      if (kind === 'tool' || kind === 'subagent') {
        var summaryClass = kind === 'subagent' ? 'rj-subagent-summary' : 'rj-tool-summary';
        return '<details class="rj-msg ' + kind + '"' + messageKeyAttr + keyAttr + '>' +
          '<summary class="' + summaryClass + '">' + summaryHtml(message, kind, icon) + '</summary>' +
          messageBody(message, kind) + '</details>';
      }
      if (kind === 'tool_result') {
        var resultClass = 'rj-msg tool-result' + (message.is_error ? ' error' : '');
        return '<details class="' + resultClass + '"' + messageKeyAttr + keyAttr + '>' +
          '<summary class="rj-tool-result-summary">' + summaryHtml(message, kind, icon) + '</summary>' +
          messageBody(message, kind) + '</details>';
      }
      return '<div class="rj-msg ' + kind + '"' + messageKeyAttr + '>' +
        '<div class="rj-msg-head"><span class="rj-msg-title"><i class="fas ' + icon + '"></i>' + esc(message.title || 'AI 回复') + '</span>' +
        '<span>' + esc(message.meta || '') + '</span></div>' + messageBody(message, kind) + '</div>';
    }

    function rawTraceHtml(files, context, trace) {
      files = files || [];
      if (!files.length) return '';
      var file = files[0] || {};
      var key = traceIdentity(context, trace) + '|trace-json|' + (file.path || '');
      return '<details class="rj-raw-json"' + detailAttr(key) + '><summary>展开原始 JSON</summary>' +
        '<div class="small text-muted mt-2"><code>' + esc(file.path || '') + '</code> · ' + esc(file.size || 0) + ' B</div>' +
        '<pre class="rj-pre mt-2">' + esc(file.content || '') + '</pre></details>';
    }

    function shellHtml(trace, context) {
      var messages = trace.trace_messages || [];
      var runningText = esc(option(context, trace, 'runningText', 'AI 正在作答'));
      var pendingText = esc(option(context, trace, 'pendingText', '等待 Agent 开始执行'));
      var emptyText = esc(option(context, trace, 'emptyText', '暂无可展示轨迹'));
      var html = trace.error_message
        ? '<div class="rj-alert" data-agent-trace-error>' + esc(trace.error_message) + '</div>'
        : '<div data-agent-trace-error hidden></div>';
      html += '<div class="rj-agent-feed" data-agent-trace-feed></div>';
      html += '<div class="rj-empty" data-agent-trace-empty' + (messages.length ? ' hidden' : '') + '>' +
        (trace.status === 'running' ? MathCurveLoader.markup(option(context, trace, 'runningText', 'AI 正在作答'), 'sm') :
          (trace.status === 'pending' ? pendingText : emptyText)) +
        '</div>';
      html += '<div data-agent-trace-activity></div>';
      html += '<div data-agent-trace-raw>' + rawTraceHtml(trace.trace_files || [], context, trace) + '</div>';
      html += '<div data-agent-trace-stdio></div>';
      return html;
    }

    // TRACE_ORDER_HELPER_START
    function reconcileMessageOrder(existingKeys, incomingKeys) {
      function isPrefix(prefix, full) {
        if (prefix.length > full.length) return false;
        for (var index = 0; index < prefix.length; index += 1) {
          if (prefix[index] !== full[index]) return false;
        }
        return true;
      }

      if (isPrefix(existingKeys, incomingKeys)) return incomingKeys.slice();
      if (isPrefix(incomingKeys, existingKeys)) return existingKeys.slice();

      var existingIndex = Object.create(null);
      var incomingSet = Object.create(null);
      existingKeys.forEach(function (key, index) { existingIndex[key] = index; });
      incomingKeys.forEach(function (key) { incomingSet[key] = true; });

      var firstOverlapIndex = -1;
      for (var index = 0; index < incomingKeys.length; index += 1) {
        if (Object.prototype.hasOwnProperty.call(existingIndex, incomingKeys[index])) {
          firstOverlapIndex = existingIndex[incomingKeys[index]];
          break;
        }
      }
      if (firstOverlapIndex < 0) return existingKeys.concat(incomingKeys);

      // 新快照可能是滑动尾窗，也可能补回了先前缺失的前置事件。保留第一个
      // 重叠事件之前、且新快照没有携带的历史；重叠部分则以新快照顺序为准。
      return existingKeys.slice(0, firstOverlapIndex).filter(function (key) {
        return !incomingSet[key];
      }).concat(incomingKeys);
    }
    // TRACE_ORDER_HELPER_END

    // TRACE_WINDOW_HELPER_START
    function visibleMessageKeys(keys, expanded) {
      if (expanded || keys.length <= 9) return keys.slice();
      return keys.slice(0, 7).concat(keys.slice(-2));
    }
    // TRACE_WINDOW_HELPER_END

    function reconcileMessages(root, trace, context) {
      var feed = root.querySelector('[data-agent-trace-feed]');
      if (!feed) return [];
      var existingElements = Object.create(null);
      var unknownElements = [];
      Array.prototype.forEach.call(feed.children, function (element) {
        if (element.hasAttribute('data-agent-trace-toggle')) return;
        var key = element.getAttribute('data-agent-trace-message-key');
        if (!key || existingElements[key]) {
          unknownElements.push(element);
          return;
        }
        existingElements[key] = element;
      });

      var incomingMessages = Object.create(null);
      var incomingKeys = [];
      (trace.trace_messages || []).forEach(function (message, index) {
        var key = messageKey(message, index, context, trace);
        if (incomingMessages[key]) return;
        incomingMessages[key] = {
          message: message, index: index, context: context, trace: trace
        };
        incomingKeys.push(key);
      });

      var targetKeys = reconcileMessageOrder(messageOrder, incomingKeys);
      var targetSet = Object.create(null);
      targetKeys.forEach(function (key) {
        targetSet[key] = true;
        if (incomingMessages[key]) messageRecords[key] = incomingMessages[key];
      });
      Object.keys(messageRecords).forEach(function (key) {
        if (!targetSet[key]) delete messageRecords[key];
      });
      messageOrder = targetKeys.slice();

      var visibleKeys = visibleMessageKeys(messageOrder, traceExpanded);
      var visibleSet = Object.create(null);
      var addedElements = [];
      visibleKeys.forEach(function (key) {
        visibleSet[key] = true;
        if (existingElements[key]) return;
        var record = messageRecords[key];
        if (!record) return;
        feed.insertAdjacentHTML(
          'beforeend', messageHtml(
            record.message, record.index, record.context, record.trace
          )
        );
        existingElements[key] = feed.lastElementChild;
        addedElements.push(existingElements[key]);
      });

      unknownElements.forEach(function (element) {
        if (element.parentNode === feed) feed.removeChild(element);
      });

      Object.keys(existingElements).forEach(function (key) {
        if (!visibleSet[key] && existingElements[key].parentNode === feed) {
          feed.removeChild(existingElements[key]);
        }
      });

      var oldToggle = feed.querySelector('[data-agent-trace-toggle]');
      if (oldToggle) oldToggle.remove();
      visibleKeys.forEach(function (key) {
        var element = existingElements[key];
        if (element && element.parentNode === feed) feed.appendChild(element);
      });

      if (messageOrder.length > 9 && !traceExpanded) {
        var omittedCount = messageOrder.length - 9;
        var toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'agent-trace-ellipsis';
        toggle.setAttribute('data-agent-trace-toggle', '');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', '展开中间 ' + omittedCount + ' 条执行记录');
        toggle.title = toggle.getAttribute('aria-label');
        toggle.textContent = '…';
        var eighthMessage = feed.querySelectorAll('[data-agent-trace-message-key]')[7];
        feed.insertBefore(toggle, eighthMessage || null);
      }
      return addedElements;
    }

    function bindWindowToggle(root) {
      if (root.dataset.agentTraceToggleBound === '1') return;
      root.dataset.agentTraceToggleBound = '1';
      root.addEventListener('click', function (event) {
        var toggle = event.target.closest && event.target.closest('[data-agent-trace-toggle]');
        if (!toggle || root !== currentRoot || !root.contains(toggle)) return;
        traceExpanded = true;
        remember(root);
        var addedElements = reconcileMessages(root, latestTrace, latestContext);
        restore(root);
        typesetMath(addedElements);
      });
    }

    function thinkingLoaderHtml(word) {
      return '<div class="agent-trace-thinking" role="status" aria-live="polite">' +
        '<span class="math-curve-loader" data-math-curve-loader data-size="sm">' +
        '<span class="math-curve-loader__label">' + esc(word) +
        '<span class="agent-trace-thinking-dots" aria-hidden="true">' +
        '<span>.</span><span>.</span><span>.</span></span></span></span></div>';
    }

    function pendingLoaderHtml(context, trace) {
      var label = esc(option(context, trace, 'pendingText', '等待 Agent 开始执行'));
      return '<div class="agent-trace-pending" role="status" aria-label="' + label + '">' +
        '<span class="math-curve-loader" data-math-curve-loader data-icon-only="true" data-size="lg"></span>' +
        '</div>';
    }

    function syncActivity(root, trace, context) {
      var activity = root.querySelector('[data-agent-trace-activity]');
      if (!activity) return;
      var showThinking = !!option(context, trace, 'showThinkingLoader', false);
      var showPending = !!option(context, trace, 'showPendingLoader', false);
      var mode = trace.status === 'running' && showThinking
        ? 'thinking' : (trace.status === 'pending' && showPending ? 'pending' : '');
      var empty = root.querySelector('[data-agent-trace-empty]');
      if (mode && empty) empty.hidden = true;
      if (!mode) {
        thinkingWord = '';
        if (activity.dataset.agentTraceActivityState !== '') {
          activity.innerHTML = '';
          activity.dataset.agentTraceActivityState = '';
        }
        return;
      }
      if (mode === 'thinking' && !thinkingWord) {
        thinkingWord = THINKING_WORDS[Math.floor(Math.random() * THINKING_WORDS.length)];
      }
      var state = mode === 'thinking' ? mode + '|' + thinkingWord : mode;
      if (activity.dataset.agentTraceActivityState === state) return;
      activity.innerHTML = mode === 'thinking'
        ? thinkingLoaderHtml(thinkingWord) : pendingLoaderHtml(context, trace);
      activity.dataset.agentTraceActivityState = state;
    }

    function syncExtras(root, trace, context) {
      var error = root.querySelector('[data-agent-trace-error]');
      if (error) {
        var errorText = trace.error_message || '';
        if (error.hidden === !!errorText) error.hidden = !errorText;
        var errorClass = errorText ? 'rj-alert' : '';
        if (error.className !== errorClass) error.className = errorClass;
        if (error.textContent !== errorText) error.textContent = errorText;
      }
      var empty = root.querySelector('[data-agent-trace-empty]');
      if (empty) {
        var feed = root.querySelector('[data-agent-trace-feed]');
        var hasMessages = !!(feed && feed.children.length);
        empty.hidden = hasMessages;
        if (!hasMessages) {
          var runningText = esc(option(context, trace, 'runningText', 'AI 正在作答'));
          var pendingText = esc(option(context, trace, 'pendingText', '等待 Agent 开始执行'));
          var emptyText = esc(option(context, trace, 'emptyText', '暂无可展示轨迹'));
          var emptyHtml = trace.status === 'running'
            ? MathCurveLoader.markup(option(context, trace, 'runningText', 'AI 正在作答'), 'sm')
            : (trace.status === 'pending' ? pendingText : emptyText);
          var emptyState = trace.status + '|' + runningText + '|' + pendingText + '|' + emptyText;
          if (empty.dataset.agentTraceState !== emptyState) {
            empty.innerHTML = emptyHtml;
            empty.dataset.agentTraceState = emptyState;
          }
        }
      }
      syncActivity(root, trace, context);
      var raw = root.querySelector('[data-agent-trace-raw]');
      if (raw) {
        var rawHtml = rawTraceHtml(trace.trace_files || [], context, trace);
        if (raw.innerHTML !== rawHtml) raw.innerHTML = rawHtml;
      }
      var stdio = root.querySelector('[data-agent-trace-stdio]');
      if (stdio) {
        var identity = traceIdentity(context, trace);
        var html = '';
        if (trace.stdout) {
          html += '<details class="rj-raw-json"' + detailAttr(identity + '|stdout') + '><summary>stdout</summary><pre class="rj-pre mt-2">' + esc(trace.stdout) + '</pre></details>';
        }
        if (trace.stderr) {
          html += '<details class="rj-raw-json"' + detailAttr(identity + '|stderr') + '><summary>stderr</summary><pre class="rj-pre mt-2">' + esc(trace.stderr) + '</pre></details>';
        }
        if (stdio.innerHTML !== html) stdio.innerHTML = html;
      }
    }

    function reset(root, options) {
      var target = root || currentRoot;
      var resetOptions = options || {};
      if (target) {
        target.removeAttribute('data-agent-trace-scope');
        if (resetOptions.clear !== false) target.innerHTML = '';
      }
      currentRoot = null;
      currentScope = '';
      thinkingWord = '';
      traceExpanded = false;
      messageOrder = [];
      messageRecords = Object.create(null);
      latestTrace = {};
      latestContext = {};
      openDetails = Object.create(null);
    }

    function render(root, trace, context) {
      if (!root) return;
      trace = trace || {};
      context = context || {};
      var nextScope = scopeKey(context, trace);
      var rebuild = currentRoot !== root || currentScope !== nextScope || !root.querySelector('[data-agent-trace-feed]');
      latestTrace = trace;
      latestContext = context;
      root.classList.add('agent-execution-trace');
      bindWindowToggle(root);
      if (rebuild) {
        remember(currentRoot);
        if (currentRoot !== root || currentScope !== nextScope) {
          thinkingWord = '';
          traceExpanded = false;
          messageOrder = [];
          messageRecords = Object.create(null);
        }
        root.innerHTML = shellHtml(trace, context);
        root.setAttribute('data-agent-trace-scope', nextScope);
        currentRoot = root;
        currentScope = nextScope;
        reconcileMessages(root, trace, context);
        restore(root);
        syncExtras(root, trace, context);
        restore(root);
        typesetMath(root);
        return;
      }
      remember(root);
      var addedElements = reconcileMessages(root, trace, context);
      syncExtras(root, trace, context);
      restore(root);
      typesetMath(addedElements);
    }

    return {reset: reset, render: render};
  }

  var defaultRenderer = createRenderer();
  window.AgentExecutionTrace = {
    create: createRenderer,
    reset: defaultRenderer.reset,
    render: defaultRenderer.render
  };
})();
