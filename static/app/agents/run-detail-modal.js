(function () {
  if (window.__agentTaskDetailModalInit) return;
  window.__agentTaskDetailModalInit = true;

  var modalEl = document.querySelector('[data-agent-task-modal]');
  if (!modalEl || !window.bootstrap || !window.AgentExecutionTrace) return;

  var modal = new bootstrap.Modal(modalEl);
  var traceRoot = modalEl.querySelector('[data-agent-task-trace]');
  var metaEl = modalEl.querySelector('[data-agent-task-meta]');
  var statusEl = modalEl.querySelector('[data-agent-task-status]');
  var messageEl = modalEl.querySelector('[data-agent-task-message]');
  var inputEl = modalEl.querySelector('[data-agent-task-input]');
  var cachedEl = modalEl.querySelector('[data-agent-task-cached]');
  var outputEl = modalEl.querySelector('[data-agent-task-output]');
  var costEl = modalEl.querySelector('[data-agent-task-cost]');
  var costFactEl = modalEl.querySelector('[data-agent-task-cost-fact]');
  var scoreEl = modalEl.querySelector('[data-agent-task-score]');
  var attemptsEl = modalEl.querySelector('[data-agent-task-attempts]');
  var liveEl = modalEl.querySelector('[data-agent-task-live]');
  var finalLinkEl = modalEl.querySelector('[data-agent-task-final-link]');
  var finalLabelEl = modalEl.querySelector('[data-agent-task-final-label]');
  var renderer = window.AgentExecutionTrace.create({
    keyPrefix: 'problem-agent',
    showThinkingLoader: true,
    showPendingLoader: true
  });
  var source = null;
  var pollingTimer = null;
  var currentTaskId = '';
  var liveGeneration = 0;

  var STATUS = {
    pending: {label: '等待中', className: 'is-pending'},
    running: {label: '运行中', className: 'is-running'},
    completed: {label: '已完成', className: 'is-completed'},
    failed: {label: '未通过', className: 'is-failed'},
    canceled: {label: '已取消', className: 'is-canceled'},
    cancelled: {label: '已取消', className: 'is-canceled'}
  };

  function taskUrl(template, taskId) {
    return String(template || '').split('__TASK_ID__').join(encodeURIComponent(taskId));
  }

  function submissionUrl(submissionId) {
    var id = Number(submissionId || 0);
    if (!Number.isInteger(id) || id <= 0) return '';
    return String(modalEl.dataset.submissionUrlTemplate || '').replace(
      /\/0(?=([?#]|$))/, '/' + String(id)
    );
  }

  function statusKey(value) {
    return String(value || 'Pending').trim().toLowerCase();
  }

  function isFinished(state) {
    var key = statusKey(state && state.status);
    return key === 'completed' || key === 'failed' || key === 'canceled' || key === 'cancelled';
  }

  function setLiveState(label, className) {
    if (!liveEl) return;
    liveEl.classList.remove('is-live', 'is-ended');
    if (className) liveEl.classList.add(className);
    var text = liveEl.querySelector('span');
    if (text) text.textContent = label;
  }

  function updateLocation(taskId) {
    if (!window.history || !window.URL) return;
    var url = new URL(window.location.href);
    if (taskId) url.searchParams.set('task_id', taskId);
    else url.searchParams.delete('task_id');
    window.history.replaceState(window.history.state, '', url.toString());
  }

  function isCurrentRun(taskId, generation, activeSource) {
    if (taskId !== currentTaskId || generation !== liveGeneration) return false;
    return !activeSource || source === activeSource;
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

  function renderTokenUsage(trace) {
    var usage = trace && trace.token_usage && typeof trace.token_usage === 'object'
      ? trace.token_usage
      : null;
    if (!usage) {
      inputEl.textContent = '—';
      cachedEl.textContent = '—';
      outputEl.textContent = '—';
      costEl.textContent = '—';
      costFactEl.hidden = true;
      return;
    }
    var inputTokens = Number(usage.input_total_tokens);
    var cachedTokens = Number(usage.input_cached_tokens);
    var outputTokens = Number(usage.output_tokens);
    var cachedPercent = inputTokens > 0 && cachedTokens >= 0
      ? Math.min(100, cachedTokens / inputTokens * 100)
      : 0;
    inputEl.textContent = formatTokenCount(inputTokens);
    cachedEl.textContent = cachedPercent.toFixed(2) + '%';
    outputEl.textContent = formatTokenCount(outputTokens);

    var hasCost = usage.cost_rmb !== null
      && usage.cost_rmb !== undefined
      && usage.cost_rmb !== ''
      && Number.isFinite(Number(usage.cost_rmb))
      && Number(usage.cost_rmb) >= 0;
    costFactEl.hidden = !hasCost;
    costEl.textContent = hasCost
      ? formatMeasuredValue(Number(usage.cost_rmb)) + ' RMB'
      : '—';
  }

  function applyState(state, expectedTaskId, generation) {
    if (
      !state || typeof state !== 'object'
      || !isCurrentRun(expectedTaskId, generation)
    ) return;
    var key = statusKey(state.status);
    var display = STATUS[key] || {label: String(state.status || '状态未知'), className: 'is-pending'};
    statusEl.textContent = display.label;
    statusEl.className = 'agent-task-status-pill ' + display.className;
    messageEl.textContent = String(state.message || '任务执行中');
    scoreEl.textContent = String(Number(state.best_score || 0));
    attemptsEl.textContent = String(Array.isArray(state.attempts) ? state.attempts.length : 0);
    if (state.problem_title) {
      metaEl.textContent = String(state.problem_title) + ' · Task ' + expectedTaskId;
    }

    var trace = state.execution_trace && typeof state.execution_trace === 'object'
      ? state.execution_trace
      : {};
    renderTokenUsage(trace);
    renderer.render(traceRoot, trace, {
      scope: expectedTaskId,
      source: String(trace.trace_id || expectedTaskId),
      phase: 'run',
      runningText: 'Agent 正在执行',
      pendingText: '等待 Agent 开始执行',
      emptyText: '暂无运行轨迹',
      showThinkingLoader: true,
      showPendingLoader: true
    });

    var finished = isFinished(state);
    setLiveState(finished ? '任务已结束' : '实时更新', finished ? 'is-ended' : 'is-live');
    var finalId = Number(state.final_submission_id || 0);
    var finalUrl = finished ? submissionUrl(finalId) : '';
    finalLinkEl.hidden = !finalUrl;
    if (finalUrl) {
      finalLinkEl.href = finalUrl;
      finalLabelEl.textContent = '最终提交 #' + String(finalId);
    } else {
      finalLinkEl.removeAttribute('href');
      finalLabelEl.textContent = '最终提交';
    }
  }

  function stopLiveUpdates() {
    if (source) {
      source.close();
      source = null;
    }
    if (pollingTimer) {
      clearTimeout(pollingTimer);
      pollingTimer = null;
    }
  }

  function fetchState(taskId, generation) {
    var url = taskUrl(modalEl.dataset.statusUrlTemplate, taskId);
    return fetch(url, {headers: {'Accept': 'application/json'}, credentials: 'same-origin'})
      .then(function (response) {
        if (!response.ok) throw new Error('读取任务状态失败（HTTP ' + response.status + '）');
        return response.json();
      })
      .then(function (payload) {
        if (!payload || !payload.success || !payload.state) {
          throw new Error((payload && payload.message) || '任务状态不可用');
        }
        applyState(payload.state, taskId, generation);
        return payload.state;
      });
  }

  function startPolling(taskId, generation) {
    if (!isCurrentRun(taskId, generation)) return;
    fetchState(taskId, generation).then(function (state) {
      if (!isCurrentRun(taskId, generation) || isFinished(state)) return;
      pollingTimer = setTimeout(function () {
        startPolling(taskId, generation);
      }, 2000);
    }).catch(function (error) {
      if (!isCurrentRun(taskId, generation)) return;
      setLiveState('连接重试中', '');
      messageEl.textContent = error.message || '读取任务状态失败';
      pollingTimer = setTimeout(function () {
        startPolling(taskId, generation);
      }, 3000);
    });
  }

  function parseStreamState(event, taskId, generation) {
    try { applyState(JSON.parse(event.data), taskId, generation); }
    catch (_error) {
      setLiveState('数据异常', '');
    }
  }

  function startStream(taskId, generation) {
    if (!window.EventSource) {
      startPolling(taskId, generation);
      return;
    }
    var activeSource = new EventSource(
      taskUrl(modalEl.dataset.streamUrlTemplate, taskId)
    );
    source = activeSource;
    activeSource.addEventListener('status', function (event) {
      if (!isCurrentRun(taskId, generation, activeSource)) return;
      parseStreamState(event, taskId, generation);
    });
    activeSource.addEventListener('done', function (event) {
      if (!isCurrentRun(taskId, generation, activeSource)) return;
      parseStreamState(event, taskId, generation);
      activeSource.close();
      if (source === activeSource) source = null;
    });
    activeSource.addEventListener('timeout', function (event) {
      if (!isCurrentRun(taskId, generation, activeSource)) return;
      parseStreamState(event, taskId, generation);
    });
    activeSource.addEventListener('error', function () {
      if (!isCurrentRun(taskId, generation, activeSource)) return;
      if (activeSource.readyState === EventSource.CLOSED) {
        activeSource.close();
        if (source === activeSource) source = null;
        startPolling(taskId, generation);
      } else {
        setLiveState('正在重连', '');
      }
    });
  }

  function resetView(taskId, problemTitle) {
    renderer.reset(traceRoot);
    statusEl.textContent = '等待中';
    statusEl.className = 'agent-task-status-pill is-pending';
    messageEl.textContent = '正在连接任务状态…';
    scoreEl.textContent = '0';
    inputEl.textContent = '—';
    cachedEl.textContent = '—';
    outputEl.textContent = '—';
    costEl.textContent = '—';
    costFactEl.hidden = true;
    attemptsEl.textContent = '0';
    metaEl.textContent = (problemTitle ? problemTitle + ' · ' : '') + 'Task ' + taskId;
    finalLinkEl.hidden = true;
    finalLinkEl.removeAttribute('href');
    setLiveState('正在连接', '');
    renderer.render(traceRoot, {
      status: 'pending', error_message: '', trace_messages: [], trace_files: []
    }, {
      scope: taskId,
      pendingText: '正在读取任务状态',
      showPendingLoader: true
    });
  }

  function openTask(taskId, problemTitle) {
    taskId = String(taskId || '').trim();
    if (!taskId) return;
    liveGeneration += 1;
    stopLiveUpdates();
    currentTaskId = taskId;
    resetView(taskId, String(problemTitle || '').trim());
    updateLocation(taskId);
    modal.show();
    startStream(taskId, liveGeneration);
  }

  document.addEventListener('click', function (event) {
    var button = event.target.closest && event.target.closest('[data-agent-task-detail]');
    if (!button) return;
    event.preventDefault();
    openTask(button.getAttribute('data-task-id'), button.getAttribute('data-problem-title'));
  });

  modalEl.addEventListener('hidden.bs.modal', function () {
    liveGeneration += 1;
    stopLiveUpdates();
    currentTaskId = '';
    renderer.reset(traceRoot);
    updateLocation('');
  });

  var initialTaskId = String(modalEl.dataset.initialTaskId || '').trim();
  if (initialTaskId) openTask(initialTaskId, '');
})();
