(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let code;
  let seq = 0;
  let status = 'loading';
  let view = {};
  let starter = '';
  let lastRunSource = '';
  let busy = false;
  let frames = [];
  let position = 0;
  let playing = false;
  let speed = 1;
  let timer = null;
  let pollTimer = null;
  const speeds = [1, 2, 4, 0.5];
  const base = new URL('./', window.location.href);
  const uuid = () => globalThis.crypto?.randomUUID?.() || `cmd-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const endpoint = (name) => new URL(`_edu/v1/${name}`, base).href;

  async function api(name, payload) {
    const response = await fetch(endpoint(name), {
      method: payload === undefined ? 'GET' : 'POST',
      credentials: 'omit',
      headers: { 'Accept': 'application/json', ...(payload === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    });
    let data;
    try { data = await response.json(); } catch { throw new Error('平台暂时没有返回作答数据，请稍后重试。'); }
    if (!response.ok || data.success === false) {
      if (response.status === 409) await loadState(false);
      throw new Error(data.error || data.message || `请求失败（${response.status}）`);
    }
    return data;
  }

  function message(text, good = false) {
    $('codeMessage').textContent = text || '';
    $('codeMessage').className = `code-message${text ? ' visible' : ''}${good ? ' good' : ''}`;
  }

  function updateButtons() {
    const active = status === 'active';
    $('runButton').disabled = busy || !active;
    $('submitButton').disabled = busy || !['active', 'submitted', 'error'].includes(status);
    $('submitButton').textContent = ['submitted', 'error'].includes(status) ? '重试评分 ↗' : '提交作业 ↗';
    $('resetButton').disabled = busy || !active;
    code?.updateOptions({ readOnly: busy || !active, domReadOnly: busy || !active });
    $('runButton').innerHTML = busy ? '<span>◌</span> 正在执行' : '<span>▶</span> 试运行';
    $('playButton').disabled = !frames.length;
    $('nextButton').disabled = !frames.length || position >= frames.length - 1;
    $('replayButton').disabled = !frames.length;
    $('playButton').textContent = playing ? 'Ⅱ' : '▶';
  }

  function setBadge(data) {
    const homework = data.assignment_id || data.homework_id || data.assignment || view.assignment_id;
    const label = { active: homework ? '作业模式' : '练习模式', submitted: '作业已提交', grading: '正在评分', graded: '评分完成', error: '评分暂时失败' }[status] || '正在连接';
    $('assignmentBadge').textContent = '● ' + label;
  }

  async function loadState(restoreCode = true) {
    const data = await api('state');
    seq = data.seq ?? 0;
    status = data.status || 'active';
    view = data.view || data.data?.view || {};
    if (!starter) starter = view.initial_source || view.source || '';
    if (restoreCode) {
      code.setValue(view.source || starter);
    }
    lastRunSource = view.execution ? (view.source || '') : '';
    setBadge(data);
    if (view.execution?.rounds?.length) preparePlayback(view.execution, false);
    else renderFrame({ left: [], right: [], round: 0, message: '等待试运行' });
    updateButtons();
    if (['submitted', 'grading', 'graded', 'error'].includes(status)) pollResult();
    return data;
  }

  function svgElement(name, attributes, text) {
    const item = document.createElementNS('http://www.w3.org/2000/svg', name);
    Object.entries(attributes || {}).forEach(([key, value]) => item.setAttribute(key, String(value)));
    if (text !== undefined) item.textContent = text;
    return item;
  }

  function renderHeap(id, items, highlight) {
    const svg = $(id);
    svg.replaceChildren();
    if (!items.length) { svg.append(svgElement('text', { x: 200, y: 126, class: 'empty-heap' }, '等待第一个数字')); return; }
    const shown = items.slice(0, 31);
    const depth = Math.floor(Math.log2(shown.length));
    const levelGap = depth > 3 ? 43 : 53;
    const radius = depth > 3 ? 12 : depth > 2 ? 15 : 19;
    const coordinate = (index) => {
      const level = Math.floor(Math.log2(index + 1));
      const offset = index - (2 ** level - 1);
      return [400 * (offset + 0.5) / (2 ** level), 39 + level * levelGap];
    };
    shown.forEach((_value, index) => {
      if (!index) return;
      const [x1, y1] = coordinate(Math.floor((index - 1) / 2));
      const [x2, y2] = coordinate(index);
      svg.append(svgElement('line', { x1, y1, x2, y2, class: 'heap-edge' }));
    });
    shown.forEach((value, index) => {
      const [x, y] = coordinate(index);
      const node = svgElement('g', { class: `heap-node${index === 0 ? ' root' : ''}${index === highlight ? ' new' : ''}`, transform: `translate(${x},${y})` });
      node.append(svgElement('circle', { r: radius }));
      node.append(svgElement('text', { style: `font-size:${Math.abs(value) > 999 ? 9 : radius < 15 ? 10 : 15}px` }, value));
      svg.append(node);
    });
    if (items.length > shown.length) svg.append(svgElement('text', { x: 200, y: 238, class: 'heap-extra' }, `另有 ${items.length - shown.length} 个节点，已省略显示`));
  }

  function renderConveyor(round, entering) {
    const conveyor = $('conveyor');
    conveyor.replaceChildren();
    const inputs = view.inputs || [];
    inputs.slice(round, round + 11).forEach((value, index) => {
      const block = document.createElement('div');
      block.className = `number-block${entering && index === 0 ? ' active' : ''}`;
      block.textContent = value;
      conveyor.append(block);
    });
    if (round >= inputs.length && inputs.length) {
      const block = document.createElement('span');
      block.className = 'quiet'; block.textContent = '本次输入已全部处理'; conveyor.append(block);
    }
  }

  function renderFrame(frame) {
    const left = frame.left || [], right = frame.right || [];
    renderHeap('heapA', left, frame.highlight?.heap === 'A' ? frame.highlight.index : -1);
    renderHeap('heapB', right, frame.highlight?.heap === 'B' ? frame.highlight.index : -1);
    $('sizeA').textContent = `${left.length} 个`;
    $('sizeB').textContent = `${right.length} 个`;
    const checked = frame.checked;
    const round = frame.round || 0;
    renderConveyor(round + (checked ? 1 : 0), frame.entering);
    $('roundLabel').textContent = view.inputs?.length ? `第 ${Math.min(round + 1, view.inputs.length)} / ${view.inputs.length} 轮` : '等待试运行';
    $('currentInput').textContent = frame.x === undefined ? '等待输入' : `x = ${frame.x}`;
    $('median').textContent = frame.median === undefined ? '—' : frame.median;
    $('returned').textContent = checked ? frame.returned : '—';
    $('executionMessage').textContent = frame.message || '';
    $('executionMessage').className = `execution-message${frame.error ? ' error' : frame.success ? ' success' : ''}`;
    $('timelineProgress').style.width = frames.length > 1 ? `${100 * position / (frames.length - 1)}%` : '0%';
    $('operationLog').replaceChildren();
    (frame.log || []).slice(-5).forEach((entry, index, all) => {
      const span = document.createElement('span');
      span.className = `operation-chip${entry.startsWith('B') ? ' b' : ''}${index === all.length - 1 ? ' current' : ''}`;
      span.textContent = entry;
      $('operationLog').append(span);
    });
    updateButtons();
  }

  function buildFrames(execution) {
    const left = [], right = [], output = [], log = [];
    let median;
    const add = (round, values = {}) => output.push({ left: [...left], right: [...right], round, x: execution.rounds[round]?.x, median, log: [...log], ...values });
    add(0, { message: '准备开始：从传送带最左端取出下一个数字。' });
    for (let round = 0; round < execution.rounds.length; round++) {
      const result = execution.rounds[round];
      add(round, { entering: true, message: `取出 ${result.x}，调用 step(${result.x})。` });
      for (const operation of result.operations || []) {
        const heap = operation.heap === 'A' ? left : right;
        const higher = operation.heap === 'A' ? (a, b) => a > b : (a, b) => a < b;
        const label = `${operation.heap}.${operation.type}(${operation.type === 'insert' ? operation.value : ''})`;
        log.push(label);
        const highlight = (index) => ({ heap: operation.heap, index });
        if (operation.type === 'insert') {
          heap.push(operation.value);
          let at = heap.length - 1;
          add(round, { message: `${label}：把 ${operation.value} 放到末尾。`, highlight: highlight(at) });
          while (at > 0) {
            const parent = Math.floor((at - 1) / 2);
            if (!higher(heap[at], heap[parent])) break;
            [heap[at], heap[parent]] = [heap[parent], heap[at]];
            at = parent;
            add(round, { message: `${operation.heap} 中的新节点上浮，恢复堆序。`, highlight: highlight(at) });
          }
        } else if (operation.type === 'pop') {
          const last = heap.pop();
          if (heap.length) heap[0] = last;
          add(round, { message: `${label}：删除堆顶 ${operation.value}，由末尾节点补位。`, highlight: highlight(0) });
          let at = 0;
          while (2 * at + 1 < heap.length) {
            let child = 2 * at + 1;
            if (child + 1 < heap.length && higher(heap[child + 1], heap[child])) child++;
            if (!higher(heap[child], heap[at])) break;
            [heap[at], heap[child]] = [heap[child], heap[at]];
            at = child;
            add(round, { message: `${operation.heap} 的补位节点下沉，恢复堆序。`, highlight: highlight(at) });
          }
        } else if (operation.type === 'size') {
          add(round, { message: `${label}：当前有 ${operation.value} 个元素。` });
        } else {
          add(round, { message: `${label}：读到堆顶 ${operation.value}。`, highlight: highlight(0) });
        }
        if (output.length >= 5000) break;
      }
      left.splice(0, left.length, ...(result.left_heap || []));
      right.splice(0, right.length, ...(result.right_heap || []));
      median = result.expected;
      add(round, { checked: true, returned: result.returned ?? '未返回', error: !result.passed, success: result.passed, message: result.passed ? `第 ${round + 1} 轮通过，返回 ${result.returned}。` : `第 ${round + 1} 轮停止：${result.feedback}。应返回 ${result.expected}，${result.returned == null ? '函数未能返回。' : `实际返回 ${result.returned}。`}` });
      if (!result.passed || output.length >= 5000) break;
    }
    if (execution.passed === execution.total && output.length) output[output.length - 1].message = `全部 ${execution.total} 轮通过。`;
    return output;
  }

  function stopPlayback() { playing = false; clearTimeout(timer); updateButtons(); }
  function tick() {
    if (!playing || position >= frames.length - 1) { stopPlayback(); return; }
    position++;
    renderFrame(frames[position]);
    if (frames[position].error || position >= frames.length - 1) { stopPlayback(); return; }
    timer = setTimeout(tick, 650 / speed);
  }
  function play() { if (position >= frames.length - 1) position = 0; playing = true; updateButtons(); timer = setTimeout(tick, 300 / speed); }
  function preparePlayback(execution, autoplay) {
    stopPlayback();
    frames = buildFrames(execution);
    position = 0;
    renderFrame(frames[0]);
    if (autoplay) play();
  }

  async function runCode(autoplay = true) {
    const source = code.getValue();
    const data = await api('actions', { command_id: uuid(), expected_seq: seq, action: { type: 'run_code', source } });
    seq = data.seq;
    view = data.view;
    lastRunSource = source;
    const execution = view.execution;
    if (execution?.error) {
      message(execution.error);
      stopPlayback();
      if (execution.rounds?.length) {
        preparePlayback(execution, autoplay);
        return false;
      }
      frames = [];
      renderFrame({ left: [], right: [], round: 0, error: true, message: '试运行未能完成，请根据右侧提示修改代码。' });
      return false;
    }
    if (!execution?.rounds?.length) throw new Error('本次试运行没有返回可播放的堆操作记录。');
    message(`真实执行完成：连续通过 ${execution.passed}/${execution.total} 轮。${execution.passed < execution.total ? '播放会在首个错误处停止，并标注原因。' : '现在可以提交作业。'}`, execution.passed === execution.total);
    preparePlayback(execution, autoplay);
    return true;
  }

  async function performRun() {
    if (busy) return;
    busy = true; stopPlayback(); updateButtons(); message('正在编译并运行 C++ 代码…', true);
    try { await runCode(); } catch (error) { message(error.message); }
    finally { busy = false; updateButtons(); }
  }

  async function pollResult() {
    clearTimeout(pollTimer);
    try {
      const data = await api('result');
      const result = data.result || data.grade || data;
      const current = data.status || status;
      status = current;
      $('resultCard').hidden = false;
      if (result.score_bp != null || result.score != null) {
        $('resultTitle').textContent = '作业已评分';
        $('resultFeedback').textContent = result.feedback || '评分结果已经保存到本次作业。';
        const score = result.score_bp !== undefined ? result.score_bp / 100 : Number(result.score);
        $('resultScore').textContent = `${Number(score.toFixed(2))} 分`;
        status = 'graded';
      } else if (current === 'error') {
        $('resultTitle').textContent = '评分暂时失败';
        $('resultFeedback').textContent = result.feedback || data.error || '提交记录已保留，可点击“重试评分”。';
      } else {
        $('resultTitle').textContent = '作业已提交，正在评分';
        $('resultFeedback').textContent = '平台正在使用隐藏数据重新执行你的代码，成绩会自动显示在这里。';
        pollTimer = setTimeout(pollResult, 2000);
      }
      setBadge(data); updateButtons();
    } catch (error) {
      message(`结果查询暂时失败：${error.message}`);
      pollTimer = setTimeout(pollResult, 4000);
    }
  }

  async function submit() {
    if (busy) return;
    busy = true; stopPlayback(); updateButtons(); message('正在保存当前代码并提交…', true);
    try {
      if (status === 'active' && code.getValue() !== lastRunSource) await runCode(false);
      const data = await api('submit', { request_id: uuid(), expected_seq: seq });
      status = data.status || 'grading';
      message('当前代码已冻结并提交，平台将使用隐藏数据重新评分。', true);
      setBadge(data);
      await pollResult();
    } catch (error) { message(error.message); }
    finally { busy = false; updateButtons(); }
  }

  $('runButton').addEventListener('click', performRun);
  $('submitButton').addEventListener('click', submit);
  $('resetButton').addEventListener('click', () => { code.setValue(starter); message('已恢复初始代码。', true); });
  $('playButton').addEventListener('click', () => { if (playing) stopPlayback(); else play(); });
  $('nextButton').addEventListener('click', () => { stopPlayback(); if (position < frames.length - 1) renderFrame(frames[++position]); });
  $('replayButton').addEventListener('click', () => { stopPlayback(); position = 0; renderFrame(frames[0]); play(); });
  $('speedButton').addEventListener('click', () => { speed = speeds[(speeds.indexOf(speed) + 1) % speeds.length]; $('speedButton').textContent = `${speed}× 速度`; });
  function showTask() {
    const panel = $('taskInstructions');
    const overlay = $('taskOverlay');
    const button = $('acknowledgeButton');
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    let acknowledged = false;
    function dockTask() {
      if (acknowledged) return;
      acknowledged = true;
      const before = panel.getBoundingClientRect();
      document.body.style.overflow = previousOverflow;
      button.hidden = true;
      panel.classList.add('docked');
      panel.removeAttribute('role');
      panel.removeAttribute('aria-modal');
      $('instructionDock').append(panel);
      const after = panel.getBoundingClientRect();
      const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      if (!reducedMotion && panel.animate && after.width && after.height) {
        panel.style.zIndex = '1001';
        const motion = panel.animate([
          { transform: `translate(${before.left - after.left}px, ${before.top - after.top}px) scale(${before.width / after.width}, ${before.height / after.height})` },
          { transform: 'none' },
        ], { duration: 520, easing: 'cubic-bezier(.22,1,.36,1)' });
        panel.style.transformOrigin = 'top left';
        const finishMotion = () => { panel.style.zIndex = ''; panel.style.transformOrigin = ''; };
        motion.finished.then(finishMotion, finishMotion);
        const fade = overlay.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 180 });
        overlay.style.pointerEvents = 'none';
        const finishFade = () => { overlay.hidden = true; };
        fade.finished.then(finishFade, finishFade);
      } else overlay.hidden = true;
      code?.focus();
    }
    button.addEventListener('click', dockTask);
    overlay.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') { event.preventDefault(); dockTask(); }
      if (event.key === 'Tab') { event.preventDefault(); button.focus(); }
    });
    button.focus();
  }
  showTask();
  try {
    code = window.NumOJEduEditor.create($('code'), { onRun: performRun });
    $('editorLoading').hidden = true;
  } catch (error) {
    status = 'unavailable';
    $('editorLoading').textContent = '代码编辑器加载失败，请刷新页面重试。';
    message('代码编辑器未能加载，请刷新页面重试。');
    updateButtons();
    return;
  }
  loadState().catch((error) => { status = 'unavailable'; message(error.message); $('assignmentBadge').textContent = '● 未连接作答'; updateButtons(); });
})();
