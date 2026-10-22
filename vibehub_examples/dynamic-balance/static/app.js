(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let code;
  let attemptId = '';
  let seq = 0;
  let status = 'loading';
  let view = {};
  let starter = $('starterSource')?.textContent.trim() || '';
  if (starter) starter += '\n';
  let lastRunSource = '';
  let busy = false;
  let submitting = false;
  let frames = [];
  let position = 0;
  let playing = false;
  let speed = 1;
  let timer = null;
  let pollTimer = null;
  let resultGeneration = 0;
  let continuationRequest = null;
  let transitioning = false;
  let playbackGeneration = 0;
  const speeds = [1, 2, 4, 0.5];
  const base = new URL('./', window.location.href);
  const uuid = () => {
    if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
    const bytes = new Uint8Array(16);
    if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
    else bytes.forEach((_value, index) => { bytes[index] = Math.floor(Math.random() * 256); });
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const text = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
    return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`;
  };
  const endpoint = (name) => new URL(`_edu/v1/${name}`, base).href;
  const heapMotion = window.NumOJHeapMotion.create({
    heapA: $('heapA'), heapB: $('heapB'), conveyor: $('conveyor'),
    inputs: () => view.inputs || [],
    reducedMotion: () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches || false,
  });

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
    const error = good ? '' : text || '';
    $('codeMessage').textContent = error;
    $('codeMessage').className = `code-message${error ? ' visible' : ''}`;
  }

  function resultPending() {
    $('resultCard').hidden = false;
    $('resultCard').classList.add('is-grading');
    $('resultCard').setAttribute('aria-busy', 'true');
    $('resultTitle').textContent = '正在评测';
    $('resultFeedback').textContent = '';
    $('resultScore').textContent = '评测中';
  }

  function resultSettled(title, feedback = '', score = '—') {
    $('resultCard').hidden = false;
    $('resultCard').classList.remove('is-grading');
    $('resultCard').setAttribute('aria-busy', 'false');
    $('resultTitle').textContent = title;
    $('resultFeedback').textContent = feedback;
    $('resultScore').textContent = score;
  }

  function updateButtons() {
    const canAttempt = ['active', 'graded', 'error'].includes(status);
    const editable = canAttempt || ['preview', 'submitted', 'grading'].includes(status);
    $('runButton').disabled = busy || !canAttempt;
    $('submitButton').disabled = busy || !canAttempt;
    $('submitButton').textContent = '提交作业 ↗';
    $('resetButton').disabled = !editable;
    code?.updateOptions({ readOnly: !editable, domReadOnly: !editable });
    $('runButton').innerHTML = busy ? '<span>◌</span> 正在执行' : '<span>▶</span> 试运行';
    $('playButton').disabled = busy || !frames.length;
    $('nextButton').disabled = busy || !frames.length || position >= frames.length - 1 || Boolean(frames[position]?.error);
    $('replayButton').disabled = busy || !frames.length;
    $('playButton').textContent = playing ? 'Ⅱ' : '▶';
  }

  async function loadState(restoreCode = true) {
    const data = await api('state');
    stopResultPolling();
    attemptId = data.attempt_id || attemptId;
    if (continuationRequest?.expected_attempt_id !== attemptId) continuationRequest = null;
    seq = data.seq ?? 0;
    status = data.status || 'active';
    if (['submitted', 'grading'].includes(status)) resultPending();
    view = data.view || data.data?.view || {};
    if (view.initial_source) starter = view.initial_source;
    else if (!starter) starter = view.source || '';
    if (restoreCode) {
      code.setValue(view.source || starter);
    }
    lastRunSource = view.execution ? (view.source || '') : '';
    if (view.execution?.rounds?.length) preparePlayback(view.execution, false);
    else renderFrame({ left: [], right: [], round: 0, message: '等待试运行' });
    updateButtons();
    if (['submitted', 'grading', 'graded', 'error'].includes(status)) void pollResult(resultGeneration);
    return data;
  }

  function renderFrame(frame, animate = true) {
    const rendered = heapMotion.render(frame, { animate });
    const error = frame.error ? frame.message || '' : '';
    $('statusLine').hidden = !error;
    $('statusText').textContent = error;
    updateButtons();
    return rendered;
  }

  function stopPlayback() {
    playing = false;
    clearTimeout(timer);
    timer = null;
    heapMotion.pause();
    updateButtons();
  }

  function restartPlayback() {
    clearTimeout(timer);
    timer = null;
    playbackGeneration++;
    transitioning = false;
    heapMotion.reset();
    position = 0;
    if (frames.length) renderFrame(frames[0], false);
  }

  async function advance() {
    if (transitioning || !frames.length || position >= frames.length - 1 || frames[position]?.error) return;
    const generation = playbackGeneration;
    const frame = frames[++position];
    transitioning = true;
    await renderFrame(frame);
    if (generation !== playbackGeneration) return;
    transitioning = false;
    if (frame.error || position >= frames.length - 1) { stopPlayback(); return; }
    if (playing) {
      const hold = frame.motion?.kind === 'swap' ? 25 : frame.motion?.kind === 'idle' ? 140 : 90;
      timer = setTimeout(tick, hold / speed);
    }
  }

  function tick() {
    timer = null;
    if (!playing || transitioning || position >= frames.length - 1) return;
    void advance();
  }

  function play() {
    if (!frames.length) return;
    if (position >= frames.length - 1 || frames[position]?.error) restartPlayback();
    playing = true;
    heapMotion.resume();
    updateButtons();
    if (!transitioning) {
      clearTimeout(timer);
      timer = setTimeout(tick, 180 / speed);
    }
  }

  function preparePlayback(execution, autoplay) {
    stopPlayback();
    frames = window.NumOJHeapPlayback.buildFrames(execution);
    restartPlayback();
    if (autoplay) play();
  }

  function stopResultPolling() {
    resultGeneration++;
    clearTimeout(pollTimer);
    pollTimer = null;
  }

  async function ensureActiveAttempt() {
    if (status === 'active') return;
    if (!['graded', 'error'].includes(status)) throw new Error('上一次作答仍在评测，请等待完成后再试。');
    if (!attemptId) throw new Error('作答信息尚未加载，请刷新页面重试。');
    if (!continuationRequest || continuationRequest.expected_attempt_id !== attemptId) {
      continuationRequest = { request_id: uuid(), expected_attempt_id: attemptId };
    }
    stopResultPolling();
    const data = await api('continue', continuationRequest);
    attemptId = data.attempt_id;
    seq = data.seq;
    status = data.status;
    view = data.view;
    continuationRequest = null;
    lastRunSource = '';
    if (submitting) resultPending();
    else $('resultCard').hidden = true;
    frames = [];
    restartPlayback();
    renderFrame({ left: [], right: [], round: 0 }, false);
    if (status !== 'active') {
      if (['submitted', 'grading', 'graded', 'error'].includes(status)) void pollResult(resultGeneration);
      throw new Error('作答状态已变化，请重试。');
    }
  }

  async function runCode(autoplay = true, source = code.getValue()) {
    await ensureActiveAttempt();
    const data = await api('actions', { command_id: uuid(), expected_seq: seq, action: { type: 'run_code', source } });
    seq = data.seq;
    view = data.view;
    lastRunSource = source;
    const execution = view.execution;
    if (execution?.error) {
      stopPlayback();
      if (execution.rounds?.length) {
        message('');
        preparePlayback(execution, autoplay);
        return false;
      }
      message(execution.error);
      frames = [];
      restartPlayback();
      renderFrame({ left: [], right: [], round: 0 });
      return false;
    }
    if (!execution?.rounds?.length) throw new Error('本次试运行没有返回可播放的堆操作记录。');
    message('');
    preparePlayback(execution, autoplay);
    return true;
  }

  async function performRun() {
    if (busy || !['active', 'graded', 'error'].includes(status)) return;
    busy = true; stopPlayback(); updateButtons(); message('正在编译并运行 C++ 代码…', true);
    try { await runCode(); } catch (error) { message(error.message); }
    finally { busy = false; updateButtons(); }
  }

  async function pollResult(generation = resultGeneration) {
    if (generation !== resultGeneration) return;
    clearTimeout(pollTimer);
    pollTimer = null;
    try {
      const data = await api('result');
      if (generation !== resultGeneration) return;
      const result = data.result || data.grade || data;
      const current = data.status || status;
      const hasScore = result.score_bp != null || result.score != null;
      if (current === 'submitted' || current === 'grading') {
        status = current;
        resultPending();
        pollTimer = setTimeout(() => pollResult(generation), 2000);
      } else if (current === 'error') {
        status = current;
        resultSettled('评分暂时失败', data.error || (!hasScore && result.feedback)
          || '提交记录已保留，可再次提交重试。');
      } else if (current === 'graded' && hasScore) {
        const score = result.score_bp !== undefined ? result.score_bp / 100 : Number(result.score);
        resultSettled('作业已评分', result.feedback || '评分结果已经保存到本次作业。', `${Number(score.toFixed(2))} 分`);
        status = 'graded';
      } else {
        status = 'grading';
        resultPending();
        pollTimer = setTimeout(() => pollResult(generation), 2000);
      }
      updateButtons();
    } catch (error) {
      if (generation !== resultGeneration) return;
      message(`结果查询暂时失败：${error.message}`);
      pollTimer = setTimeout(() => pollResult(generation), 4000);
    }
  }

  async function submit() {
    if (busy || !['active', 'graded', 'error'].includes(status)) return;
    const source = code.getValue();
    submitting = true;
    resultPending();
    busy = true; stopPlayback(); updateButtons(); message('正在提交…', true);
    stopResultPolling();
    try {
      if (source !== lastRunSource) await runCode(false, source);
      const data = await api('submit', { request_id: uuid(), expected_seq: seq });
      status = data.status || 'grading';
      resultPending();
      message('作业已提交。', true);
      await pollResult(resultGeneration);
    } catch (error) {
      if (!['submitted', 'grading'].includes(status)) {
        stopResultPolling();
        resultSettled('提交未完成');
      }
      message(error.message);
    }
    finally { submitting = false; busy = false; updateButtons(); }
  }

  $('runButton').addEventListener('click', performRun);
  $('submitButton').addEventListener('click', submit);
  $('resetButton').addEventListener('click', () => { code.setValue(starter); message('已恢复初始代码。', true); });
  $('playButton').addEventListener('click', () => { if (!busy) { if (playing) stopPlayback(); else play(); } });
  $('nextButton').addEventListener('click', () => {
    if (busy) return;
    stopPlayback();
    if (transitioning) heapMotion.finish();
    else void advance();
  });
  $('replayButton').addEventListener('click', () => { if (!busy && frames.length) { stopPlayback(); restartPlayback(); play(); } });
  $('speedButton').addEventListener('click', () => {
    speed = speeds[(speeds.indexOf(speed) + 1) % speeds.length];
    heapMotion.setSpeed(speed);
    $('speedButton').textContent = `${speed}× 速度`;
    if (playing && !transitioning) { clearTimeout(timer); timer = setTimeout(tick, 90 / speed); }
  });
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
    code.setValue(starter);
    $('editorLoading').hidden = true;
  } catch (error) {
    status = 'unavailable';
    $('editorLoading').textContent = '代码编辑器加载失败，请刷新页面重试。';
    message('代码编辑器未能加载，请刷新页面重试。');
    updateButtons();
    return;
  }
  if (base.protocol === 'file:') {
    status = 'preview';
    renderFrame({ left: [], right: [], round: 0, message: '等待试运行' });
    updateButtons();
  } else {
    loadState().catch((error) => { status = 'unavailable'; message(error.message); updateButtons(); });
  }
})();
