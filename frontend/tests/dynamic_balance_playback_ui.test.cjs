const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { JSDOM, VirtualConsole } = require('jsdom');

const directory = path.resolve(__dirname, '../../vibehub_examples/dynamic-balance/static');
const html = fs.readFileSync(path.join(directory, 'index.html'), 'utf8');
const SOURCE_A = 'double step(int x) { A.insert(x); return A.top(); } // saved A';
const SOURCE_B = 'double step(int x) { B.insert(x); return B.top(); } // other tab B';
const operation = (heap, type, value) => ({ heap, type, value });

function executionFixture(shift = 0) {
  const execution = { compiled: true, passed: 3, total: 5, rounds: [
    { x: 4, expected: 4, returned: 4, passed: true, left_heap: [4], right_heap: [],
      operations: [operation('A', 'insert', 4), operation('A', 'top', 4)] },
    { x: 9, expected: 6.5, returned: 6.5, passed: true, left_heap: [4], right_heap: [9],
      operations: [operation('B', 'insert', 9), operation('A', 'top', 4), operation('B', 'top', 9)] },
    { x: 7, expected: 7, returned: 7, passed: true, left_heap: [7, 4], right_heap: [9],
      operations: [operation('B', 'insert', 7), operation('B', 'pop', 7), operation('A', 'insert', 7), operation('A', 'top', 7)] },
    { x: 2, expected: 5.5, returned: 0, passed: false, left_heap: [4, 2], right_heap: [7, 9],
      operations: [operation('A', 'insert', 2), operation('A', 'pop', 7), operation('B', 'insert', 7), operation('A', 'top', 4)] },
    { x: 8, expected: 7, returned: 7, passed: true, left_heap: [7, 2, 4], right_heap: [8, 9],
      operations: [operation('B', 'insert', 8), operation('B', 'pop', 7), operation('A', 'insert', 7)] },
  ] };
  if (shift) for (const round of execution.rounds) {
    round.x += shift;
    round.expected += shift;
    round.returned += shift;
    round.left_heap = round.left_heap.map(value => value + shift);
    round.right_heap = round.right_heap.map(value => value + shift);
    round.operations.forEach(operation => { operation.value += shift; });
  }
  return execution;
}

async function flush() {
  await new Promise(setImmediate);
}

function controlledClock(window) {
  let now = 0, sequence = 0;
  const timers = new Map();
  window.setTimeout = (callback, delay = 0, ...args) => {
    const id = ++sequence;
    timers.set(id, { due: now + Math.max(0, Number(delay) || 0), callback: () => callback(...args) });
    return id;
  };
  window.clearTimeout = id => timers.delete(id);
  window.requestAnimationFrame = callback => window.setTimeout(() => callback(now), 16);
  window.cancelAnimationFrame = window.clearTimeout;
  Object.defineProperty(window.performance, 'now', { value: () => now });
  const next = () => [...timers].sort((a, b) => a[1].due - b[1].due || a[0] - b[0])[0];
  async function advance(milliseconds) {
    const target = now + milliseconds;
    let iterations = 0;
    while (next()?.[1].due <= target) {
      assert.ok(iterations++ < 10000, '动画调度不能产生无限定时器');
      const [id, timer] = next();
      now = timer.due;
      timers.delete(id);
      timer.callback();
      await flush();
    }
    now = target;
    await flush();
  }
  async function until(predicate) {
    let iterations = 0;
    await flush();
    while (!predicate()) {
      assert.ok(iterations++ < 1000, '应在有限帧内到达目标状态');
      const timer = next();
      assert.ok(timer, '到达目标前调度器意外停止');
      await advance(Math.max(0, timer[1].due - now));
    }
  }
  async function drain() {
    await until(() => timers.size === 0);
    await flush();
    assert.equal(timers.size, 0);
  }
  return { get now() { return now; }, timers, advance, until, drain };
}

function installAnimations(window, clock) {
  const animations = [];
  class Animation {
    constructor(element, keyframes, options) {
      this.element = element;
      this.keyframes = keyframes;
      this.duration = typeof options === 'number' ? options : Number(options?.duration) || 0;
      this._time = 0;
      this._rate = 1;
      this.started = clock.now;
      this.playState = 'running';
      this.pauseCalls = this.playCalls = this.finishCalls = this.cancelCalls = 0;
      this.rateCalls = [];
      this.listeners = new Map();
      this.finished = new window.Promise((resolve, reject) => { this.resolve = resolve; this.reject = reject; });
      this.finished.catch(() => {});
      this.effect = { getTiming: () => ({ duration: this.duration }),
        getComputedTiming: () => ({ duration: this.duration, progress: this.duration ? this.currentTime / this.duration : 1 }) };
      animations.push(this);
      this.schedule();
    }
    get currentTime() { return Math.min(this.duration, this._time + (this.playState === 'running' ? (clock.now - this.started) * this._rate : 0)); }
    set currentTime(value) { this._time = Number(value) || 0; this.started = clock.now; this.schedule(); }
    get playbackRate() { return this._rate; }
    set playbackRate(value) {
      this._time = this.currentTime;
      this.started = clock.now;
      this._rate = value;
      this.schedule();
    }
    schedule() {
      window.clearTimeout(this.timer);
      if (this.playState === 'running') this.timer = window.setTimeout(() => this.complete(),
        Math.max(0, this.duration - this._time) / this._rate);
    }
    complete() {
      if (this.playState !== 'running') return;
      this._time = this.duration;
      this.playState = 'finished';
      window.clearTimeout(this.timer);
      this.resolve(this);
      this.onfinish?.();
      this.listeners.get('finish')?.();
    }
    pause() {
      this.pauseCalls++;
      this._time = this.currentTime;
      this.playState = 'paused';
      window.clearTimeout(this.timer);
    }
    play() {
      this.playCalls++;
      this.started = clock.now;
      this.playState = 'running';
      this.schedule();
    }
    finish() {
      this.finishCalls++;
      if (this.playState === 'finished' || this.playState === 'idle') return;
      this.playState = 'running';
      this.complete();
    }
    cancel() {
      this.cancelCalls++;
      window.clearTimeout(this.timer);
      if (this.playState !== 'finished' && this.playState !== 'idle') this.reject(new window.DOMException('cancelled', 'AbortError'));
      this.playState = 'idle';
      this.oncancel?.();
    }
    updatePlaybackRate(value) { this.rateCalls.push(value); this.playbackRate = value; }
    commitStyles() {}
    addEventListener(name, callback) { this.listeners.set(name, callback); }
    removeEventListener(name) { this.listeners.delete(name); }
  }
  window.Element.prototype.animate = function (keyframes, options) { return new Animation(this, keyframes, options); };
  window.Element.prototype.getAnimations = function () { return animations.filter(animation => animation.element === this && ['running', 'paused'].includes(animation.playState)); };
  return animations;
}

function installGeometry(window) {
  window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  window.ResizeObserver = class { observe() {} disconnect() {} };
  window.Element.prototype.getBoundingClientRect = function () {
    let left = 20, top = 40, width = 500, height = 400;
    if (this.id === 'heapA' || this.id === 'heapB') {
      left = this.id === 'heapA' ? 20 : 440; top = 150; width = 400; height = 245;
    } else if (this.classList.contains('number-block')) {
      const transform = /translate(?:3d|X)?\(\s*(-?[\d.]+)px/.exec(this.style.transform);
      left += Number(transform?.[1] || 0); width = 46; height = 46;
    }
    return { x: left, y: top, left, top, width, height, right: left + width, bottom: top + height };
  };
}

async function boot(t, { url = 'https://example.test/vibehub/runtime/test/', initialExecution = false,
  initialStatus = 'active', deferInitialResult = false, insecureCrypto = false,
  resultMode = 'graded', resultFields = {} } = {}) {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', error => errors.push(error));
  const dom = new JSDOM(html, { url, runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole });
  t.after(() => { dom.window.close(); assert.deepEqual(errors, [], '真实页面脚本不应抛出 DOM 错误'); });
  const { window } = dom;
  window.document.querySelectorAll('script[src]').forEach(script => script.remove());
  const element = id => window.document.getElementById(id);
  const clock = controlledClock(window);
  installGeometry(window);
  const animations = installAnimations(window, clock);
  const calls = [], editorValues = [], renders = [], built = [];
  const starter = element('starterSource').textContent.trim() + '\n';
  const server = { attempt_id: 'att_1', seq: 1, source: SOURCE_A, status: initialStatus,
    inputs: [4, 9, 7, 2, 8], execution: initialExecution ? executionFixture() : null,
    attemptCount: 1, submissions: [], continuations: new Map(), continueFailures: 0,
    resultMode, resultFields, deferNextResult: deferInitialResult, pendingResults: [],
    deferNextAction: false, pendingActions: [], submitFailures: 0,
    deferNextSubmit: false, pendingSubmits: [] };
  if (initialStatus !== 'active') server.submissions.push(Object.freeze({ id: 11,
    attempt_id: server.attempt_id, source: server.source, seq: server.seq }));
  let uuidCounter = 0;
  Object.defineProperty(window.crypto, 'randomUUID', {
    value: insecureCrypto ? undefined : () => `00000000-0000-4000-8000-${String(++uuidCounter).padStart(12, '0')}`,
  });
  let editorValue = '', onRun;
  const editor = { getValue: () => editorValue,
    setValue: value => { editorValue = value; editorValues.push(value); }, focus() {},
    updateOptions: options => { editor.readOnly = options.readOnly; } };
  window.NumOJEduEditor = { create: (_host, options) => { onRun = options.onRun; return editor; } };
  const snapshot = () => ({ success: true, attempt_id: server.attempt_id, seq: server.seq, status: server.status,
    view: { source: server.source, initial_source: starter, inputs: server.inputs, execution: server.execution } });
  const response = (status, data) => ({ ok: status >= 200 && status < 300, status, json: async () => structuredClone(data) });
  window.fetch = async (url, options) => {
    assert.equal(editorValues[0], starter, '首次请求之前就应显示默认代码');
    const operation = new URL(url).pathname.split('/').pop();
    const payload = options.body ? JSON.parse(options.body) : null;
    calls.push({ operation, payload });
    if (operation === 'state') return response(200, snapshot());
    if (operation === 'actions') {
      if (payload.expected_seq !== server.seq || server.status !== 'active') return response(409, { success: false, message: '操作并发冲突' });
      server.source = payload.action.source;
      server.seq++;
      server.execution = executionFixture(10 * (server.attemptCount - 1));
      if (server.deferNextAction) {
        server.deferNextAction = false;
        const captured = snapshot();
        return new Promise(resolve => server.pendingActions.push({ attempt_id: server.attempt_id,
          resolve: () => resolve(response(200, captured)) }));
      }
      return response(200, snapshot());
    }
    if (operation === 'continue') {
      assert.deepEqual(Object.keys(payload).sort(), ['expected_attempt_id', 'request_id']);
      assert.match(payload.request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
      const previous = server.continuations.get(payload.request_id);
      if (previous) {
        assert.equal(payload.expected_attempt_id, previous.expected_attempt_id);
        return response(200, previous.state);
      }
      assert.equal(payload.expected_attempt_id, server.attempt_id);
      assert.ok(['graded', 'error'].includes(server.status), '评分完成或失败后才允许继续');
      server.attempt_id = `att_${++server.attemptCount}`;
      server.seq = 0;
      server.status = 'active';
      server.source = starter;
      server.inputs = [4, 9, 7, 2, 8].map(value => value + 10 * (server.attemptCount - 1));
      server.execution = null;
      const state = structuredClone(snapshot());
      server.continuations.set(payload.request_id, { expected_attempt_id: payload.expected_attempt_id, state });
      if (server.continueFailures > 0) {
        server.continueFailures--;
        throw new TypeError('Failed to fetch after continue committed');
      }
      return response(200, state);
    }
    if (operation === 'submit') {
      if (server.submitFailures > 0) {
        server.submitFailures--;
        throw new TypeError('Failed to fetch during submit');
      }
      assert.equal(payload.expected_seq, server.seq);
      let frozen = server.submissions.find(submission => submission.attempt_id === server.attempt_id);
      if (!frozen) {
        frozen = Object.freeze({ id: 11 + server.submissions.length, attempt_id: server.attempt_id,
          source: server.source, seq: server.seq });
        server.submissions.push(frozen);
      }
      server.status = 'grading';
      const submitted = { success: true, attempt_id: server.attempt_id, submission_id: frozen.id, status: 'grading' };
      if (server.deferNextSubmit) {
        server.deferNextSubmit = false;
        return new Promise(resolve => server.pendingSubmits.push({ resolve: () => resolve(response(200, submitted)) }));
      }
      return response(200, submitted);
    }
    if (operation === 'result') {
      const attempt_id = server.attempt_id;
      const submission = server.submissions.find(submission => submission.attempt_id === attempt_id);
      const result = { success: true, attempt_id, submission_id: submission?.id, status: server.resultMode,
        ...(server.resultMode === 'graded' ? { result: { score_bp: 10000, verdict: 'passed', feedback: '已评分' } } : {}),
        ...server.resultFields };
      if (['graded', 'error'].includes(server.resultMode)) server.status = server.resultMode;
      if (server.deferNextResult) {
        server.deferNextResult = false;
        return new Promise(resolve => server.pendingResults.push({ attempt_id, submission_id: submission?.id,
          resolve: (overrides = {}) => resolve(response(200, { ...result, ...overrides })) }));
      }
      return response(200, result);
    }
    throw new Error('未预期的请求 ' + operation);
  };
  window.eval(fs.readFileSync(path.join(directory, 'playback.js'), 'utf8'));
  const model = window.NumOJHeapPlayback;
  window.NumOJHeapPlayback = { ...model, buildFrames(value) { const frames = model.buildFrames(value); built.push(frames); return frames; } };
  window.eval(fs.readFileSync(path.join(directory, 'heap-motion.js'), 'utf8'));
  const motion = window.NumOJHeapMotion;
  window.NumOJHeapMotion = { ...motion, create(...args) {
    const renderer = motion.create(...args);
    return new Proxy(renderer, { get(target, key) {
      if (key === 'render') return (frame, options) => {
        const record = { frame, start: clock.now, done: false };
        renders.push(record);
        const result = target.render(frame, options);
        Promise.resolve(result).then(() => { record.done = true; record.end = clock.now; });
        return result;
      };
      const value = target[key];
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } };
  window.eval(fs.readFileSync(path.join(directory, 'app.js'), 'utf8'));
  await flush();
  element('acknowledgeButton').click();
  await clock.advance(600);
  renders.length = 0;
  return { window, element, clock, animations, calls, editor, editorValues, starter, server, renders, built,
    onRun: () => onRun(), click: async id => { element(id).click(); await flush(); },
    current: () => renders.at(-1), active: () => animations.filter(animation => animation.playState === 'running') };
}

test('autoplay awaits every actual render, including 200 ms swaps, and stops at the first error', async t => {
  const ui = await boot(t);
  await ui.click('runButton');
  assert.equal(ui.element('statusLine').hidden, true);
  assert.equal(ui.element('statusText').textContent, '');
  assert.equal(ui.element('codeMessage').textContent, '');
  const frames = ui.built.at(-1);
  await ui.clock.until(() => ui.current()?.frame.motion.kind === 'swap' && !ui.current().done);
  const swap = ui.current(), before = ui.renders.length;
  assert.equal(swap.frame.duration, 200);
  await ui.clock.advance(199);
  assert.equal(ui.renders.length, before, '200 ms 交换未完成前不能进入下一帧');
  assert.equal(swap.done, false);
  assert.equal(ui.element('statusLine').hidden, true, '正常调整不应显示状态小字');
  await ui.clock.advance(1);
  assert.equal(swap.done, true);
  assert.ok(swap.end - swap.start >= 200);
  await ui.clock.drain();
  assert.deepEqual(ui.renders.map(record => frames.indexOf(record.frame)), Array.from(frames, (_frame, index) => index));
  assert.equal(ui.current().frame.error, true);
  assert.equal(ui.current().frame.round, 3);
  assert.ok(ui.renders.every(record => record.frame.round < 4));
  assert.equal(ui.element('statusLine').hidden, false);
  assert.match(ui.element('statusText').textContent, /应返回 5\.5，实际返回 0/);
  assert.equal(ui.element('nextButton').disabled, true);
  assert.equal(ui.element('playButton').textContent, '▶');
  assert.equal(ui.active().length, 0);
});

test('pause freezes WAAPI and the scheduler, resume continues, and speed changes active animations', async t => {
  const ui = await boot(t);
  await ui.click('runButton');
  await ui.clock.until(() => ui.current()?.frame.motion.kind === 'insert' && !ui.current().done);
  const current = ui.current(), before = ui.renders.length;
  const active = ui.active();
  assert.ok(active.length > 0);
  await ui.click('playButton');
  assert.ok(active.every(animation => animation.playState === 'paused'));
  await ui.clock.advance(10000);
  assert.equal(ui.renders.length, before);
  assert.equal(current.done, false);
  await ui.click('speedButton');
  assert.ok(active.some(animation => animation.rateCalls.includes(2)));
  await ui.click('playButton');
  assert.ok(active.every(animation => animation.playCalls > 0));
  await ui.clock.drain();
  assert.equal(ui.current().frame.error, true);
  assert.equal(ui.clock.timers.size, 0);
});

test('step finishes an in-flight frame without skipping it and rapid clicks leave no old scheduler', async t => {
  const ui = await boot(t);
  await ui.click('runButton');
  await ui.clock.until(() => ui.current()?.frame.motion.kind === 'insert' && !ui.current().done);
  const frames = ui.built.at(-1), before = ui.renders.length, current = ui.current(), active = ui.active();
  await ui.click('nextButton');
  assert.ok(active.some(animation => animation.finishCalls > 0));
  assert.equal(ui.renders.length, before, '动画中的单步只完成当前帧');
  assert.equal(current.done, true);
  assert.equal(ui.element('playButton').textContent, '▶');
  await ui.click('nextButton');
  assert.equal(ui.renders.length, before + 1);
  assert.equal(frames.indexOf(ui.current().frame), frames.indexOf(current.frame) + 1);
  for (let index = 0; index < 8; index++) ui.element('nextButton').click();
  await flush();
  await ui.clock.drain();
  const sequence = ui.renders.map(record => frames.indexOf(record.frame));
  assert.ok(sequence.every((value, index) => !index || value === sequence[index - 1] + 1));
  assert.equal(ui.element('playButton').textContent, '▶');
  assert.equal(ui.active().length, 0);
});

test('replay during a moving node cancels the old generation and restarts from frame zero once', async t => {
  const ui = await boot(t);
  await ui.click('runButton');
  await ui.clock.until(() => ui.current()?.frame.motion.kind === 'insert' && !ui.current().done);
  const frames = ui.built.at(-1), old = ui.active(), before = ui.renders.length;
  await ui.click('replayButton');
  assert.ok(old.every(animation => ['idle', 'finished'].includes(animation.playState)));
  await ui.clock.drain();
  const replay = ui.renders.slice(before).map(record => frames.indexOf(record.frame));
  assert.deepEqual(replay, Array.from(frames, (_frame, index) => index));
  assert.equal(ui.current().frame.error, true);
  assert.equal(ui.clock.timers.size, 0);
  assert.equal(ui.active().length, 0);
  assert.equal(ui.window.document.querySelectorAll('.heap-flight').length, 0);
});

test('trailing conveyor blocks slide as persistent elements and a transferred heap node keeps its DOM identity', async t => {
  const ui = await boot(t);
  await ui.click('runButton');
  const trailing = ui.element('conveyor').querySelector('[data-input-index="1"]');
  assert.ok(trailing);
  await ui.clock.until(() => ui.current()?.frame.motion.kind === 'insert' && ui.current().frame.round === 0);
  assert.equal(ui.element('conveyor').querySelector('[data-input-index="1"]'), trailing);
  const slide = ui.animations.find(animation => animation.element === trailing && animation.duration === 700);
  assert.ok(slide, '后续方块应沿传送带左滑，而非替换 DOM');
  assert.equal(slide.keyframes[0].transform, 'translate3d(63px, 0, 0)');
  assert.equal(slide.keyframes[1].transform, 'translate3d(0px, 0, 0)');
  assert.equal(ui.window.document.querySelector('.belt-line').style.backgroundPosition, '-63px 0px');
  await ui.clock.until(() => ui.current()?.frame.motion.kind === 'insert'
    && ui.current().frame.motion.heap === 'B' && ui.current().frame.round === 2);
  const id = ui.current().frame.motion.nodeId;
  const group = ui.window.document.querySelector(`[data-node-id="${id}"]`);
  assert.ok(group && ui.element('heapB').contains(group));
  await ui.clock.until(() => ui.current()?.frame.motion.kind === 'insert'
    && ui.current().frame.motion.from?.kind === 'parked' && ui.current().frame.motion.nodeId === id);
  assert.equal(ui.window.document.querySelector(`[data-node-id="${id}"]`), group);
  assert.equal(ui.element('heapA').contains(group), true);
  assert.equal(ui.window.document.querySelectorAll(`[data-node-id="${id}"]`).length, 1);
  await ui.clock.drain();
  assert.equal(ui.active().length, 0);
});

test('file preview shows editable starter and reset while blocking all execution and submission entry points', async t => {
  const ui = await boot(t, { url: 'file://' + path.join(directory, 'index.html') });
  assert.equal(ui.editor.getValue(), ui.starter);
  assert.equal(ui.editor.readOnly, false);
  ui.editor.setValue('locally edited');
  await ui.click('resetButton');
  assert.equal(ui.editor.getValue(), ui.starter);
  assert.equal(ui.element('runButton').disabled, true);
  assert.equal(ui.element('submitButton').disabled, true);
  ui.element('runButton').dispatchEvent(new ui.window.Event('click'));
  ui.element('submitButton').dispatchEvent(new ui.window.Event('click'));
  await ui.onRun();
  await ui.clock.drain();
  assert.deepEqual(ui.calls, []);
  assert.equal(ui.element('resultCard').hidden, true);
});

test('online saved source wins and a 409 keeps editor A before saving it again for submission', async t => {
  const ui = await boot(t, { initialExecution: true });
  assert.equal(ui.editorValues[0], ui.starter);
  assert.equal(ui.editor.getValue(), SOURCE_A);
  ui.server.source = SOURCE_B;
  ui.server.seq = 2;
  await ui.click('runButton');
  assert.equal(ui.editor.getValue(), SOURCE_A);
  assert.equal(ui.server.source, SOURCE_B);
  const before = ui.calls.length;
  await ui.click('submitButton');
  const subsequent = ui.calls.slice(before);
  assert.deepEqual(subsequent.map(call => call.operation), ['actions', 'submit', 'result']);
  assert.equal(subsequent[0].payload.action.source, SOURCE_A);
  assert.equal(subsequent[0].payload.expected_seq, 2);
  assert.equal(subsequent[1].payload.expected_seq, 3);
  assert.equal(ui.server.source, SOURCE_A);
  assert.equal(ui.element('resultScore').textContent, '100 分');
  await ui.clock.drain();
});

test('a graded submission stays immutable while the editor can run and submit a new draft', async t => {
  const ui = await boot(t, { initialExecution: true });
  await ui.click('submitButton');
  assert.equal(ui.server.submissions.length, 1);
  const original = structuredClone(ui.server.submissions[0]);
  assert.equal(original.source, SOURCE_A);
  assert.equal(ui.editor.readOnly, false);
  assert.equal(ui.element('runButton').disabled, false);
  assert.equal(ui.element('submitButton').disabled, false);
  ui.editor.setValue(SOURCE_B);
  const before = ui.calls.length;
  await ui.click('runButton');
  assert.deepEqual(ui.calls.slice(before).map(call => call.operation), ['continue', 'actions']);
  assert.equal(ui.calls[before].payload.expected_attempt_id, original.attempt_id);
  assert.equal(ui.calls[before + 1].payload.expected_seq, 0);
  assert.equal(ui.calls[before + 1].payload.action.source, SOURCE_B);
  assert.equal(ui.editor.getValue(), SOURCE_B, '新 start 的初始代码不能覆盖当前草稿');
  assert.equal(ui.server.attempt_id, 'att_2');
  assert.equal(ui.server.inputs[0], 14);
  assert.equal(ui.server.seq, 1);
  assert.equal(ui.server.source, SOURCE_B);
  assert.equal(ui.element('resultCard').hidden, true);
  const beforeSubmit = ui.calls.length;
  await ui.click('submitButton');
  assert.deepEqual(ui.calls.slice(beforeSubmit).map(call => call.operation), ['submit', 'result']);
  assert.equal(ui.server.submissions.length, 2);
  assert.deepEqual(ui.server.submissions[0], original);
  assert.equal(ui.server.submissions[1].source, SOURCE_B);
  assert.equal(ui.server.submissions[1].attempt_id, 'att_2');
  assert.equal(ui.server.submissions[1].seq, 1, '新作答必须先保存一次 run_code 才提交');
  assert.equal(ui.editor.readOnly, false);
  await ui.clock.drain();
});

for (const terminal of ['graded', 'error']) test(`grading permits editing but blocks another attempt until ${terminal}`, async t => {
  const ui = await boot(t, { initialExecution: true });
  ui.server.resultMode = 'grading';
  await ui.click('submitButton');
  const original = structuredClone(ui.server.submissions[0]);
  assert.equal(ui.editor.readOnly, false);
  assert.equal(ui.element('resetButton').disabled, false);
  assert.equal(ui.element('runButton').disabled, true);
  assert.equal(ui.element('submitButton').disabled, true);
  ui.editor.setValue(SOURCE_B);
  const beforeBlockedClicks = ui.calls.length;
  ui.element('runButton').dispatchEvent(new ui.window.Event('click'));
  ui.element('submitButton').dispatchEvent(new ui.window.Event('click'));
  await ui.onRun();
  await flush();
  assert.equal(ui.calls.length, beforeBlockedClicks, '未完成评分时事件或快捷键也不能绕过等待');
  assert.equal(ui.server.attemptCount, 1);
  assert.equal(ui.editor.getValue(), SOURCE_B);
  assert.deepEqual(ui.server.submissions[0], original);
  ui.server.resultMode = terminal;
  await ui.clock.advance(2000);
  assert.equal(ui.element('runButton').disabled, false);
  assert.equal(ui.element('submitButton').disabled, false);
  assert.equal(ui.editor.readOnly, false);
  await ui.click('runButton');
  assert.equal(ui.editor.getValue(), SOURCE_B);
  assert.equal(ui.server.attempt_id, 'att_2');
  assert.equal(ui.server.status, 'active');
  assert.deepEqual(ui.server.submissions[0], original);
  const resultRequests = ui.calls.filter(call => call.operation === 'result').length;
  await ui.clock.drain();
  assert.equal(ui.calls.filter(call => call.operation === 'result').length, resultRequests,
    '继续新作答后不能留下旧作答的定时轮询');
  assert.equal(ui.editor.readOnly, false);
  assert.equal(ui.element('submitButton').disabled, false);
});

test('a submitted state stays editable while polling but cannot continue before its terminal result', async t => {
  const ui = await boot(t, { initialExecution: true, initialStatus: 'submitted', deferInitialResult: true });
  assert.equal(ui.editor.readOnly, false);
  assert.equal(ui.element('runButton').disabled, true);
  assert.equal(ui.element('submitButton').disabled, true);
  ui.editor.setValue(SOURCE_B);
  const before = ui.calls.length;
  ui.element('runButton').dispatchEvent(new ui.window.Event('click'));
  ui.element('submitButton').dispatchEvent(new ui.window.Event('click'));
  await ui.onRun();
  await flush();
  assert.equal(ui.calls.length, before);
  assert.equal(ui.server.attemptCount, 1);
  ui.server.pendingResults[0].resolve();
  await flush();
  assert.equal(ui.element('runButton').disabled, false);
  assert.equal(ui.element('submitButton').disabled, false);
  assert.equal(ui.editor.getValue(), SOURCE_B);
  await ui.click('runButton');
  assert.equal(ui.server.attempt_id, 'att_2');
  assert.equal(ui.server.source, SOURCE_B);
  await ui.clock.drain();
});

test('a delayed old grading result cannot mark a new active draft as graded or replace its UI', async t => {
  // 初始 state 已确认 graded，允许继续；随后查询旧结果的响应仍可能迟到。
  const ui = await boot(t, { initialExecution: true, initialStatus: 'graded', deferInitialResult: true });
  assert.equal(ui.server.pendingResults.length, 1);
  const pending = ui.server.pendingResults[0];
  assert.equal(pending.attempt_id, 'att_1');
  assert.equal(ui.editor.readOnly, false, '等待旧评分响应时也能改草稿');
  assert.equal(ui.element('runButton').disabled, false);
  ui.editor.setValue(SOURCE_B);
  await ui.click('runButton');
  assert.equal(ui.server.attempt_id, 'att_2');
  assert.equal(ui.server.source, SOURCE_B);
  pending.resolve({ status: 'graded', result: { score_bp: 2500, verdict: 'failed', feedback: '旧提交结果' } });
  await flush();
  assert.equal(ui.element('resultCard').hidden, true, '旧轮询回包不能显示为新草稿的结果');
  assert.equal(ui.editor.getValue(), SOURCE_B);
  assert.equal(ui.editor.readOnly, false);
  assert.equal(ui.element('runButton').disabled, false);
  const before = ui.calls.length;
  const nextDraft = SOURCE_B + '\n// still editing the same active attempt';
  ui.editor.setValue(nextDraft);
  await ui.click('runButton');
  assert.deepEqual(ui.calls.slice(before).map(call => call.operation), ['actions'],
    '旧结果不能把新 active 作答改为 graded 并触发另一次 continue');
  assert.equal(ui.server.attemptCount, 2);
  assert.equal(ui.server.source, nextDraft);
  assert.equal(ui.server.submissions[0].source, SOURCE_A);
  await ui.clock.drain();
});

test('retry after a committed continuation loses its response reuses both request and expected attempt IDs', async t => {
  const ui = await boot(t, { initialExecution: true });
  await ui.click('submitButton');
  ui.editor.setValue(SOURCE_B);
  ui.server.continueFailures = 1;
  const before = ui.calls.length;
  await ui.click('runButton');
  assert.equal(ui.server.attemptCount, 2, '服务端已创建新作答，只是响应丢失');
  assert.equal(ui.editor.getValue(), SOURCE_B);
  assert.equal(ui.editor.readOnly, false);
  assert.deepEqual(ui.calls.slice(before).map(call => call.operation), ['continue']);
  const request = structuredClone(ui.calls[before].payload);
  assert.equal(request.expected_attempt_id, 'att_1');
  await ui.click('runButton');
  const continuations = ui.calls.slice(before).filter(call => call.operation === 'continue');
  assert.equal(continuations.length, 2);
  assert.deepEqual(continuations[1].payload, request, '网络失败后不能生成新 request_id 或改为新 expected_attempt_id');
  assert.deepEqual(ui.calls.slice(before).map(call => call.operation), ['continue', 'continue', 'actions']);
  assert.equal(ui.server.attemptCount, 2);
  assert.equal(ui.server.seq, 1);
  assert.equal(ui.server.source, SOURCE_B);
  assert.equal(ui.editor.getValue(), SOURCE_B);
  assert.equal(ui.server.submissions.length, 1);
  assert.equal(ui.server.submissions[0].source, SOURCE_A);
  await ui.clock.drain();
});

test('insecure HTTP without crypto.randomUUID still sends a valid UUID4 and continues a graded attempt', async t => {
  const ui = await boot(t, { url: 'http://example.test/vibehub/runtime/test/',
    initialExecution: true, initialStatus: 'graded', insecureCrypto: true });
  assert.equal(ui.window.location.protocol, 'http:');
  assert.equal(ui.window.crypto.randomUUID, undefined);
  assert.equal(typeof ui.window.crypto.getRandomValues, 'function');
  ui.editor.setValue(SOURCE_B);
  const before = ui.calls.length;
  await ui.click('runButton');
  const calls = ui.calls.slice(before);
  assert.deepEqual(calls.map(call => call.operation), ['continue', 'actions']);
  assert.match(calls[0].payload.request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  assert.equal(calls[0].payload.expected_attempt_id, 'att_1');
  assert.equal(ui.server.attempt_id, 'att_2');
  assert.equal(ui.server.seq, 1);
  assert.equal(ui.server.source, SOURCE_B);
  assert.equal(ui.editor.getValue(), SOURCE_B);
  await ui.clock.drain();
});

test('resubmitting unchanged frozen source queries or retries the same immutable submission', async t => {
  const ui = await boot(t, { initialExecution: true });
  await ui.click('submitButton');
  const original = structuredClone(ui.server.submissions[0]);
  const before = ui.calls.length;
  await ui.click('submitButton');
  const subsequent = ui.calls.slice(before);
  assert.ok(subsequent.some(call => call.operation === 'result'));
  assert.ok(subsequent.every(call => ['submit', 'result'].includes(call.operation)));
  assert.equal(ui.server.attemptCount, 1);
  assert.equal(ui.server.submissions.length, 1);
  assert.deepEqual(ui.server.submissions[0], original);
  assert.equal(ui.editor.readOnly, false);
  await ui.clock.drain();
});

test('editing while compilation is pending preserves the captured submission source and the next draft', async t => {
  const ui = await boot(t);
  ui.server.deferNextAction = true;
  await ui.click('submitButton');
  assert.equal(ui.server.pendingActions.length, 1);
  assert.equal(ui.element('runButton').disabled, true, '忙时按钮防止并发请求');
  assert.equal(ui.editor.readOnly, false, '编译期间仍可编辑下一份草稿');
  ui.editor.setValue(SOURCE_B);
  ui.server.pendingActions[0].resolve();
  await flush();
  assert.equal(ui.server.submissions.length, 1);
  assert.equal(ui.server.submissions[0].source, SOURCE_A, '本次提交必须使用点击时捕获的源码');
  assert.equal(ui.editor.getValue(), SOURCE_B, '迟到的编译响应不能覆盖下一份草稿');
  assert.equal(ui.editor.readOnly, false);
  const original = structuredClone(ui.server.submissions[0]);
  const before = ui.calls.length;
  await ui.click('submitButton');
  assert.deepEqual(ui.calls.slice(before).map(call => call.operation), ['continue', 'actions', 'submit', 'result']);
  assert.equal(ui.server.submissions.length, 2);
  assert.deepEqual(ui.server.submissions[0], original);
  assert.equal(ui.server.submissions[1].source, SOURCE_B);
  assert.equal(ui.server.submissions[1].attempt_id, 'att_2');
  await ui.clock.drain();
});

function assertGrading(ui) {
  assert.equal(ui.element('resultCard').hidden, false);
  assert.equal(ui.element('resultCard').classList.contains('is-grading'), true);
  assert.equal(ui.element('resultCard').getAttribute('aria-busy'), 'true');
  assert.equal(ui.element('resultScore').textContent, '评测中');
  assert.equal(ui.element('resultFeedback').textContent, '');
  assert.equal(ui.element('runButton').disabled, true);
  assert.equal(ui.element('submitButton').disabled, true);
}

test('submission immediately covers the previous score throughout continuation, compilation, submit and polling', async t => {
  const ui = await boot(t, { initialExecution: true, initialStatus: 'graded' });
  assert.equal(ui.element('resultScore').textContent, '100 分');
  ui.editor.setValue(SOURCE_B);
  ui.server.deferNextAction = ui.server.deferNextSubmit = ui.server.deferNextResult = true;
  ui.server.resultMode = 'grading';
  ui.server.resultFields = { score: 100, result: { score_bp: 10000, feedback: '旧成绩说明' } };

  ui.element('submitButton').click();
  assertGrading(ui); // 在任何异步请求返回之前就必须遮住上次得分。
  await flush();
  assert.equal(ui.server.pendingActions.length, 1);
  assert.equal(ui.server.attempt_id, 'att_2');
  assertGrading(ui); // continue 不能把本次评测动画隐藏。
  ui.server.pendingActions[0].resolve();
  await flush();
  assert.equal(ui.server.pendingSubmits.length, 1);
  assertGrading(ui);
  ui.server.pendingSubmits[0].resolve();
  await flush();
  assert.equal(ui.server.pendingResults.length, 1);
  assertGrading(ui);
  ui.server.pendingResults[0].resolve();
  await flush();
  assertGrading(ui); // pending 回包中的残留分数既不能显示，也不能解锁按钮。

  ui.server.resultMode = 'graded';
  ui.server.resultFields = { result: { score_bp: 6100, feedback: '本次成绩' } };
  await ui.clock.advance(2000);
  assert.equal(ui.element('resultScore').textContent, '61 分');
  assert.equal(ui.element('resultFeedback').textContent, '本次成绩');
  assert.equal(ui.element('resultCard').classList.contains('is-grading'), false);
  assert.equal(ui.element('resultCard').getAttribute('aria-busy'), 'false');
  assert.equal(ui.element('submitButton').disabled, false);
  await ui.clock.drain();
});

for (const initialStatus of ['submitted', 'grading']) test(`restoring ${initialStatus} displays grading before a delayed result and ignores stale scores`, async t => {
  const ui = await boot(t, { initialExecution: true, initialStatus, deferInitialResult: true,
    resultMode: initialStatus, resultFields: { score: 99, result: { score_bp: 9900, feedback: '旧成绩' } } });
  assertGrading(ui);
  ui.server.pendingResults[0].resolve();
  await flush();
  assertGrading(ui);
  ui.server.resultMode = 'graded';
  ui.server.resultFields = { result: { score_bp: 4300, feedback: '新成绩' } };
  await ui.clock.advance(2000);
  assert.equal(ui.element('resultScore').textContent, '43 分');
  assert.equal(ui.element('resultCard').classList.contains('is-grading'), false);
  assert.equal(ui.element('runButton').disabled, false);
  await ui.clock.drain();
});

test('a grading error clears its spinner and does not present residual score or feedback as the new result', async t => {
  const ui = await boot(t, { initialExecution: true, initialStatus: 'graded' });
  assert.equal(ui.element('resultScore').textContent, '100 分');
  ui.server.resultMode = 'error';
  ui.server.resultFields = { score: 100, result: { score_bp: 10000, feedback: '过期的成绩说明' } };
  await ui.click('submitButton');
  assert.equal(ui.element('resultTitle').textContent, '评分暂时失败');
  assert.equal(ui.element('resultScore').textContent, '—');
  assert.doesNotMatch(ui.element('resultFeedback').textContent, /过期/);
  assert.equal(ui.element('resultCard').classList.contains('is-grading'), false);
  assert.equal(ui.element('resultCard').getAttribute('aria-busy'), 'false');
  assert.equal(ui.element('submitButton').disabled, false);
  await ui.clock.drain();
});

test('a failed submit stops grading without restoring the old score and can retry the same submission', async t => {
  const ui = await boot(t, { initialExecution: true, initialStatus: 'graded' });
  const original = structuredClone(ui.server.submissions[0]);
  ui.server.submitFailures = 1;
  ui.element('submitButton').click();
  assertGrading(ui);
  await flush();
  assert.equal(ui.element('resultTitle').textContent, '提交未完成');
  assert.equal(ui.element('resultScore').textContent, '—');
  assert.equal(ui.element('resultFeedback').textContent, '');
  assert.equal(ui.element('resultCard').classList.contains('is-grading'), false);
  assert.equal(ui.element('resultCard').getAttribute('aria-busy'), 'false');
  assert.equal(ui.element('submitButton').disabled, false);
  assert.match(ui.element('codeMessage').textContent, /Failed to fetch/);
  await ui.clock.drain();
  await ui.click('submitButton');
  assert.equal(ui.element('resultScore').textContent, '100 分');
  assert.equal(ui.server.attemptCount, 1);
  assert.equal(ui.server.submissions.length, 1);
  assert.deepEqual(ui.server.submissions[0], original);
  await ui.clock.drain();
});

test('a late result from the previous attempt cannot uncover its score over the new grading animation', async t => {
  const ui = await boot(t, { initialExecution: true, initialStatus: 'graded', deferInitialResult: true });
  const previous = ui.server.pendingResults[0];
  ui.editor.setValue(SOURCE_B);
  ui.server.deferNextResult = true;
  ui.server.resultMode = 'grading';
  await ui.click('submitButton');
  assert.equal(ui.server.pendingResults.length, 2);
  assertGrading(ui);
  previous.resolve({ status: 'graded', result: { score_bp: 2500, feedback: '迟到旧结果' } });
  await flush();
  assertGrading(ui);
  ui.server.pendingResults[1].resolve({ status: 'graded', result: { score_bp: 7200, feedback: '本次结果' } });
  await flush();
  assert.equal(ui.element('resultScore').textContent, '72 分');
  assert.equal(ui.element('resultFeedback').textContent, '本次结果');
  assert.equal(ui.element('resultCard').classList.contains('is-grading'), false);
  assert.equal(ui.element('submitButton').disabled, false);
  await ui.clock.drain();
});
