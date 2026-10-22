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

function executionFixture() {
  return { compiled: true, passed: 3, total: 5, rounds: [
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

async function boot(t, { url = 'https://example.test/vibehub/runtime/test/', initialExecution = false } = {}) {
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
  const server = { seq: 1, source: SOURCE_A, status: 'active', execution: initialExecution ? executionFixture() : null };
  let editorValue = '', onRun;
  const editor = { getValue: () => editorValue,
    setValue: value => { editorValue = value; editorValues.push(value); }, focus() {},
    updateOptions: options => { editor.readOnly = options.readOnly; } };
  window.NumOJEduEditor = { create: (_host, options) => { onRun = options.onRun; return editor; } };
  const snapshot = () => ({ success: true, seq: server.seq, status: server.status,
    view: { source: server.source, initial_source: starter, inputs: [4, 9, 7, 2, 8], execution: server.execution } });
  const response = (status, data) => ({ ok: status >= 200 && status < 300, status, json: async () => structuredClone(data) });
  window.fetch = async (url, options) => {
    assert.equal(editorValues[0], starter, '首次请求之前就应显示默认代码');
    const operation = new URL(url).pathname.split('/').pop();
    const payload = options.body ? JSON.parse(options.body) : null;
    calls.push({ operation, payload });
    if (operation === 'state') return response(200, snapshot());
    if (operation === 'actions') {
      if (payload.expected_seq !== server.seq) return response(409, { success: false, message: '操作并发冲突' });
      server.source = payload.action.source;
      server.seq++;
      server.execution = executionFixture();
      return response(200, snapshot());
    }
    if (operation === 'submit') {
      assert.equal(payload.expected_seq, server.seq);
      assert.equal(server.source, SOURCE_A);
      server.status = 'grading';
      return response(200, { success: true, submission_id: 11, status: 'grading' });
    }
    if (operation === 'result') return response(200, { success: true, status: 'graded',
      result: { score_bp: 10000, verdict: 'passed', feedback: '已评分' } });
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
