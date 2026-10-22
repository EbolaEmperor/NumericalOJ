const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const {JSDOM} = require('jsdom')

const motionPath = path.resolve(__dirname, '../../vibehub_examples/dynamic-balance/static/heap-motion.js')

function pointMatrix(x = 0, y = 0) {
  return {
    a: 1, b: 0, c: 0, d: 1, e: x, f: y,
    inverse: () => pointMatrix(-x, -y),
    transformPoint: (point) => ({x: point.x + x, y: point.y + y}),
  }
}

function rect(left, top, width, height) {
  return {x: left, y: top, left, top, width, height, right: left + width, bottom: top + height,
    toJSON() { return {left, top, width, height} }}
}

function createRenderer(t, {reducedMotion = false, inputs = [7, 7, 12, -3, 6]} = {}) {
  const styles = fs.readFileSync(path.join(path.dirname(motionPath), 'style.css'), 'utf8')
  const dom = new JSDOM(`<!doctype html><html><head><style>${styles}</style></head><body><div class="conveyor-window"><div id="conveyor" class="conveyor"></div><div class="belt-line"></div></div><div class="heap-a"><svg id="heapA" viewBox="0 0 400 260"></svg></div><div class="heap-b"><svg id="heapB" viewBox="0 0 400 260"></svg></div></body></html>`,
    {runScripts: 'dangerously', pretendToBeVisual: true, url: 'http://localhost/'})
  const {window} = dom
  const {document} = window
  const animations = []
  const heapA = document.getElementById('heapA')
  const heapB = document.getElementById('heapB')
  const conveyor = document.getElementById('conveyor')

  function svgPoint(element) {
    const svg = element.closest('svg')
    let x = svg?.id === 'heapB' ? 580 : 100
    let y = 200
    for (let current = element; current && current !== svg; current = current.parentElement) {
      const transform = current.getAttribute?.('transform') || current.style?.transform || ''
      const translated = /translate\(\s*(-?[\d.]+)(?:px)?[\s,]+\s*(-?[\d.]+)(?:px)?\s*\)/.exec(transform)
      if (translated) { x += Number(translated[1]); y += Number(translated[2]) }
    }
    return {x, y}
  }

  window.Element.prototype.getBoundingClientRect = function () {
    if (this === heapA) return rect(100, 200, 400, 260)
    if (this === heapB) return rect(580, 200, 400, 260)
    if (this === conveyor) return rect(24, 34, 600, 52)
    if (conveyor.contains(this)) {
      const index = Array.from(conveyor.querySelectorAll('.number-block')).indexOf(this)
      return rect(24 + Math.max(0, index) * 54, 34, 42, 42)
    }
    if (this.closest('svg')) {
      const point = svgPoint(this)
      return rect(point.x - 19, point.y - 19, 38, 38)
    }
    return rect(Number.parseFloat(this.style.left) || 0, Number.parseFloat(this.style.top) || 0,
      Number.parseFloat(this.style.width) || 38, Number.parseFloat(this.style.height) || 38)
  }
  window.SVGElement.prototype.getScreenCTM = function () {
    const point = this.matches('svg') ? {x: this.id === 'heapB' ? 580 : 100, y: 200} : svgPoint(this)
    return pointMatrix(point.x, point.y)
  }
  window.SVGElement.prototype.getCTM = window.SVGElement.prototype.getScreenCTM
  window.SVGElement.prototype.getBBox = () => ({x: -19, y: -19, width: 38, height: 38})
  window.SVGSVGElement.prototype.createSVGPoint = () => ({x: 0, y: 0,
    matrixTransform(matrix) { return {x: matrix.a * this.x + matrix.c * this.y + matrix.e,
      y: matrix.b * this.x + matrix.d * this.y + matrix.f} }})
  window.DOMPoint = class {
    constructor(x = 0, y = 0) { this.x = x; this.y = y }
    matrixTransform(matrix) { return matrix.transformPoint(this) }
  }
  window.matchMedia = () => ({matches: reducedMotion})
  window.Element.prototype.getAnimations = function ({subtree = false} = {}) {
    return animations.filter((animation) => animation.playState !== 'idle'
      && (animation.target === this || (subtree && this.contains(animation.target))))
  }
  window.Element.prototype.animate = function (keyframes, options = {}) {
    let resolve
    let reject
    let settled = false
    const finished = new Promise((done, fail) => { resolve = done; reject = fail })
    // 浏览器的取消会拒绝 finished；保留拒绝语义，并避免清理测试环境时产生无关噪音。
    finished.catch(() => {})
    const record = Object.assign(new window.EventTarget(), {
      target: this,
      keyframes: JSON.parse(JSON.stringify(keyframes)),
      options: typeof options === 'number' ? {duration: options} : {...options},
      pauseCount: 0, playCount: 0, finishCount: 0, cancelCount: 0,
      finished,
      playState: 'running',
      playbackRate: 1,
      currentTime: 0,
      effect: {target: this, getComputedTiming: () => ({duration: Number(options.duration) || 0}),
        getKeyframes: () => keyframes},
      pause() { this.pauseCount++; this.playState = 'paused' },
      play() { this.playCount++; this.playState = 'running' },
      updatePlaybackRate(rate) { this.playbackRate = rate },
      commitStyles() {},
      finish() {
        if (settled) return
        settled = true; this.finishCount++; this.playState = 'finished'; resolve()
        const event = new window.Event('finish')
        this.dispatchEvent(event); this.onfinish?.(event)
      },
      cancel() {
        if (settled) return
        settled = true; this.cancelCount++; this.playState = 'idle'
        reject(new window.DOMException('Canceled', 'AbortError'))
        const event = new window.Event('cancel')
        this.dispatchEvent(event); this.oncancel?.(event)
      },
    })
    animations.push(record)
    if (Number(record.options.duration) <= 1) queueMicrotask(() => record.finish())
    return record
  }
  window.eval(fs.readFileSync(motionPath, 'utf8'))
  const motion = window.NumOJHeapMotion.create({heapA, heapB, conveyor, inputs: () => inputs,
    reducedMotion: () => reducedMotion})
  t.after(() => { motion.reset(); dom.window.close() })
  return {dom, document, heapA, heapB, conveyor, motion, animations}
}

function nodes(values) {
  return values.map(([id, value], index) => ({id, value, index}))
}

function frame(left = [], right = [], motion = {kind: 'idle'}, extra = {}) {
  return {left, right, parked: [], round: 0, x: 7, conveyorOffset: 0, motion, ...extra}
}

function nodeIn(heap, id) {
  return Array.from(heap.querySelectorAll('[data-node-id]')).find((element) => element.dataset.nodeId === id)
}

function moving(record) {
  const frames = record.keyframes
  return ['transform', 'translate', 'left', 'top', 'x', 'y'].some((property) => {
    const values = Array.isArray(frames) ? frames.map((entry) => entry[property]).filter((value) => value !== undefined) : frames[property]
    return Array.isArray(values) && new Set(values).size > 1
  })
}

function fixedFlights(environment) {
  return environment.animations.filter((record) => record.target.namespaceURI !== 'http://www.w3.org/2000/svg'
    && environment.dom.window.getComputedStyle(record.target).position === 'fixed')
}

function assertClean(environment) {
  assert.equal(environment.document.querySelectorAll('.is-picked,.is-arriving').length, 0)
  assert.ok(fixedFlights(environment).every((record) => !record.target.isConnected), '固定浮层应已移除')
}

async function flush() {
  for (let index = 0; index < 6; index++) await Promise.resolve()
}

async function complete(environment, rendered) {
  for (let index = 0; index < 12; index++) {
    await flush()
    const pending = environment.animations.filter((animation) => ['running', 'paused'].includes(animation.playState))
    if (!pending.length) break
    pending.forEach((animation) => animation.finish())
  }
  await rendered
}

test('重复数值使用独立身份，交换位置后仍复用原来的节点 DOM', async (t) => {
  const env = createRenderer(t)
  await env.motion.render(frame(nodes([['first', 7], ['second', 7]]), nodes([['third', 7]])), {animate: false})
  const first = nodeIn(env.heapA, 'first')
  const second = nodeIn(env.heapA, 'second')
  const third = nodeIn(env.heapB, 'third')
  assert.ok(first && second && third)
  assert.notEqual(first, second)
  assert.equal(first.textContent, second.textContent)
  const rendered = env.motion.render(frame(nodes([['second', 7], ['first', 7]]), nodes([['third', 7]]),
    {kind: 'swap', heap: 'A', nodeId: 'second', otherNodeId: 'first', fromIndex: 1, toIndex: 0}))
  await complete(env, rendered)
  assert.equal(nodeIn(env.heapA, 'first'), first)
  assert.equal(nodeIn(env.heapA, 'second'), second)
  assert.equal(nodeIn(env.heapB, 'third'), third)
  assert.ok(env.animations.filter(moving).length >= 2, '交换双方都应有位移动画')
})

test('只有 top 帧高亮堆顶并缩放内部节点，下一帧恢复普通配色', async (t) => {
  const env = createRenderer(t)
  const left = nodes([['root-a', 9], ['child-a', 7]])
  const right = nodes([['root-b', 12]])
  await env.motion.render(frame(left, right), {animate: false})
  assert.equal(env.document.querySelector('.is-top'), null)
  const root = nodeIn(env.heapA, 'root-a')
  const normalFill = env.dom.window.getComputedStyle(root.querySelector('circle')).fill
  const normalChildFill = env.dom.window.getComputedStyle(nodeIn(env.heapA, 'child-a').querySelector('circle')).fill
  assert.equal(normalFill, normalChildFill, '平时根节点和子节点应使用同样的浅色')
  const rendered = env.motion.render(frame(left, right, {kind: 'top', heap: 'A', nodeId: 'root-a'}))
  await flush()
  const highlighted = env.document.querySelectorAll('.is-top')
  assert.equal(highlighted.length, 1)
  assert.ok(root === highlighted[0] || root.contains(highlighted[0]))
  assert.notEqual(env.dom.window.getComputedStyle(root.querySelector('circle')).fill, normalFill)
  assert.equal(nodeIn(env.heapB, 'root-b').querySelector('.is-top'), null)
  assert.ok(env.animations.some((animation) => animation.target !== root && root.contains(animation.target)
    && JSON.stringify(animation.keyframes).includes('scale(')), '弹性缩放应作用在内部节点而非定位 group')
  await complete(env, rendered)
  await env.motion.render(frame(left, right), {animate: false})
  assert.equal(env.document.querySelector('.is-top'), null)
  assert.equal(env.dom.window.getComputedStyle(root.querySelector('circle')).fill, normalFill)
  assert.equal(nodeIn(env.heapA, 'root-a'), root)
})

test('insert 等待真实动画完成，并由传送带方块变为落位圆形', async (t) => {
  const env = createRenderer(t)
  await env.motion.render(frame(), {animate: false})
  const source = env.conveyor.querySelector('.number-block')
  assert.ok(source)
  let finished = false
  const rendered = env.motion.render(frame(nodes([['input-0', 7]]), [],
    {kind: 'insert', heap: 'A', nodeId: 'input-0', from: {kind: 'conveyor', round: 0}, toIndex: 0},
    {conveyorOffset: 1})).then(() => { finished = true })
  await flush()
  assert.equal(finished, false, 'render 应等待 WAAPI.finished，而非立即完成')
  const flight = fixedFlights(env).find((animation) => animation.target.isConnected)
  assert.ok(flight, '插入时应产生跨越传送带与 SVG 的固定浮层')
  assert.ok(moving(flight))
  const corners = Array.isArray(flight.keyframes) ? flight.keyframes.map((item) => item.borderRadius).filter(Boolean)
    : flight.keyframes.borderRadius
  assert.ok(Array.isArray(corners) && new Set(corners).size > 1, '飞行方块应逐渐变成圆形')
  assert.ok(source.classList.contains('is-picked'))
  assert.ok(nodeIn(env.heapA, 'input-0').classList.contains('is-arriving'))
  await complete(env, rendered)
  assert.equal(finished, true)
  assertClean(env)
})

test('pop 移出堆顶，replace 保留末尾节点身份并移动到根，再插入另一棵堆复用被取出的节点', async (t) => {
  const env = createRenderer(t)
  const original = nodes([['removed', 9], ['remaining', 7], ['last', 6]])
  await env.motion.render(frame(original), {animate: false})
  const removed = nodeIn(env.heapA, 'removed')
  const last = nodeIn(env.heapA, 'last')
  let start = env.animations.length
  const hole = [{id: 'remaining', value: 7, index: 1}, {id: 'last', value: 6, index: 2}]
  const parked = [{id: 'removed', value: 9, heap: 'A'}]
  await complete(env, env.motion.render(frame(hole, [], {kind: 'pop', heap: 'A', nodeId: 'removed', fromIndex: 0}, {parked})))
  assert.ok(env.animations.slice(start).some(moving), 'pop 应有离开根节点的位移动画')
  assert.equal(nodeIn(env.heapA, 'removed'), undefined)
  start = env.animations.length
  await complete(env, env.motion.render(frame(nodes([['last', 6], ['remaining', 7]]), [],
    {kind: 'replace', heap: 'A', nodeId: 'last', fromIndex: 2, toIndex: 0}, {parked})))
  assert.equal(nodeIn(env.heapA, 'last'), last)
  assert.ok(env.animations.slice(start).some(moving), 'replace 应有从原末尾到根的位移')
  start = env.animations.length
  await complete(env, env.motion.render(frame(nodes([['last', 6], ['remaining', 7]]), nodes([['removed', 9]]),
    {kind: 'insert', heap: 'B', nodeId: 'removed', from: {kind: 'parked', nodeId: 'removed', heap: 'A'}, toIndex: 0})))
  assert.equal(nodeIn(env.heapB, 'removed'), removed, '移入 B 的仍应是原先被取出的节点')
  assert.ok(env.animations.slice(start).some(moving), '跨堆插入应从停靠点移动')
  assertClean(env)
})

test('finish 完成飞行动画并清理临时标记，reset 取消进行中的动画且旧 Promise 能结束', async (t) => {
  const env = createRenderer(t)
  await env.motion.render(frame(), {animate: false})
  const insert = () => env.motion.render(frame(nodes([['input-0', 7]]), [],
    {kind: 'insert', heap: 'A', nodeId: 'input-0', from: {kind: 'conveyor', round: 0}, toIndex: 0},
    {conveyorOffset: 1}))
  let rendered = insert()
  await flush()
  assert.ok(fixedFlights(env).some((animation) => animation.target.isConnected))
  env.motion.finish()
  await rendered
  assertClean(env)
  env.motion.reset()
  await env.motion.render(frame(), {animate: false})
  rendered = insert()
  await flush()
  env.motion.reset()
  await rendered
  assertClean(env)
  assert.ok(env.animations.every((animation) => !['running', 'paused'].includes(animation.playState)))
})

test('新的静态帧可以中断旧飞行动画，旧浮层和占位标记不会残留', async (t) => {
  const env = createRenderer(t)
  await env.motion.render(frame(), {animate: false})
  const rendered = env.motion.render(frame(nodes([['input-0', 7]]), [],
    {kind: 'insert', heap: 'A', nodeId: 'input-0', from: {kind: 'conveyor', round: 0}, toIndex: 0},
    {conveyorOffset: 1}))
  await flush()
  await env.motion.render(frame(), {animate: false})
  await rendered
  assertClean(env)
  assert.equal(nodeIn(env.heapA, 'input-0'), undefined)
})

test('pause/resume 和运行中速度调整作用于尚未完成的动画', async (t) => {
  const env = createRenderer(t)
  const left = nodes([['root-a', 9]])
  await env.motion.render(frame(left), {animate: false})
  const rendered = env.motion.render(frame(left, [], {kind: 'top', heap: 'A', nodeId: 'root-a'}))
  await flush()
  const pending = env.animations.filter((animation) => animation.playState === 'running')
  assert.ok(pending.length)
  env.motion.pause()
  assert.ok(pending.every((animation) => animation.playState === 'paused'))
  env.motion.setSpeed(2)
  assert.ok(pending.every((animation) => animation.playbackRate === 2))
  env.motion.resume()
  assert.ok(pending.every((animation) => animation.playState === 'running' && animation.playCount > 0))
  await complete(env, rendered)
})

test('减少动态效果时没有长时间动画，最终节点和清理行为保持一致', async (t) => {
  const env = createRenderer(t, {reducedMotion: true})
  await env.motion.render(frame(), {animate: false})
  const rendered = env.motion.render(frame(nodes([['input-0', 7]]), [],
    {kind: 'insert', heap: 'A', nodeId: 'input-0', from: {kind: 'conveyor', round: 0}, toIndex: 0},
    {conveyorOffset: 1}))
  await complete(env, rendered)
  assert.ok(env.animations.every((animation) => Number(animation.options.duration) <= 100))
  assert.ok(nodeIn(env.heapA, 'input-0'))
  assertClean(env)
})

test('同一轮多个 insert 仅首次消费输入，后续数字以持久 DOM 向左移动一次', async (t) => {
  const env = createRenderer(t)
  await env.motion.render(frame(), {animate: false})
  const initial = Array.from(env.conveyor.querySelectorAll('.number-block'))
  assert.ok(initial.length >= 3)
  const next = initial[1]
  const later = initial[2]
  let start = env.animations.length
  await complete(env, env.motion.render(frame(nodes([['input-0', 7]]), [],
    {kind: 'insert', heap: 'A', nodeId: 'input-0', from: {kind: 'conveyor', round: 0}, toIndex: 0},
    {conveyorOffset: 1})))
  assert.ok(next.isConnected && later.isConnected, '未消费输入应保留自己的 DOM 身份')
  const afterFirst = Array.from(env.conveyor.querySelectorAll('.number-block')).filter((block) => !block.classList.contains('is-picked'))
  assert.ok(afterFirst.indexOf(next) < afterFirst.indexOf(later))
  assert.ok(env.animations.slice(start).some((animation) => (animation.target === next || animation.target === env.conveyor
    || animation.target.contains(next)) && moving(animation)), '消费后传送带后续数字应向左滑动')
  const belt = env.document.querySelector('.belt-line')
  const beltMotion = env.animations.slice(start).find((animation) => animation.target === belt)
  assert.ok(beltMotion, '传送带纹理应与输入方块同步移动')
  const backgrounds = ['backgroundPositionX', 'backgroundPosition'].flatMap((property) => Array.isArray(beltMotion.keyframes)
    ? beltMotion.keyframes.map((entry) => entry[property]).filter((value) => value !== undefined)
    : beltMotion.keyframes[property] || [])
  assert.ok(backgrounds.length >= 2 && Number.parseFloat(backgrounds.at(-1)) < Number.parseFloat(backgrounds[0]),
    '带面纹理应沿着后续数字移动的方向向左前进')
  start = env.animations.length
  await complete(env, env.motion.render(frame(nodes([['input-0', 7], ['another', 7]]), [],
    {kind: 'insert', heap: 'A', nodeId: 'another', from: {kind: 'conveyor', round: 0}, toIndex: 1},
    {conveyorOffset: 1})))
  assert.ok(next.isConnected && later.isConnected)
  assert.equal(env.animations.slice(start).filter((animation) => (animation.target === next || animation.target === env.conveyor
    || animation.target.contains(next)) && moving(animation)).length, 0, '同一输入不能再次推进传送带')
  assert.equal(env.animations.slice(start).filter((animation) => animation.target === belt).length, 0,
    '同一输入也不能重复推进带面纹理')
})
