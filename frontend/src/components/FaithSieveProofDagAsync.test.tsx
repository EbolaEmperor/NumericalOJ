// @vitest-environment jsdom

import {act, cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {layoutFaithSieveProofDag} from '../lib/faithSieveProofDagLayout'
import type {FaithSieveProofDagV3Data} from '../lib/faithSieveProofDag'
import {proofDagV3Fixture, proofDagVerificationFixture} from '../test/faithSieveProofDag'
import {FaithSieveProofTree} from './FaithSieveProofTree'

vi.mock('../lib/faithSieveProofDagLayout', () => ({layoutFaithSieveProofDag: vi.fn()}))
vi.mock('./useMarkdownEnhancements', () => ({useMarkdownEnhancements: vi.fn()}))
vi.mock('./MarkdownContent', () => ({MarkdownContent: () => null}))

type Layout = Awaited<ReturnType<typeof layoutFaithSieveProofDag>>
const layoutMock = vi.mocked(layoutFaithSieveProofDag)

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((accept, fail) => {resolve = accept; reject = fail})
  return {promise, resolve, reject}
}

function layoutFor(graph: FaithSieveProofDagV3Data, offset = 0): Layout {
  const positions = Object.fromEntries(graph.nodes.map((node, index) => [node.id, {x: 80 + index % 3 * 180 + offset, y: 70 + Math.floor(index / 3) * 180}]))
  const edgeRoutes = Object.fromEntries(graph.edges.map((edge) => {
    const from = positions[edge.from]
    const to = positions[edge.to]
    const length = Math.hypot(to.x - from.x, to.y - from.y) || 1
    const ux = (to.x - from.x) / length
    const uy = (to.y - from.y) / length
    return [edge.id, [{x: from.x + ux * 19, y: from.y + uy * 19}, {x: to.x - ux * 19, y: to.y - uy * 19}]]
  }))
  return {positions, edgeRoutes, width: 720 + offset, height: 620}
}

async function waitForCanvas(container: HTMLElement) {
  await waitFor(() => expect(container.querySelectorAll('[data-proof-node]')).toHaveLength(7))
  return container.querySelector<HTMLElement>('.faithsieve-proof-canvas')!
}

function pathPoints(path: SVGPathElement) {
  const numbers = (path.getAttribute('d') || '').match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)?.map(Number) || []
  return Array.from({length: numbers.length / 2}, (_, index) => ({x: numbers[index * 2], y: numbers[index * 2 + 1]}))
}

function nodeCenter(node: HTMLElement) {
  return {x: Number.parseFloat(node.style.left) + 19, y: Number.parseFloat(node.style.top) + 19}
}

beforeEach(() => layoutMock.mockReset())
afterEach(() => {cleanup(); vi.restoreAllMocks()})

describe('证明依赖图异步布局', () => {
  it('等待 ELK 结果时不闪现旧布局，旧图迟到不能覆盖新图', async () => {
    const graph = proofDagV3Fixture()
    const next = {...graph, nodes: graph.nodes.map((node) => ({...node, label: `${node.label} 新`}))}
    const first = deferred<Layout>()
    const second = deferred<Layout>()
    layoutMock.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)
    const {container, rerender} = render(<FaithSieveProofTree tree={graph} />)
    expect(screen.getByRole('status', {name: '证明依赖图布局状态'}).textContent).toBe('布局中…')
    expect(container.querySelector('.faithsieve-proof-canvas')).toBeNull()
    expect(container.querySelector('[data-proof-node]')).toBeNull()
    rerender(<FaithSieveProofTree tree={next} />)
    expect(layoutMock).toHaveBeenNthCalledWith(2, next)
    await act(async () => {second.resolve(layoutFor(next, 100)); await second.promise})
    const canvas = await waitForCanvas(container)
    const position = container.querySelector<HTMLElement>('[data-proof-node="N1"]')!.style.left
    expect(canvas.style.width).toBe('820px')
    await act(async () => {first.resolve(layoutFor(graph)); await first.promise})
    expect(container.querySelector('.faithsieve-proof-canvas')).toBe(canvas)
    expect(container.querySelector<HTMLElement>('[data-proof-node="N1"]')!.style.left).toBe(position)
    expect(canvas.style.width).toBe('820px')
    expect(screen.queryByRole('status', {name: '证明依赖图布局状态'})).toBeNull()
  })

  it('切换已绘制图时立即隐藏旧画布，直到新图布局完成', async () => {
    const graph = proofDagV3Fixture()
    const next = {...graph, nodes: graph.nodes.map((node) => ({...node, statement: `${node.statement} 新版`}))}
    const pending = deferred<Layout>()
    layoutMock.mockResolvedValueOnce(layoutFor(graph)).mockReturnValueOnce(pending.promise)
    const {container, rerender} = render(<FaithSieveProofTree tree={graph} />)
    await waitForCanvas(container)
    rerender(<FaithSieveProofTree tree={next} />)
    expect(container.querySelector('.faithsieve-proof-canvas')).toBeNull()
    expect(screen.getByRole('status', {name: '证明依赖图布局状态'})).toBeTruthy()
    await act(async () => {pending.resolve(layoutFor(next, 60)); await pending.promise})
    expect((await waitForCanvas(container)).style.width).toBe('780px')
  })

  it('布局失败可重试，不绘制未经 ELK 布局的图', async () => {
    const graph = proofDagV3Fixture()
    layoutMock.mockRejectedValueOnce(new Error('ELK unavailable')).mockResolvedValueOnce(layoutFor(graph))
    const {container} = render(<FaithSieveProofTree tree={graph} />)
    expect((await screen.findByRole('alert')).textContent).toContain('证明依赖图布局失败')
    expect(container.querySelector('.faithsieve-proof-canvas')).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: '重新布局'}))
    await waitForCanvas(container)
    expect(layoutMock).toHaveBeenCalledTimes(2)
    expect(layoutMock).toHaveBeenNthCalledWith(2, graph)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('卸载后的迟到布局不干扰另一幅仍在等待的图', async () => {
    const firstGraph = proofDagV3Fixture()
    const nextGraph = proofDagV3Fixture()
    const first = deferred<Layout>()
    const second = deferred<Layout>()
    layoutMock.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)
    const previous = render(<FaithSieveProofTree tree={firstGraph} />)
    previous.unmount()
    const {container} = render(<FaithSieveProofTree tree={nextGraph} />)
    await act(async () => {first.resolve(layoutFor(firstGraph)); await first.promise})
    expect(container.querySelector('.faithsieve-proof-canvas')).toBeNull()
    expect(screen.getByRole('status', {name: '证明依赖图布局状态'})).toBeTruthy()
    await act(async () => {second.resolve(layoutFor(nextGraph, 60)); await second.promise})
    expect((await waitForCanvas(container)).style.width).toBe('780px')
  })

  it('只更新验证结果时保留布局和缩放，不重新调用 ELK', async () => {
    const graph = proofDagV3Fixture()
    const verification = proofDagVerificationFixture()
    layoutMock.mockResolvedValue(layoutFor(graph))
    const {container, rerender} = render(<FaithSieveProofTree tree={graph} nodeVerification={verification} />)
    const canvas = await waitForCanvas(container)
    fireEvent.click(screen.getByRole('button', {name: '放大证明依赖图'}))
    const scale = canvas.style.transform
    rerender(<FaithSieveProofTree tree={graph} nodeVerification={{...verification, N9: {...verification.N9, local_status: 'refuted', status: 'not_established'}}} />)
    expect(screen.getByText('推理被反驳')).toBeTruthy()
    expect(container.querySelector('.faithsieve-proof-canvas')).toBe(canvas)
    expect(canvas.style.transform).toBe(scale)
    expect(container.querySelector('[data-proof-node="N9"]')?.classList.contains('is-refuted')).toBe(true)
    expect(layoutMock).toHaveBeenCalledTimes(1)
  })

  it('宽 DAG 默认按栏宽完整展示，响应窗口变化；手动缩放仍可平移并用适应恢复', async () => {
    const graph = proofDagV3Fixture()
    const layout = {...layoutFor(graph), width: 1400, height: 2400}
    let paneWidth = 600
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(function (this: HTMLElement) {
      return this.classList.contains('faithsieve-proof-viewport') ? paneWidth : 0
    })
    layoutMock.mockResolvedValue(layout)
    const {container} = render(<FaithSieveProofTree tree={graph} />)
    const canvas = await waitForCanvas(container)
    const viewport = screen.getByLabelText('证明依赖图画布')
    const plane = container.querySelector<HTMLElement>('.faithsieve-proof-plane')!
    const scale = () => Number(canvas.style.transform.match(/scale\(([^)]+)\)/)![1])
    expect(scale()).toBeCloseTo((600 - 48) / layout.width)
    expect(plane.style.width).toBe('600px')
    // 高度超出时向下滚动，不能用适应高度把默认节点再压缩。
    expect(Number.parseFloat(plane.style.height)).toBeGreaterThan(720)
    expect(viewport.scrollLeft).toBe(0)
    paneWidth = 320
    fireEvent(window, new Event('resize'))
    expect(scale()).toBeCloseTo((320 - 48) / layout.width)
    expect(plane.style.width).toBe('320px')
    expect(viewport.scrollLeft).toBe(0)
    fireEvent.click(screen.getByRole('button', {name: '放大证明依赖图'}))
    const manualScale = scale()
    expect(manualScale).toBeCloseTo((320 - 48) / layout.width * 1.25)
    expect(Number.parseFloat(plane.style.width)).toBeGreaterThan(paneWidth)
    paneWidth = 600
    fireEvent(window, new Event('resize'))
    expect(scale()).toBe(manualScale)
    fireEvent.click(screen.getByRole('button', {name: '适应证明依赖图'}))
    expect(Number.parseFloat(plane.style.width)).toBeLessThanOrEqual(paneWidth)
    fireEvent.click(screen.getByRole('button', {name: '展开证明依赖图'}))
    expect(scale()).toBeCloseTo((600 - 48) / layout.width)
    expect(viewport.scrollLeft).toBe(0)
    expect(layoutMock).toHaveBeenCalledTimes(1)
  })

  it('绘制 ELK 折点并保留拖动后的圆形端点和箭头方向', async () => {
    const graph = proofDagV3Fixture()
    const layout = layoutFor(graph)
    layout.positions.N1 = {x: 80, y: 70}
    layout.positions.N7 = {x: 260, y: 310}
    const bends = [{x: 80, y: 140}, {x: 210, y: 160}, {x: 260, y: 230}]
    layout.edgeRoutes.D1 = [{x: 80, y: 89}, ...bends, {x: 260, y: 291}]
    layoutMock.mockResolvedValue(layout)
    const {container} = render(<FaithSieveProofTree tree={graph} />)
    await waitForCanvas(container)
    const edge = container.querySelector('[data-proof-edge="D1"]')!
    const path = edge.querySelector<SVGPathElement>('path.faithsieve-proof-edge-line')!
    expect(path).toBeTruthy()
    expect(pathPoints(path).slice(1, -1)).toEqual(bends)
    expect(edge.querySelector('.faithsieve-proof-edge-hit')?.getAttribute('d')).toBe(path.getAttribute('d'))
    const viewport = screen.getByLabelText('证明依赖图画布')
    const source = container.querySelector<HTMLElement>('[data-proof-node="N1"]')!
    const target = container.querySelector<HTMLElement>('[data-proof-node="N7"]')!
    const originalSource = nodeCenter(source)
    fireEvent.pointerDown(source, {button: 0, pointerId: 11, clientX: 100, clientY: 100})
    fireEvent.pointerMove(viewport, {pointerId: 11, clientX: 140, clientY: 110})
    fireEvent.pointerUp(viewport, {pointerId: 11})
    const movedSource = nodeCenter(source)
    expect(movedSource).not.toEqual(originalSource)
    const afterSource = pathPoints(path)
    expect(afterSource.slice(1, -1)).toEqual(bends)
    expect(Math.hypot(afterSource[0].x - movedSource.x, afterSource[0].y - movedSource.y)).toBeCloseTo(19)
    const originalTarget = nodeCenter(target)
    fireEvent.pointerDown(target, {button: 0, pointerId: 12, clientX: 100, clientY: 100})
    fireEvent.pointerMove(viewport, {pointerId: 12, clientX: 115, clientY: 135})
    fireEvent.pointerUp(viewport, {pointerId: 12})
    const movedTarget = nodeCenter(target)
    expect(movedTarget).not.toEqual(originalTarget)
    const afterTarget = pathPoints(path)
    expect(afterTarget.slice(1, -1)).toEqual(bends)
    const end = afterTarget.at(-1)!
    expect(Math.hypot(end.x - movedTarget.x, end.y - movedTarget.y)).toBeCloseTo(22)
    const arrow = edge.querySelector('polygon')!.getAttribute('points')!.split(/[,\s]+/).map(Number)
    expect(arrow.slice(0, 2)).toEqual([end.x, end.y])
    const beforeEnd = afterTarget.at(-2)!
    const arrowBase = {x: (arrow[2] + arrow[4]) / 2, y: (arrow[3] + arrow[5]) / 2}
    const edgeAngle = Math.atan2(end.y - beforeEnd.y, end.x - beforeEnd.x)
    const arrowAngle = Math.atan2(end.y - arrowBase.y, end.x - arrowBase.x)
    expect(arrowAngle).toBeCloseTo(edgeAngle)
    expect(layoutMock).toHaveBeenCalledTimes(1)
  })
})
