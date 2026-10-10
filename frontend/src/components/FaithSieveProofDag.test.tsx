// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {proofDagExternalFixture, proofDagExternalVerificationFixture, proofDagFixture, proofDagV3Fixture, proofDagVerificationFixture} from '../test/faithSieveProofDag'
import {denseProofDagTopologyFixture} from '../test/faithSieveProofDagTopology'
import {FaithSieveProofTree} from './FaithSieveProofTree'

vi.mock('./useMarkdownEnhancements', () => ({useMarkdownEnhancements: vi.fn()}))
vi.mock('./MarkdownContent', () => ({MarkdownContent: () => null}))
afterEach(() => cleanup())

async function waitForDiagram(container: HTMLElement, nodeCount = 7) {
  await waitFor(() => expect(container.querySelectorAll('[data-proof-node]')).toHaveLength(nodeCount), {timeout: 8_000})
  expect(screen.queryByRole('status', {name: '证明依赖图布局状态'})).toBeNull()
}

function distanceToSegment(point: {x: number; y: number}, from: {x: number; y: number}, to: {x: number; y: number}) {
  const dx = to.x - from.x
  const dy = to.y - from.y
  const length = dx * dx + dy * dy
  const fraction = length ? Math.max(0, Math.min(1, ((point.x - from.x) * dx + (point.y - from.y) * dy) / length)) : 0
  return Math.hypot(point.x - from.x - fraction * dx, point.y - from.y - fraction * dy)
}

describe('证明依赖图画布', () => {
  it('密集跨层依赖的实际 SVG 路径不穿过无关圆节点，贴近端口的箭头始终指向结论', async () => {
    const graph = denseProofDagTopologyFixture()
    const {container} = render(<FaithSieveProofTree tree={graph} />)
    await waitForDiagram(container, 36)
    const positions = Object.fromEntries(graph.nodes.map(({id}) => {
      const node = container.querySelector<HTMLElement>(`[data-proof-node="${id}"]`)!
      return [id, {x: Number.parseFloat(node.style.left) + 19, y: Number.parseFloat(node.style.top) + 19}]
    }))
    expect(container.querySelectorAll('.faithsieve-proof-edge-line')).toHaveLength(92)
    for (const edge of graph.edges) {
      const path = container.querySelector<SVGPathElement>(`[data-proof-edge="${edge.id}"] .faithsieve-proof-edge-line`)!
      const numbers = path.getAttribute('d')!.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number)
      const points = Array.from({length: numbers.length / 2}, (_, index) => ({x: numbers[index * 2], y: numbers[index * 2 + 1]}))
      for (const node of graph.nodes.filter(({id}) => id !== edge.from && id !== edge.to)) {
        for (let segment = 1; segment < points.length; segment++) {
          expect(distanceToSegment(positions[node.id], points[segment - 1], points[segment]), `${edge.id} 不应穿过 ${node.id}`).toBeGreaterThanOrEqual(19)
        }
      }
      const tip = points.at(-1)!
      const before = points.at(-2)!
      const target = positions[edge.to]
      expect((tip.x - before.x) * (target.x - tip.x) + (tip.y - before.y) * (target.y - tip.y), `${edge.id} 箭头应指向 ${edge.to}`).toBeGreaterThan(0)
    }
  })

  it('外部结果保持独立前提与虚线圆节点，完整宿主摘要到达前不猜测成立状态', async () => {
    const graph = proofDagExternalFixture()
    const select = vi.fn()
    const {container, rerender} = render(<FaithSieveProofTree tree={graph} onSelect={select} />)
    await waitForDiagram(container, 3)
    expect(container.querySelectorAll('.faithsieve-proof-edge-line')).toHaveLength(2)
    const external = screen.getByRole('button', {name: '外部结果 N2，正弦界'})
    expect(external.classList.contains('is-external')).toBe(true)
    expect(external.classList.contains('is-root')).toBe(false)
    expect(external.classList.contains('is-established')).toBe(false)
    expect(external.style.width).toBe('38px')
    expect(external.style.height).toBe('38px')
    expect(external.title).toBe('N2 · 正弦界 · 外部结果')
    const premises = container.querySelector<HTMLElement>('.faithsieve-proof-premises')!
    expect(within(premises).getAllByRole('button').map((button) => button.textContent)).toEqual(['N1', 'N2'])
    expect(within(premises).getByText('外部结果')).toBeTruthy()
    expect(within(premises).getByText(graph.nodes[1].statement)).toBeTruthy()
    fireEvent.click(within(premises).getByRole('button', {name: 'N2'}))
    expect(select).toHaveBeenLastCalledWith({kind: 'node', id: 'N2'})
    expect(screen.getByRole('heading', {name: 'N2 · 正弦界'})).toBeTruthy()
    expect(screen.getByRole('heading', {name: '外部结果'})).toBeTruthy()
    expect(screen.queryByRole('heading', {name: '初始条件'})).toBeNull()
    expect(screen.queryByRole('heading', {name: '目标'})).toBeNull()
    expect(screen.queryByRole('heading', {name: '前置条件'})).toBeNull()
    expect(screen.getByText(graph.nodes[1].statement)).toBeTruthy()
    expect(screen.getByText('未验证')).toBeTruthy()
    expect(screen.queryByText('已成立')).toBeNull()
    rerender(<FaithSieveProofTree tree={graph} nodeVerification={proofDagExternalVerificationFixture()} onSelect={select} />)
    expect(screen.getByText('已成立')).toBeTruthy()
    expect(external.classList.contains('is-established')).toBe(true)
    expect(external.classList.contains('is-external')).toBe(true)
    fireEvent.click(screen.getByRole('button', {name: '证明结论 N3，目标界'}))
    expect(screen.getByRole('heading', {name: '目标'})).toBeTruthy()
    expect(screen.getByText('已成立')).toBeTruthy()
    expect(screen.queryByText('局部推理已验证')).toBeNull()
  })
  it('v3节点仅展示完整直接前提、目标和宿主结果，不新增引文或步骤映射', async () => {
    const {container} = render(<FaithSieveProofTree tree={proofDagV3Fixture()} nodeVerification={proofDagVerificationFixture()} />)
    await waitForDiagram(container)
    expect(screen.getByRole('heading', {name: '证明依赖图'})).toBeTruthy()
    expect(screen.getByRole('heading', {name: 'N9 · 乘积'})).toBeTruthy()
    expect(screen.getByText('\\((a+b)^2>0\\)')).toBeTruthy()
    expect(screen.getByText('\\((a+b)^3>0\\)')).toBeTruthy()
    expect(screen.getByText('\\((a+b)^5>0\\)')).toBeTruthy()
    expect(screen.getByText('前提待验证')).toBeTruthy()
    expect(container.querySelector('.faithsieve-proof-source')).toBeNull()
    expect(screen.queryByText('原文')).toBeNull()
    expect(screen.queryByText('S4、S12')).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: 'N11'}))
    expect(screen.getByText('\\(a+b>0\\)')).toBeTruthy()
    expect(screen.queryByText('\\((a+b)^3>0\\)')).toBeNull()
  })
  it('绘制多根、分支和唯一合流节点，详情只列直接前提与目标', async () => {
    const graph = proofDagFixture()
    const {container} = render(<FaithSieveProofTree tree={graph} nodeVerification={proofDagVerificationFixture()} />)
    await waitForDiagram(container)
    expect(container.querySelectorAll('[data-proof-node]')).toHaveLength(7)
    expect(container.querySelectorAll('[data-proof-node="N7"]')).toHaveLength(1)
    expect(container.querySelectorAll('.faithsieve-proof-edge-line')).toHaveLength(6)
    expect(container.querySelector('[data-source="N1"][data-target="N9"]')).toBeNull()
    expect(container.querySelectorAll('.faithsieve-proof-edge-label')).toHaveLength(0)
    const details = container.querySelector<HTMLElement>('.faithsieve-proof-details')!
    expect(within(details).getByRole('heading', {name: 'N9 · 乘积'})).toBeTruthy()
    const premises = details.querySelector<HTMLElement>('.faithsieve-proof-premises')!
    expect(within(premises).getAllByRole('button').map((button) => button.textContent)).toEqual(['N11', 'N13'])
    expect(within(premises).getByText('\\((a+b)^2>0\\)')).toBeTruthy()
    expect(within(premises).getByText('\\((a+b)^3>0\\)')).toBeTruthy()
    expect(within(premises).queryByText('\\(a+b>0\\)')).toBeNull()
    expect(within(premises).queryByText('\\(a>0\\)')).toBeNull()
    expect(within(details).getByText('\\((a+b)^5>0\\)')).toBeTruthy()
    expect(within(details).getByText('前提待验证')).toBeTruthy()
    expect(within(details).getByText('局部推理已验证')).toBeTruthy()
    expect(within(details).queryByText('已成立')).toBeNull()
  })
  it('依赖边选择指向结论，不再作为待检验步骤；前提可直接选择', async () => {
    const select = vi.fn()
    const {container} = render(<FaithSieveProofTree tree={proofDagFixture()} onSelect={select} />)
    await waitForDiagram(container)
    fireEvent.keyDown(screen.getByRole('button', {name: '直接依赖 N1 到 N7'}), {key: 'Enter'})
    expect(select).toHaveBeenLastCalledWith({kind: 'node', id: 'N7'})
    expect(screen.getByRole('heading', {name: 'N7 · 和'})).toBeTruthy()
    expect(screen.getByRole('heading', {name: '前置条件'})).toBeTruthy()
    expect(container.querySelector('.faithsieve-proof-state-pair')).toBeNull()
    expect(screen.queryByRole('heading', {name: '条件变化'})).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: 'N4'}))
    expect(select).toHaveBeenLastCalledWith({kind: 'node', id: 'N4'})
    expect(screen.getByRole('heading', {name: 'N4 · 条件 b'})).toBeTruthy()
    expect(screen.queryByRole('heading', {name: '前置条件'})).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: '直接依赖 N7 到 N11'}))
    expect(select).toHaveBeenLastCalledWith({kind: 'node', id: 'N11'})
  })
  it('仅宿主 established 标记已成立，局部反驳不称命题为假', async () => {
    const graph = proofDagFixture()
    const map = proofDagVerificationFixture()
    const {container, rerender} = render(<FaithSieveProofTree tree={graph} nodeVerification={map} />)
    await waitForDiagram(container)
    expect(screen.getByText('前提待验证')).toBeTruthy()
    expect(container.querySelector('[data-proof-node="N9"]')?.classList.contains('is-established')).toBe(false)
    const established = Object.fromEntries(Object.entries(map).map(([id, item]) => [id, {...item, local_status: item.local_status === 'given' ? 'given' as const : 'passed' as const, established: true, status: 'established' as const, blocking_premise_ids: []}]))
    rerender(<FaithSieveProofTree tree={graph} nodeVerification={established} />)
    expect(screen.getByText('已成立')).toBeTruthy()
    expect(container.querySelector('[data-proof-node="N9"]')?.classList.contains('is-established')).toBe(true)
    rerender(<FaithSieveProofTree tree={graph} nodeVerification={{...map, N9: {...map.N9, local_status: 'refuted', status: 'not_established'}}} />)
    expect(screen.getByText('推理被反驳')).toBeTruthy()
    expect(screen.queryByText('结论为假')).toBeNull()
    expect(screen.queryByText('定理为假')).toBeNull()
    expect(screen.queryByText('已成立')).toBeNull()
    expect(container.querySelector('[data-proof-node="N9"]')?.classList.contains('is-refuted')).toBe(true)
  })
  it('未知结果与独立结论如实展示，来源文本保持数学符号且无HTML执行', async () => {
    const graph = proofDagFixture()
    graph.nodes[5].source_text = '<img src=x onerror=alert(1)>\n\\nu 与 u'
    const {container} = render(<FaithSieveProofTree tree={graph} />)
    await waitForDiagram(container)
    expect(screen.getByText('未验证')).toBeTruthy()
    expect(container.querySelector('.faithsieve-proof-source .faithsieve-proof-math')?.textContent).toBe('<img src=x onerror=alert(1)>\n\\nu 与 u')
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('S4、S12')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', {name: '证明结论 N20，恒等式'}))
    expect(screen.getByText('\\(1=1\\)')).toBeTruthy()
    expect(screen.queryByRole('heading', {name: '前置条件'})).toBeNull()
    expect(screen.getByText('未验证')).toBeTruthy()
  })
  it('沿用缩放、展开和键盘收起，隐藏外层重复标题', async () => {
    const {container} = render(<FaithSieveProofTree tree={proofDagFixture()} title="" />)
    await waitForDiagram(container)
    expect(screen.queryByRole('heading', {name: '证明依赖图'})).toBeNull()
    const canvas = container.querySelector<HTMLElement>('.faithsieve-proof-canvas')!
    const initial = canvas.style.transform
    fireEvent.click(screen.getByRole('button', {name: '放大证明依赖图'}))
    expect(canvas.style.transform).not.toBe(initial)
    fireEvent.click(screen.getByRole('button', {name: '展开证明依赖图'}))
    expect(screen.getByRole('dialog', {name: '证明依赖图'})).toBeTruthy()
    expect(screen.getByRole('heading', {name: '证明依赖图（历史）'})).toBeTruthy()
    fireEvent.keyDown(document, {key: 'Escape'})
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.body.style.overflow).toBe('')
  })
})
