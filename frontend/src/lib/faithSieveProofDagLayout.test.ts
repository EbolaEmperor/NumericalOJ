import {describe, expect, it} from 'vitest'

import {proofDagFixture, proofDagV3Fixture} from '../test/faithSieveProofDag'
import {denseProofDagTopologyFixture} from '../test/faithSieveProofDagTopology'
import type {FaithSieveProofDagData, FaithSieveProofDagV3Data} from './faithSieveProofDag'
import {layoutFaithSieveProofDag, type FaithSieveProofDagLayout} from './faithSieveProofDagLayout'
import type {FaithSieveProofPoint} from './faithSieveProofTree'

function segmentDistance(point: FaithSieveProofPoint, start: FaithSieveProofPoint, end: FaithSieveProofPoint) {
  const dx = end.x - start.x; const dy = end.y - start.y
  const length = dx * dx + dy * dy
  const projection = length ? Math.max(0, Math.min(1, ((point.x - start.x) * dx + (point.y - start.y) * dy) / length)) : 0
  return Math.hypot(point.x - start.x - projection * dx, point.y - start.y - projection * dy)
}

function expectCompleteLayout(graph: FaithSieveProofDagData, layout: FaithSieveProofDagLayout) {
  expect(Object.keys(layout.positions).sort()).toEqual(graph.nodes.map(({id}) => id).sort())
  expect(Object.keys(layout.edgeRoutes).sort()).toEqual(graph.edges.map(({id}) => id).sort())
  for (const point of Object.values(layout.positions)) {
    expect(Number.isFinite(point.x)).toBe(true); expect(Number.isFinite(point.y)).toBe(true)
    expect(point.x).toBeGreaterThanOrEqual(19); expect(point.x).toBeLessThanOrEqual(layout.width - 19)
    expect(point.y).toBeGreaterThanOrEqual(19); expect(point.y).toBeLessThanOrEqual(layout.height - 19)
  }
  for (const {id, from, to} of graph.edges) {
    const route = layout.edgeRoutes[id]
    expect(route.length).toBeGreaterThanOrEqual(2)
    expect(layout.positions[to].y).toBeGreaterThan(layout.positions[from].y + 38)
    expect(Math.hypot(route[0].x - layout.positions[from].x, route[0].y - layout.positions[from].y)).toBeCloseTo(19)
    expect(Math.hypot(route.at(-1)!.x - layout.positions[to].x, route.at(-1)!.y - layout.positions[to].y)).toBeCloseTo(19)
    for (const point of route) {
      expect(Number.isFinite(point.x)).toBe(true); expect(Number.isFinite(point.y)).toBe(true)
      expect(point.x).toBeGreaterThanOrEqual(0); expect(point.x).toBeLessThanOrEqual(layout.width)
      expect(point.y).toBeGreaterThanOrEqual(0); expect(point.y).toBeLessThanOrEqual(layout.height)
    }
  }
}

function chain(count: number): FaithSieveProofDagV3Data {
  return {
    schema_version: 3,
    nodes: Array.from({length: count}, (_, index) => ({id: `N${index + 1}`, kind: index ? 'claim' : 'given', label: `命题 ${index + 1}`, statement: `${index + 1} = ${index + 1}`})),
    edges: Array.from({length: count - 1}, (_, index) => ({id: `D${index + 1}`, from: `N${index + 1}`, to: `N${index + 2}`})),
    target_ids: [`N${count}`], ambiguities: [],
  }
}

describe('ELK Layered 证明 DAG 布局', () => {
  it('真实算法保留多根、合流及独立结论，节点不重叠且前提总位于结论上方', async () => {
    const graph = proofDagFixture()
    const layout = await layoutFaithSieveProofDag(graph)
    expectCompleteLayout(graph, layout)
    const points = Object.values(layout.positions)
    for (const [index, point] of points.entries()) for (const other of points.slice(index + 1)) expect(Math.hypot(point.x - other.x, point.y - other.y)).toBeGreaterThan(42)
    expect(layout.positions.N1.y).toBeCloseTo(layout.positions.N4.y)
    expect(layout.positions.N11.y).toBeCloseTo(layout.positions.N13.y)
    expect(layout.positions.N11.x).not.toBe(layout.positions.N13.x)
    expect(Object.keys(layout.positions).filter((id) => id === 'N9')).toHaveLength(1)
  })

  it('同一输入得到确定布局，v2与v3的来源字段不会影响几何或修改证明内容', async () => {
    const graph = proofDagFixture()
    const before = JSON.parse(JSON.stringify(graph))
    const layout = await layoutFaithSieveProofDag(graph)
    expect(await layoutFaithSieveProofDag(proofDagFixture())).toEqual(layout)
    expect(await layoutFaithSieveProofDag(proofDagV3Fixture())).toEqual(layout)
    expect(graph).toEqual(before)
  })

  it('跨越多个层次的依赖保留折点，并绕开无关节点', async () => {
    const graph = chain(7)
    graph.nodes = [graph.nodes[4], graph.nodes[0], graph.nodes[5], graph.nodes[2], graph.nodes[6], graph.nodes[1], graph.nodes[3]]
    graph.edges.push({id: 'D20', from: 'N1', to: 'N7'})
    const layout = await layoutFaithSieveProofDag(graph)
    expectCompleteLayout(graph, layout)
    const route = layout.edgeRoutes.D20
    expect(route.length).toBeGreaterThan(2)
    for (const {id} of graph.nodes.filter(({id}) => id !== 'N1' && id !== 'N7')) for (let segment = 1; segment < route.length; segment++) {
      expect(segmentDistance(layout.positions[id], route[segment - 1], route[segment])).toBeGreaterThanOrEqual(19)
    }
  })

  it('真实密集拓扑中的每条跨层路由均绕开无关圆节点，不删除任何依赖', async () => {
    const graph = denseProofDagTopologyFixture()
    const layout = await layoutFaithSieveProofDag(graph)
    expectCompleteLayout(graph, layout)
    expect(graph.nodes).toHaveLength(36)
    expect(graph.edges).toHaveLength(92)
    for (const edge of graph.edges) {
      const route = layout.edgeRoutes[edge.id]
      for (const node of graph.nodes.filter(({id}) => id !== edge.from && id !== edge.to)) {
        for (let segment = 1; segment < route.length; segment++) {
          expect(segmentDistance(layout.positions[node.id], route[segment - 1], route[segment]), `${edge.id} 不应穿过 ${node.id}`).toBeGreaterThanOrEqual(19)
        }
      }
    }
  })

  it('没有依赖的单个结论仍可布局，不创建虚构根或连线', async () => {
    const graph: FaithSieveProofDagV3Data = {schema_version: 3, nodes: [{id: 'N20', kind: 'claim', label: '恒等式', statement: '1=1'}], edges: [], target_ids: ['N20'], ambiguities: []}
    const layout = await layoutFaithSieveProofDag(graph)
    expectCompleteLayout(graph, layout)
    expect(layout.edgeRoutes).toEqual({})
    expect(layout.width).toBeGreaterThanOrEqual(38)
    expect(layout.height).toBeGreaterThanOrEqual(38)
  })

  it.each([32, 128, 1000])('%i 个节点长链按真实依赖逐层排布，保留可读节点间距和每条边', async (count) => {
    const graph = chain(count)
    const layout = await layoutFaithSieveProofDag(graph)
    expectCompleteLayout(graph, layout)
    for (let index = 1; index < count; index++) {
      const spacing = layout.positions[`N${index + 1}`].y - layout.positions[`N${index}`].y
      expect(spacing).toBeGreaterThanOrEqual(64)
      expect(spacing).toBeLessThanOrEqual(76)
      const route = layout.edgeRoutes[`D${index}`]
      expect(route).toHaveLength(2)
      expect(Math.hypot(route[1].x - route[0].x, route[1].y - route[0].y)).toBeLessThanOrEqual(38)
    }
    expect(layout.width).toBeLessThan(200)
    expect(layout.height).toBeGreaterThan(count * 64)
    expect(layout.height).toBeLessThan(count * 76)
  }, 15_000)

  it('拒绝循环输入而不靠布局算法反转证明依赖', async () => {
    const graph = chain(2)
    graph.edges.push({id: 'D2', from: 'N2', to: 'N1'})
    await expect(layoutFaithSieveProofDag(graph)).rejects.toThrow(/包含环/)
  })
})
