import {describe, expect, it} from 'vitest'

import {layoutFaithSieveProofTree, parseFaithSieveProofTree, type FaithSieveJsonProofTree, type FaithSieveLegacyProofTree} from './faithSieveProofTree'

function tree(count = 4, parent = (index: number) => index - 1): FaithSieveJsonProofTree {
  return {schema_version: 1, root_id: 'N1', nodes: Array.from({length: count}, (_, index) => ({id: `N${index + 1}`, label: index ? '推导状态' : '起始状态', conditions: ['\\(x > 0\\)'], goal: '\\(x^2 > 0\\)', scope: []})), edges: Array.from({length: count - 1}, (_, index) => ({id: `E${index + 1}`, from: `N${parent(index + 1) + 1}`, to: `N${index + 2}`, step_id: `S${index + 1}`, source_location: '第 1 页', source_text: '因为 \\(x > 0\\)，所以 \\(x^2 > 0\\)。', changes: {retained: ['\\(x > 0\\)'], added: [], consumed: [], transformed: []}, goal_relation: '目标保持', transition_type: '直接推导', scope: []})), ambiguities: []}
}

describe('证明状态树 JSON', () => {
  it('保留公式和状态，不补写不存在的信息', () => {
    const value = tree()
    const parsed = parseFaithSieveProofTree(value)
    expect(parsed).toEqual(value)
    expect(parsed).not.toBe(value)
    expect('conditions' in parsed.nodes[0] && parsed.nodes[0].conditions).toEqual(['\\(x > 0\\)'])
  })
  it.each([
    ['版本', (value: FaithSieveJsonProofTree) => ({...value, schema_version: 4}), /版本/],
    ['未知字段', (value: FaithSieveJsonProofTree) => ({...value, explanation: 'guess'}), /未知字段/],
    ['根', (value: FaithSieveJsonProofTree) => ({...value, root_id: 'missing'}), /根节点不存在/],
    ['孤立节点', (value: FaithSieveJsonProofTree) => ({...value, edges: value.edges.slice(1)}), /边数/],
    ['重复节点', (value: FaithSieveJsonProofTree) => ({...value, nodes: [value.nodes[0], value.nodes[0], ...value.nodes.slice(2)]}), /重复/],
    ['重复步骤', (value: FaithSieveJsonProofTree) => ({...value, edges: value.edges.map((edge) => ({...edge, step_id: 'S1'}))}), /序号一致/],
    ['跳跃编号', (value: FaithSieveJsonProofTree) => ({...value, edges: value.edges.map((edge, index) => index ? edge : {...edge, id: 'E10'})}), /连续编号/],
    ['空条件', (value: FaithSieveJsonProofTree) => ({...value, nodes: value.nodes.map((node, index) => index ? node : {...node, conditions: ['']})}), /不能为空/],
    ['无效引用', (value: FaithSieveJsonProofTree) => ({...value, edges: value.edges.map((edge, index) => index ? edge : {...edge, to: 'missing'})}), /不存在的节点/],
  ] as const)('明确拒绝%s', (_, change, message) => {expect(() => parseFaithSieveProofTree(change(tree()))).toThrow(message)})
  it('拒绝多父节点和根不可达的循环', () => {
    const value = tree()
    expect(() => parseFaithSieveProofTree({...value, edges: value.edges.map((edge, index) => index === 2 ? {...edge, to: 'N2'} : edge)})).toThrow(/多个父节点/)
    expect(() => parseFaithSieveProofTree({...value, edges: [{...value.edges[0], from: 'N1', to: 'N4'}, {...value.edges[1], from: 'N2', to: 'N3'}, {...value.edges[2], from: 'N3', to: 'N2'}]})).toThrow(/不可达节点或环/)
  })
  it('边与原文步骤逐项对应，Unicode 标量有效', () => {
    const value = tree()
    expect(() => parseFaithSieveProofTree({...value, edges: value.edges.map((edge, index) => ({...edge, step_id: `S${3 - index}`}))})).toThrow(/E 与 S 序号一致/)
    for (const label of ['\ud800', '\udc00', '\ud800\ud800\udc00', '\udc00\ud800']) expect(() => parseFaithSieveProofTree({...value, nodes: value.nodes.map((node, index) => index ? node : {...node, label})})).toThrow(/Unicode/)
    expect(parseFaithSieveProofTree({...value, nodes: value.nodes.map((node, index) => index ? node : {...node, label: '状态 🧮'})}).nodes[0].label).toBe('状态 🧮')
    expect(parseFaithSieveProofTree({...value, nodes: value.nodes.map((node, index) => index ? node : {...node, label: '🧮'.repeat(20_000)})}).nodes[0].label).toHaveLength(40_000)
  })
  it('结构损坏和超限工件不进入布局', () => {
    expect(() => parseFaithSieveProofTree('# N1 → N2')).toThrow(/应为对象/)
    expect(() => parseFaithSieveProofTree({...tree(), nodes: tree(1001).nodes})).toThrow(/1000/)
    const value = tree()
    expect(() => parseFaithSieveProofTree({...value, nodes: value.nodes.map((node, index) => index ? node : {...node, label: 'x'.repeat(20_001)})})).toThrow(/字符串过长/)
    expect(() => parseFaithSieveProofTree({...value, nodes: value.nodes.map((node, index) => index ? node : {...node, conditions: Array.from({length: 501}, () => 'x')})})).toThrow(/500/)
    expect(() => parseFaithSieveProofTree({...value, nodes: value.nodes.map((node) => ({...node, conditions: Array.from({length: 40}, () => '字'.repeat(20_000))}))})).toThrow(/2 MiB/)
  })
  it('历史结构只保留原状态、引用和变化字串', () => {
    const raw = '\\(\\Gamma_2=\\Gamma_1\\cup\\{x>0\\}\\)，其余沿用 N1。'
    const legacy: FaithSieveLegacyProofTree = {schema_version: 1, format: 'legacy_markdown', root_id: 'N1', nodes: [{id: 'N1', label: '初始状态', raw_state: raw}, {id: 'N2', label: '后续状态', raw_state: ''}], edges: [{id: 'E1', from: 'N1', to: 'N2', step_id: 'S1', source_location: '', source_text: '', raw_input: '沿用 N1', raw_output: '见 N2', raw_changes: raw, goal_relation: '', transition_type: '', scope_text: ''}], ambiguities: []}
    expect(parseFaithSieveProofTree(legacy)).toEqual(legacy)
    expect(() => parseFaithSieveProofTree({...legacy, nodes: legacy.nodes.map((node) => ({...node, goal: '猜测'}))})).toThrow(/未知字段/)
  })
})

describe('证明状态树自然布局', () => {
  it('32 节点长链自然展开，圆节点不重叠且不排成一根长直线', () => {
    const value = tree(32)
    const graph = layoutFaithSieveProofTree(value)
    expect(layoutFaithSieveProofTree(value)).toEqual(graph)
    expect(graph.width).toBeLessThan(1100)
    expect(graph.height).toBeLessThan(1100)
    expect(Math.max(graph.width / graph.height, graph.height / graph.width)).toBeLessThan(3)
    const points = Object.values(graph.positions)
    for (let index = 0; index < points.length; index++) for (let other = index + 1; other < points.length; other++) expect(Math.hypot(points[index].x - points[other].x, points[index].y - points[other].y)).toBeGreaterThan(42)
    const slopes = value.edges.map((edge) => {const from = graph.positions[edge.from]; const to = graph.positions[edge.to]; return Math.atan2(to.y - from.y, to.x - from.x)})
    expect(new Set(slopes.map((angle) => Math.round(angle * 10))).size).toBeGreaterThan(10)
  })
  it('保留真实父子分支，支持一百个以上节点', () => {
    const value = tree(180, (index) => Math.floor((index - 1) / 3))
    const graph = layoutFaithSieveProofTree(value)
    expect(Object.keys(graph.positions)).toHaveLength(180)
    expect(graph.width).toBeLessThan(3000)
    expect(graph.height).toBeLessThan(3000)
    for (const point of Object.values(graph.positions)) {expect(Number.isFinite(point.x)).toBe(true); expect(Number.isFinite(point.y)).toBe(true)}
    const root = graph.positions.N1
    const angles = ['N2', 'N3', 'N4'].map((id) => Math.atan2(graph.positions[id].y - root.y, graph.positions[id].x - root.x))
    expect(Math.max(...angles) - Math.min(...angles)).toBeGreaterThan(1)
  })
  it.each([['链', (index: number) => index - 1], ['分叉', () => 0]] as const)('最大允许规模的%s保持圆节点间距', (_, parent) => {
    const graph = layoutFaithSieveProofTree(tree(1000, parent))
    const points = Object.values(graph.positions)
    let minimum = Infinity
    for (let index = 0; index < points.length; index++) for (let other = index + 1; other < points.length; other++) minimum = Math.min(minimum, Math.hypot(points[index].x - points[other].x, points[index].y - points[other].y))
    expect(points).toHaveLength(1000)
    expect(minimum).toBeGreaterThan(42)
    expect(graph.width).toBeLessThan(4000)
    expect(graph.height).toBeLessThan(4000)
  })
})
