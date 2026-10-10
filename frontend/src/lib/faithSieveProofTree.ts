import {parseFaithSieveProofDag, type FaithSieveProofDagData} from './faithSieveProofDag'
export {faithSieveDagPremises, parseFaithSieveNodeVerification, type FaithSieveProofDagData, type FaithSieveProofDagNode, type FaithSieveProofDagV2Node, type FaithSieveProofDagV2Data, type FaithSieveProofDagV3Data, type FaithSieveProofDagEdge, type FaithSieveProofNodeVerification, type FaithSieveProofNodeVerificationMap} from './faithSieveProofDag'

export interface FaithSieveProofNode {
  id: string
  label: string
  conditions: string[]
  goal: string
  scope: string[]
}

export interface FaithSieveProofEdge {
  id: string
  from: string
  to: string
  step_id: string
  source_location: string
  source_text: string
  changes: {retained: string[]; added: string[]; consumed: string[]; transformed: string[]}
  goal_relation: string
  transition_type: string
  scope: string[]
}

export interface FaithSieveLegacyProofNode {id: string; label: string; raw_state: string}
export interface FaithSieveLegacyProofEdge {
  id: string
  from: string
  to: string
  step_id: string
  source_location: string
  source_text: string
  raw_input: string
  raw_output: string
  raw_changes: string
  goal_relation: string
  transition_type: string
  scope_text: string
}

export interface FaithSieveJsonProofTree {
  schema_version: 1
  root_id: string
  nodes: FaithSieveProofNode[]
  edges: FaithSieveProofEdge[]
  ambiguities: string[]
}

export interface FaithSieveLegacyProofTree {
  schema_version: 1
  format: 'legacy_markdown'
  root_id: string
  nodes: FaithSieveLegacyProofNode[]
  edges: FaithSieveLegacyProofEdge[]
  ambiguities: string[]
}

export type FaithSieveHistoricalProofTreeData = FaithSieveJsonProofTree | FaithSieveLegacyProofTree
export type FaithSieveProofTreeData = FaithSieveHistoricalProofTreeData | FaithSieveProofDagData
export type FaithSieveProofTreeSelection = {kind: 'node' | 'edge'; id: string}
export type FaithSieveProofPoint = {x: number; y: number}
export interface FaithSieveProofTreeLayout {positions: Record<string, FaithSieveProofPoint>; width: number; height: number}

const MAX_BYTES = 2 * 1024 * 1024
const MAX_NODES = 1000
const ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/

function invalid(path: string, message: string): never {throw new Error(`证明状态树 ${path}：${message}`)}
function object(value: unknown, path: string, keys: string[]) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(path, '应为对象')
  const record = value as Record<string, unknown>
  for (const key of keys) if (!Object.hasOwn(record, key)) invalid(`${path}.${key}`, '缺少字段')
  for (const key of Object.keys(record)) if (!keys.includes(key)) invalid(`${path}.${key}`, '未知字段')
  return record
}

/** 只接受 JSON 结构；不会把 Markdown 或不完整的对象修补成一棵树。 */
export function parseFaithSieveProofTree(value: unknown): FaithSieveProofTreeData {
  if (value && typeof value === 'object' && [2, 3].includes((value as Record<string, unknown>).schema_version as number)) return parseFaithSieveProofDag(value)
  let bytes = 0
  const text = (input: unknown, path: string, allowEmpty = false): string => {
    if (typeof input !== 'string') invalid(path, '应为字符串')
    if (!allowEmpty && !input.trim()) invalid(path, '不能为空')
    if (input.length > 40_000) invalid(path, '字符串过长')
    let characters = 0
    for (let index = 0; index < input.length; index++) {
      if (++characters > 20_000) invalid(path, '字符串过长')
      const unit = input.charCodeAt(index)
      if (unit >= 0xd800 && unit <= 0xdbff) {const next = input.charCodeAt(++index); if (!(next >= 0xdc00 && next <= 0xdfff)) invalid(path, '包含无效 Unicode 字符')}
      else if (unit >= 0xdc00 && unit <= 0xdfff) invalid(path, '包含无效 Unicode 字符')
    }
    bytes += new TextEncoder().encode(input).byteLength
    if (bytes > MAX_BYTES) invalid('$', '内容超过 2 MiB')
    return input
  }
  const strings = (input: unknown, path: string) => {
    if (!Array.isArray(input) || input.length > 500) invalid(path, '应为不超过 500 项的字符串数组')
    return input.map((item, index) => text(item, `${path}[${index}]`))
  }
  const id = (input: unknown, path: string) => {
    const result = text(input, path)
    if (!ID_PATTERN.test(result)) invalid(path, '标识符格式无效')
    return result
  }
  const legacy = !!value && typeof value === 'object' && (value as Record<string, unknown>).format === 'legacy_markdown'
  const raw = object(value, '$', ['schema_version', ...(legacy ? ['format'] : []), 'root_id', 'nodes', 'edges', 'ambiguities'])
  if (raw.schema_version !== 1) invalid('schema_version', '不支持的版本')
  if (!Array.isArray(raw.nodes) || raw.nodes.length < 2 || raw.nodes.length > MAX_NODES) invalid('nodes', '应包含 2 至 1000 个节点')
  if (!Array.isArray(raw.edges) || raw.edges.length !== raw.nodes.length - 1) invalid('edges', '边数必须等于节点数减一')
  const rootId = id(raw.root_id, 'root_id')
  const nodes = raw.nodes.map((input, index) => {
    const path = `nodes[${index}]`
    const node = object(input, path, legacy ? ['id', 'label', 'raw_state'] : ['id', 'label', 'conditions', 'goal', 'scope'])
    const base = {id: id(node.id, `${path}.id`), label: text(node.label, `${path}.label`)}
    return legacy ? {...base, raw_state: text(node.raw_state, `${path}.raw_state`, true)} : {...base, conditions: strings(node.conditions, `${path}.conditions`), goal: text(node.goal, `${path}.goal`), scope: strings(node.scope, `${path}.scope`)}
  })
  const edges = raw.edges.map((input, index) => {
    const path = `edges[${index}]`
    const edge = object(input, path, ['id', 'from', 'to', 'step_id', 'source_location', 'source_text', ...(legacy ? ['raw_input', 'raw_output', 'raw_changes', 'goal_relation', 'transition_type', 'scope_text'] : ['changes', 'goal_relation', 'transition_type', 'scope'])])
    const base = {id: id(edge.id, `${path}.id`), from: id(edge.from, `${path}.from`), to: id(edge.to, `${path}.to`), step_id: id(edge.step_id, `${path}.step_id`), source_location: text(edge.source_location, `${path}.source_location`, legacy), source_text: text(edge.source_text, `${path}.source_text`, legacy), goal_relation: text(edge.goal_relation, `${path}.goal_relation`, legacy), transition_type: text(edge.transition_type, `${path}.transition_type`, legacy)}
    if (base.id !== `E${index + 1}` || base.step_id !== `S${index + 1}`) invalid(path, '应按原文顺序连续编号，且 E 与 S 序号一致')
    if (legacy) return {...base, raw_input: text(edge.raw_input, `${path}.raw_input`, true), raw_output: text(edge.raw_output, `${path}.raw_output`, true), raw_changes: text(edge.raw_changes, `${path}.raw_changes`, true), scope_text: text(edge.scope_text, `${path}.scope_text`, true)}
    const changes = object(edge.changes, `${path}.changes`, ['retained', 'added', 'consumed', 'transformed'])
    return {...base, changes: {retained: strings(changes.retained, `${path}.changes.retained`), added: strings(changes.added, `${path}.changes.added`), consumed: strings(changes.consumed, `${path}.changes.consumed`), transformed: strings(changes.transformed, `${path}.changes.transformed`)}, scope: strings(edge.scope, `${path}.scope`)}
  })
  const nodeIds = new Set<string>()
  for (const node of nodes) {if (nodeIds.has(node.id)) invalid(`nodes.${node.id}`, '节点标识符重复'); nodeIds.add(node.id)}
  if (!nodeIds.has(rootId)) invalid('root_id', '根节点不存在')
  const edgeIds = new Set<string>()
  const steps = new Set<string>()
  const parents = new Set<string>()
  const children = new Map<string, string[]>()
  for (const edge of edges) {
    if (edgeIds.has(edge.id)) invalid(`edges.${edge.id}`, '边标识符重复')
    if (steps.has(edge.step_id)) invalid(`edges.${edge.id}.step_id`, '步骤标识符重复')
    edgeIds.add(edge.id); steps.add(edge.step_id)
    if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) invalid(`edges.${edge.id}`, '引用了不存在的节点')
    if (edge.from === edge.to) invalid(`edges.${edge.id}`, '节点不能指向自身')
    if (edge.to === rootId) invalid(`edges.${edge.id}`, '根节点不能有父节点')
    if (parents.has(edge.to)) invalid(`edges.${edge.id}`, '子节点有多个父节点')
    parents.add(edge.to)
    children.set(edge.from, [...(children.get(edge.from) || []), edge.to])
  }
  for (let index = 1; index <= edges.length; index++) {
    if (!edgeIds.has(`E${index}`)) invalid('edges.id', '应连续编号为 E1、E2、…')
    if (!steps.has(`S${index}`)) invalid('edges.step_id', '应连续编号为 S1、S2、…')
  }
  const reachable = new Set([rootId])
  const queue = [rootId]
  for (let offset = 0; offset < queue.length; offset++) for (const child of children.get(queue[offset]) || []) {
    if (reachable.has(child)) invalid('edges', '包含环')
    reachable.add(child); queue.push(child)
  }
  if (reachable.size !== nodes.length) invalid('edges', '存在不可达节点或环')
  const ambiguities = strings(raw.ambiguities, 'ambiguities')
  // 对 JSON 字段名、标点和转义也计入工件大小。
  if (new TextEncoder().encode(JSON.stringify(value)).byteLength > MAX_BYTES) invalid('$', '内容超过 2 MiB')
  return legacy
    ? {schema_version: 1, format: 'legacy_markdown', root_id: rootId, nodes: nodes as FaithSieveLegacyProofNode[], edges: edges as FaithSieveLegacyProofEdge[], ambiguities}
    : {schema_version: 1, root_id: rootId, nodes: nodes as FaithSieveProofNode[], edges: edges as FaithSieveProofEdge[], ambiguities}
}

const EDGE_LENGTH = 78
const NODE_DISTANCE = 48
const MARGIN = 36

/** 以树的分支扇区和连续枝干为初始位置，再做确定性的弹簧布局。 */
export function layoutFaithSieveProofTree(tree: FaithSieveHistoricalProofTreeData): FaithSieveProofTreeLayout {
  return layoutHistoricalProofTree(tree)
}

function layoutHistoricalProofTree(tree: FaithSieveHistoricalProofTreeData): FaithSieveProofTreeLayout {
  const indices = new Map(tree.nodes.map((node, index) => [node.id, index]))
  const children: number[][] = tree.nodes.map(() => [])
  const pairs = tree.edges.map((edge) => ({from: indices.get(edge.from)!, to: indices.get(edge.to)!}))
  for (const edge of pairs) children[edge.from].push(edge.to)
  const root = indices.get(tree.root_id)!
  const points = initialTreePoints(children, root)
  const lengths = pairs.map(({from, to}) => children[from].length > 8 ? Math.hypot(points[to].x - points[from].x, points[to].y - points[from].y) : EDGE_LENGTH)
  return relaxLayout(tree.nodes.map((node) => node.id), points, pairs, lengths, root)
}

function initialTreePoints(children: number[][], root: number) {
  const order = [root]
  for (let offset = 0; offset < order.length; offset++) order.push(...children[order[offset]])
  const leaves = children.map(() => 1)
  for (let offset = order.length - 1; offset >= 0; offset--) {const node = order[offset]; if (children[node].length) leaves[node] = children[node].reduce((sum, child) => sum + leaves[child], 0)}
  const points = children.map(() => ({x: 0, y: 0}))
  const sectors: {node: number; start: number; end: number}[] = [{node: root, start: -Math.PI, end: Math.PI}]
  const coil = (step: number) => {
    const spacing = 14
    const theta0 = EDGE_LENGTH / spacing
    const theta = Math.sqrt(theta0 * theta0 + 2 * step * EDGE_LENGTH / spacing) - theta0
    const radius = spacing * (theta0 + theta)
    return {x: radius * Math.cos(theta) - EDGE_LENGTH, y: radius * Math.sin(theta)}
  }
  const initial = coil(1)
  const initialAngle = Math.atan2(initial.y, initial.x)
  for (let offset = 0; offset < sectors.length; offset++) {
    const {node, start, end} = sectors[offset]
    let angle = start
    children[node].forEach((first, childIndex) => {
      const span = (end - start) * leaves[first] / leaves[node]
      const wideFan = children[node].length > 8
      const direction = wideFan ? (start + end) / 2 + childIndex * 2.399963 : angle + span / 2
      const fanScale = wideFan ? NODE_DISTANCE * 1.18 * Math.sqrt(childIndex + 1) / Math.hypot(initial.x, initial.y) : 1
      const turn = childIndex % 2 ? -1 : 1
      const rotation = direction - initialAngle * turn
      let child = first
      let step = 1
      while (true) {
        const local = coil(step)
        const x = local.x + initial.x * (fanScale - 1)
        const y = (local.y + initial.y * (fanScale - 1)) * turn
        points[child] = {x: points[node].x + x * Math.cos(rotation) - y * Math.sin(rotation), y: points[node].y + x * Math.sin(rotation) + y * Math.cos(rotation)}
        if (children[child].length !== 1) break
        child = children[child][0]; step++
      }
      sectors.push({node: child, start: angle, end: angle + span})
      angle += span
    })
  }
  return points
}

function relaxLayout(ids: string[], points: FaithSieveProofPoint[], pairs: {from: number; to: number}[], lengths: number[], root: number): FaithSieveProofTreeLayout {
  const velocity = points.map(() => ({x: 0, y: 0}))
  const iterations = points.length > 180 ? 140 : 200
  const gravity = 0.0032 * Math.min(1, 160 / points.length)
  for (let iteration = 0; iteration < iterations; iteration++) {
    const forces = points.map((point) => ({x: -point.x * gravity, y: -point.y * gravity}))
    const repel = (left: number, right: number) => {
      let dx = points[left].x - points[right].x
      let dy = points[left].y - points[right].y
      let distance = Math.hypot(dx, dy)
      if (distance < 0.01) {const angle = (left + right + 1) * 2.399963; dx = Math.cos(angle); dy = Math.sin(angle); distance = 1}
      const strength = Math.min(16, 1800 / Math.max(distance * distance, 16))
      const fx = dx / distance * strength
      const fy = dy / distance * strength
      forces[left].x += fx; forces[left].y += fy; forces[right].x -= fx; forces[right].y -= fy
    }
    if (points.length <= 180) {
      for (let left = 0; left < points.length; left++) for (let right = left + 1; right < points.length; right++) repel(left, right)
    } else {
      // 大树只计算邻近空间格的斥力，避免每轮遍历所有节点对。
      const cells = new Map<string, number[]>()
      points.forEach((point, index) => {const key = `${Math.floor(point.x / 180)},${Math.floor(point.y / 180)}`; const cell = cells.get(key); if (cell) cell.push(index); else cells.set(key, [index])})
      points.forEach((point, left) => {
        const x = Math.floor(point.x / 180)
        const y = Math.floor(point.y / 180)
        for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) for (const right of cells.get(`${x + dx},${y + dy}`) || []) if (right > left) repel(left, right)
      })
    }
    for (let index = 0; index < pairs.length; index++) {
      const {from, to} = pairs[index]
      const dx = points[to].x - points[from].x
      const dy = points[to].y - points[from].y
      const distance = Math.hypot(dx, dy) || 1
      const strength = (distance - lengths[index]) * 0.065
      const fx = dx / distance * strength
      const fy = dy / distance * strength
      forces[from].x += fx; forces[from].y += fy; forces[to].x -= fx; forces[to].y -= fy
    }
    const limit = 11 * (1 - iteration / iterations) + 0.4
    points.forEach((point, index) => {
      if (index === root) return
      const motion = velocity[index]
      motion.x = (motion.x + forces[index].x) * 0.72
      motion.y = (motion.y + forces[index].y) * 0.72
      const distance = Math.hypot(motion.x, motion.y) || 1
      const factor = Math.min(1, limit / distance)
      point.x += motion.x * factor; point.y += motion.y * factor
    })
  }
  // 终态消除圆节点碰撞；保持边为父子之间的真实直线。
  for (let iteration = 0; iteration < 12; iteration++) {
    const cells = new Map<string, number[]>()
    points.forEach((point, index) => {const key = `${Math.floor(point.x / NODE_DISTANCE)},${Math.floor(point.y / NODE_DISTANCE)}`; const cell = cells.get(key); if (cell) cell.push(index); else cells.set(key, [index])})
    points.forEach((point, left) => {
      const x = Math.floor(point.x / NODE_DISTANCE)
      const y = Math.floor(point.y / NODE_DISTANCE)
      for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) for (const right of cells.get(`${x + dx},${y + dy}`) || []) {
        if (right <= left) continue
        const other = points[right]
        let deltaX = other.x - point.x
        let deltaY = other.y - point.y
        let distance = Math.hypot(deltaX, deltaY)
        if (distance >= NODE_DISTANCE) continue
        if (distance < 0.01) {deltaX = 1; deltaY = 0; distance = 1}
        const shift = (NODE_DISTANCE - distance) / (left === root || right === root ? 1 : 2)
        if (left !== root) {point.x -= deltaX / distance * shift; point.y -= deltaY / distance * shift}
        if (right !== root) {other.x += deltaX / distance * shift; other.y += deltaY / distance * shift}
      }
    })
  }
  const minX = Math.min(...points.map((point) => point.x))
  const minY = Math.min(...points.map((point) => point.y))
  const maxX = Math.max(...points.map((point) => point.x))
  const maxY = Math.max(...points.map((point) => point.y))
  return {positions: Object.fromEntries(ids.map((id, index) => [id, {x: points[index].x - minX + MARGIN, y: points[index].y - minY + MARGIN}])), width: maxX - minX + MARGIN * 2, height: maxY - minY + MARGIN * 2}
}
