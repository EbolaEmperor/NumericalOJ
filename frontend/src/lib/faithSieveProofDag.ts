export interface FaithSieveProofDagNode {
  id: string
  kind: 'given' | 'external' | 'claim'
  label: string
  statement: string
}
export interface FaithSieveProofDagV2Node extends FaithSieveProofDagNode {
  kind: 'given' | 'claim'
  source_type: 'problem' | 'submission'
  step_ids: string[]
  source_location: string
  source_text: string
}
export interface FaithSieveProofDagEdge {id: string; from: string; to: string}
export interface FaithSieveProofDagV2Data {schema_version: 2; nodes: FaithSieveProofDagV2Node[]; edges: FaithSieveProofDagEdge[]; target_ids: string[]; ambiguities: string[]}
export interface FaithSieveProofDagV3Data {schema_version: 3; nodes: FaithSieveProofDagNode[]; edges: FaithSieveProofDagEdge[]; target_ids: string[]; ambiguities: string[]}
export type FaithSieveProofDagData = FaithSieveProofDagV2Data | FaithSieveProofDagV3Data
export interface FaithSieveProofNodeVerification {
  local_status: 'given' | 'external' | 'passed' | 'refuted' | 'inconclusive' | 'not_checked'
  established: boolean
  status: 'established' | 'blocked' | 'not_established' | 'not_checked'
  premise_ids: string[]
  blocking_premise_ids: string[]
}
export type FaithSieveProofNodeVerificationMap = Record<string, FaithSieveProofNodeVerification>

const MAX_BYTES = 2 * 1024 * 1024
function invalid(path: string, message: string): never {throw new Error(`证明依赖图 ${path}：${message}`)}
function object(value: unknown, path: string, keys: string[]) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(path, '应为对象')
  const record = value as Record<string, unknown>
  for (const key of keys) if (!Object.hasOwn(record, key)) invalid(`${path}.${key}`, '缺少字段')
  for (const key of Object.keys(record)) if (!keys.includes(key)) invalid(`${path}.${key}`, '未知字段')
  return record
}
function text(input: unknown, path: string) {
  if (typeof input !== 'string' || !input.trim()) invalid(path, '应为非空字符串')
  let characters = 0
  for (let index = 0; index < input.length; index++) {
    if (++characters > 20_000) invalid(path, '字符串过长')
    const unit = input.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {const next = input.charCodeAt(++index); if (!(next >= 0xdc00 && next <= 0xdfff)) invalid(path, '包含无效 Unicode 字符')}
    else if (unit >= 0xdc00 && unit <= 0xdfff) invalid(path, '包含无效 Unicode 字符')
  }
  return input
}
function id(input: unknown, path: string, prefix: 'N' | 'D' | 'S' = 'N') {
  const result = text(input, path)
  if (result.length > 64 || !new RegExp(`^${prefix}[1-9][0-9]*$`).test(result)) invalid(path, '标识符格式无效')
  return result
}
function strings(value: unknown, path: string, maximum = 500) {
  if (!Array.isArray(value) || value.length > maximum) invalid(path, `应为不超过 ${maximum} 项的数组`)
  return value.map((item, index) => text(item, `${path}[${index}]`))
}

/** 稳定拓扑次序只用于布局和检查；前提始终直接从真实依赖边读取。 */
export function faithSieveDagNodeOrder(graph: FaithSieveProofDagData) {
  const index = new Map(graph.nodes.map((node, position) => [node.id, position]))
  const incoming = graph.nodes.map(() => 0)
  const children: number[][] = graph.nodes.map(() => [])
  for (const edge of graph.edges) {const from = index.get(edge.from)!; const to = index.get(edge.to)!; incoming[to]++; children[from].push(to)}
  const ready = incoming.flatMap((count, position) => count ? [] : [position])
  const ordered: number[] = []
  while (ready.length) {
    const current = ready.shift()!
    ordered.push(current)
    for (const child of children[current]) if (--incoming[child] === 0) {
      let low = 0; let high = ready.length
      while (low < high) {const middle = (low + high) >>> 1; if (ready[middle] < child) low = middle + 1; else high = middle}
      ready.splice(low, 0, child)
    }
  }
  if (ordered.length !== graph.nodes.length) invalid('edges', '包含环')
  return ordered
}

export function faithSieveDagPremises(graph: FaithSieveProofDagData, nodeId: string) {
  const incoming = new Set(graph.edges.filter((edge) => edge.to === nodeId).map((edge) => edge.from))
  return graph.nodes.filter((node) => incoming.has(node.id))
}

/** 原生读取各版本，不补写原句或把历史结构转换为新图。 */
export function parseFaithSieveProofDag(value: unknown): FaithSieveProofDagData {
  const raw = object(value, '$', ['schema_version', 'nodes', 'edges', 'target_ids', 'ambiguities'])
  if (raw.schema_version !== 2 && raw.schema_version !== 3) invalid('schema_version', '不支持的版本')
  if (!Array.isArray(raw.nodes) || !raw.nodes.length || raw.nodes.length > 1000) invalid('nodes', '应包含 1 至 1000 个节点')
  if (!Array.isArray(raw.edges) || raw.edges.length > raw.nodes.length * (raw.nodes.length - 1) / 2) invalid('edges', '依赖边数超过 DAG 上限')
  const nodes = raw.nodes.map((input, index) => {
    const path = `nodes[${index}]`
    const node = object(input, path, ['id', 'kind', 'label', 'statement', ...(raw.schema_version === 2 ? ['source_type', 'step_ids', 'source_location', 'source_text'] : [])])
    if (node.kind !== 'given' && node.kind !== 'claim' && !(raw.schema_version === 3 && node.kind === 'external')) invalid(`${path}.kind`, raw.schema_version === 3 ? '应为 given、external 或 claim' : '应为 given 或 claim')
    const base: FaithSieveProofDagNode = {id: id(node.id, `${path}.id`), kind: node.kind, label: text(node.label, `${path}.label`), statement: text(node.statement, `${path}.statement`)}
    if (raw.schema_version === 3) return base
    const steps = strings(node.step_ids, `${path}.step_ids`).map((step, offset) => id(step, `${path}.step_ids[${offset}]`, 'S'))
    if (node.kind === 'given' ? node.source_type !== 'problem' || steps.length > 0 : node.source_type !== 'submission' || !steps.length) invalid(path, '节点种类、来源与步骤不一致')
    if (steps.some((step, offset) => offset > 0 && BigInt(step.slice(1)) <= BigInt(steps[offset - 1].slice(1)))) invalid(`${path}.step_ids`, '步骤应严格按原文顺序排列且不重复')
    return {...base, source_type: node.source_type as 'problem' | 'submission', step_ids: steps, source_location: text(node.source_location, `${path}.source_location`), source_text: text(node.source_text, `${path}.source_text`)}
  })
  const ids = new Set(nodes.map((node) => node.id))
  if (ids.size !== nodes.length) invalid('nodes', '节点标识符重复')
  const pairs = new Set<string>()
  const edgeIds = new Set<string>()
  const edges = raw.edges.map((input, index) => {
    const path = `edges[${index}]`; const edge = object(input, path, ['id', 'from', 'to'])
    const parsed = {id: id(edge.id, `${path}.id`, 'D'), from: id(edge.from, `${path}.from`), to: id(edge.to, `${path}.to`)}
    if (!ids.has(parsed.from) || !ids.has(parsed.to)) invalid(path, '引用了不存在的节点')
    if (parsed.from === parsed.to) invalid(path, '节点不能依赖自身')
    if (edgeIds.has(parsed.id) || pairs.has(`${parsed.from}:${parsed.to}`)) invalid(path, '依赖标识符或节点对重复')
    edgeIds.add(parsed.id); pairs.add(`${parsed.from}:${parsed.to}`)
    return parsed
  })
  const incoming = new Set(edges.map((edge) => edge.to))
  if (nodes.some((node) => node.kind === 'given' && incoming.has(node.id))) invalid('edges', '题面条件不能有前驱')
  if (nodes.some((node) => node.kind === 'external' && incoming.has(node.id))) invalid('edges', '外部结果不能有前驱')
  const targets = strings(raw.target_ids, 'target_ids', 1000).map((item, index) => id(item, `target_ids[${index}]`))
  if (!targets.length || new Set(targets).size !== targets.length || targets.some((target) => !nodes.some((node) => node.id === target && node.kind === 'claim'))) invalid('target_ids', '应为不重复的结论节点')
  const common = {edges, target_ids: targets, ambiguities: strings(raw.ambiguities, 'ambiguities')}
  const graph: FaithSieveProofDagData = raw.schema_version === 2 ? {schema_version: 2, nodes: nodes as FaithSieveProofDagV2Node[], ...common} : {schema_version: 3, nodes, ...common}
  faithSieveDagNodeOrder(graph)
  if (new TextEncoder().encode(JSON.stringify(value, null, 2)).byteLength > MAX_BYTES) invalid('$', '内容超过 2 MiB')
  return graph
}

/** 展示宿主摘要；不从局部 passed 或 LLM 文本自行推出结论已成立。 */
export function parseFaithSieveNodeVerification(value: unknown, graph: FaithSieveProofDagData): FaithSieveProofNodeVerificationMap {
  if (value === undefined || value === null) return {}
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid('node_verification', '应为对象')
  const output: FaithSieveProofNodeVerificationMap = {}
  for (const [nodeId, input] of Object.entries(value)) {
    const node = graph.nodes.find((item) => item.id === nodeId)
    if (!node) invalid('node_verification', '引用了不存在的节点')
    const path = `node_verification.${nodeId}`
    const record = object(input, path, ['local_status', 'established', 'status', 'premise_ids', 'blocking_premise_ids'])
    if (!['given', 'external', 'passed', 'refuted', 'inconclusive', 'not_checked'].includes(record.local_status as string) || !['established', 'blocked', 'not_established', 'not_checked'].includes(record.status as string) || typeof record.established !== 'boolean') invalid(path, '验证状态无效')
    if ((record.status === 'established') !== record.established || (node.kind === 'given') !== (record.local_status === 'given') || (node.kind === 'external') !== (record.local_status === 'external')) invalid(path, '验证状态与节点种类不一致')
    const premises = strings(record.premise_ids, `${path}.premise_ids`, 1000)
    const expected = faithSieveDagPremises(graph, nodeId).map((item) => item.id)
    const blocking = strings(record.blocking_premise_ids, `${path}.blocking_premise_ids`, 1000)
    if (premises.join('\0') !== expected.join('\0') || new Set(blocking).size !== blocking.length || blocking.some((item) => !premises.includes(item))) invalid(path, '前提引用与直接依赖不一致')
    output[nodeId] = {local_status: record.local_status as FaithSieveProofNodeVerification['local_status'], established: record.established, status: record.status as FaithSieveProofNodeVerification['status'], premise_ids: premises, blocking_premise_ids: blocking}
  }
  if (!Object.keys(output).length) return output
  if (Object.keys(output).length !== graph.nodes.length) invalid('node_verification', '节点摘要不完整')
  for (const index of faithSieveDagNodeOrder(graph)) {
    const node = graph.nodes[index]
    const record = output[node.id]
    const blocking = record.premise_ids.filter((parent) => !output[parent].established)
    const established = node.kind === 'given' || node.kind === 'external' || record.local_status === 'passed' && !blocking.length
    const status = established ? 'established' : record.local_status === 'passed' ? 'blocked' : record.local_status === 'not_checked' ? 'not_checked' : 'not_established'
    if (record.established !== established || record.status !== status || record.blocking_premise_ids.join('\0') !== blocking.join('\0')) invalid(`node_verification.${node.id}`, '局部状态与前提成立状态不一致')
  }
  return output
}
