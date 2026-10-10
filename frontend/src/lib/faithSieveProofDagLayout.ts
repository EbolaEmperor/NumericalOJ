import type {ElkEdgeSection, ElkExtendedEdge, ElkNode} from 'elkjs/lib/elk.bundled.js'

import {faithSieveDagNodeOrder, type FaithSieveProofDagData} from './faithSieveProofDag'
import type {FaithSieveProofPoint, FaithSieveProofTreeLayout} from './faithSieveProofTree'

export interface FaithSieveProofDagLayout extends FaithSieveProofTreeLayout {
  /** ELK 的完整路由，首尾已贴合圆形节点边界；不能用节点间直线替代长依赖边。 */
  edgeRoutes: Record<string, FaithSieveProofPoint[]>
}

const NODE_SIZE = 38
const NODE_RADIUS = NODE_SIZE / 2
const PADDING = 24

type LayoutEngine = {layout: (graph: ElkNode) => Promise<ElkNode>}
let engine: Promise<LayoutEngine> | undefined
const layouts = new WeakMap<FaithSieveProofDagData, Promise<FaithSieveProofDagLayout>>()

function getEngine() {
  if (!engine) {
    engine = import('elkjs/lib/elk.bundled.js').then(({default: ELK}) => new ELK({algorithms: ['layered']})).catch((error: unknown) => {
      engine = undefined
      throw error
    })
  }
  return engine
}

function finite(value: number | undefined, name: string) {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`证明依赖图布局缺少有效的${name}`)
  return value
}

function equalPoint(left: FaithSieveProofPoint, right: FaithSieveProofPoint) {
  return Math.abs(left.x - right.x) < 0.000001 && Math.abs(left.y - right.y) < 0.000001
}

function sectionPoints(section: ElkEdgeSection): FaithSieveProofPoint[] {
  return [section.startPoint, ...(section.bendPoints || []), section.endPoint].map((point) => ({x: finite(point.x, '边坐标'), y: finite(point.y, '边坐标')}))
}

/** 平面中的二元依赖是一条连续路径。保留所有段，不把不完整的路由改画成直线。 */
function edgePoints(edge: ElkExtendedEdge) {
  const sections = edge.sections || []
  if (!sections.length) throw new Error(`证明依赖图布局缺少依赖 ${edge.id} 的路由`)
  const first = sections.find((section) => section.incomingShape === edge.sources[0])
    || sections.find((section) => !section.incomingSections?.length && !sections.some((other) => other !== section && equalPoint(other.endPoint, section.startPoint)))
  if (!first) throw new Error(`证明依赖图布局中依赖 ${edge.id} 的路由不连续`)
  const visited = new Set<string>()
  const points: FaithSieveProofPoint[] = []
  let section: ElkEdgeSection | undefined = first
  while (section) {
    if (visited.has(section.id)) throw new Error(`证明依赖图布局中依赖 ${edge.id} 的路由包含环`)
    visited.add(section.id)
    points.push(...sectionPoints(section))
    const following: ElkEdgeSection[] = sections.filter((candidate) => !visited.has(candidate.id) && (section!.outgoingSections?.includes(candidate.id) || equalPoint(section!.endPoint, candidate.startPoint)))
    if (following.length > 1) throw new Error(`证明依赖图布局中依赖 ${edge.id} 的路由存在分叉`)
    section = following[0]
  }
  if (visited.size !== sections.length) throw new Error(`证明依赖图布局中依赖 ${edge.id} 的路由不连续`)
  return points
}

function circleBoundary(center: FaithSieveProofPoint, point: FaithSieveProofPoint, fallback: FaithSieveProofPoint) {
  let dx = point.x - center.x
  let dy = point.y - center.y
  if (Math.hypot(dx, dy) < 0.000001) {dx = fallback.x - center.x; dy = fallback.y - center.y}
  const length = Math.hypot(dx, dy)
  if (!length) throw new Error('证明依赖图布局中的依赖端点重合')
  return {x: center.x + dx / length * NODE_RADIUS, y: center.y + dy / length * NODE_RADIUS}
}

function compactPolyline(points: FaithSieveProofPoint[]) {
  const result: FaithSieveProofPoint[] = []
  for (const point of points) {
    if (result.length && equalPoint(result.at(-1)!, point)) continue
    while (result.length >= 2) {
      const before = result.at(-2)!
      const middle = result.at(-1)!
      const distance = (left: FaithSieveProofPoint, right: FaithSieveProofPoint) => Math.hypot(right.x - left.x, right.y - left.y)
      if (Math.abs(distance(before, middle) + distance(middle, point) - distance(before, point)) >= 0.000001) break
      result.pop()
    }
    result.push(point)
  }
  return result
}

async function computeLayout(graph: FaithSieveProofDagData): Promise<FaithSieveProofDagLayout> {
  // 这里只校验方向；既不根据编号添加依赖，也不向 ELK 提交生成树来替代真实 DAG。
  faithSieveDagNodeOrder(graph)
  const elk = await getEngine()
  const result = await elk.layout({
    id: 'faithsieve-proof-dag',
    layoutOptions: {
      'elk.algorithm': 'org.eclipse.elk.layered',
      'elk.direction': 'DOWN',
      'elk.edgeRouting': 'POLYLINE',
      'elk.randomSeed': '1',
      'elk.padding': `[top=${PADDING},left=${PADDING},bottom=${PADDING},right=${PADDING}]`,
      'elk.spacing.nodeNode': '24',
      'elk.spacing.edgeNode': '12',
      'elk.spacing.edgeEdge': '8',
      'elk.spacing.componentComponent': '32',
      'elk.layered.spacing.nodeNodeBetweenLayers': '32',
      'elk.layered.spacing.edgeNodeBetweenLayers': '12',
      'elk.layered.spacing.edgeEdgeBetweenLayers': '8',
      'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
      'elk.separateConnectedComponents': 'true',
    },
    children: graph.nodes.map(({id}) => ({id, width: NODE_SIZE, height: NODE_SIZE})),
    edges: graph.edges.map(({id, from, to}) => ({id, sources: [from], targets: [to]})),
  })
  const positions: Record<string, FaithSieveProofPoint> = {}
  for (const node of result.children || []) positions[node.id] = {x: finite(node.x, '节点坐标') + NODE_RADIUS, y: finite(node.y, '节点坐标') + NODE_RADIUS}
  if (graph.nodes.some(({id}) => !positions[id])) throw new Error('证明依赖图布局缺少节点')
  const routed = new Map((result.edges || []).map((edge) => [edge.id, edge as ElkExtendedEdge]))
  const edgeRoutes: Record<string, FaithSieveProofPoint[]> = {}
  for (const {id, from, to} of graph.edges) {
    const edge = routed.get(id)
    if (!edge) throw new Error(`证明依赖图布局缺少依赖 ${id}`)
    const points = edgePoints(edge)
    // 偏移端口也是 ELK 避让相邻节点的一部分。贴合圆周时保留它们，不能把无折点的路由改成圆心连线。
    const start = circleBoundary(positions[from], points[0], positions[to])
    const end = circleBoundary(positions[to], points.at(-1)!, positions[from])
    edgeRoutes[id] = compactPolyline([start, ...points, end])
  }
  return {positions, edgeRoutes, width: finite(result.width, '画布宽度'), height: finite(result.height, '画布高度')}
}

/** 新版证明 DAG 使用异步 ELK Layered；历史状态树仍可继续使用原布局。 */
export function layoutFaithSieveProofDag(graph: FaithSieveProofDagData): Promise<FaithSieveProofDagLayout> {
  const existing = layouts.get(graph)
  if (existing) return existing
  const pending = computeLayout(graph).catch((error: unknown) => {
    layouts.delete(graph)
    throw error
  })
  layouts.set(graph, pending)
  return pending
}
