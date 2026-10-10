import {useEffect, useMemo, useRef, useState, type PointerEvent, type ReactNode} from 'react'

import {faithSieveStageKind, faithSieveStageState, faithSieveStatusLabel, type FaithSieveEdge, type FaithSieveStage} from '../pages/faithsieveTypes'
import {createRuleTopology, type RuleTopologyLayout, type RuleTopologyPoint} from '../ranking/ruleTopology'
import './faithsieve-workflow-graph.css'

const NODE_WIDTH = 190
const NODE_HEIGHT = 64
const INSET = 24
const DETAIL_MAX_HEIGHT = 840
// 先复用依赖排序，再按视口分行，避免常规串行流程缩成无法阅读的长条。
const topology = createRuleTopology({nodeWidth: NODE_HEIGHT, nodeHeight: NODE_WIDTH, marginX: 20, marginY: 20, columnGap: 28, rowGap: 54, slotPadding: 28, maxSlotStep: 10})

function flowLayout(base: RuleTopologyLayout, edges: {from: number; to: number}[], viewportWidth: number) {
  const levels = new Map<number, number[]>()
  Object.entries(base.positions).forEach(([id, position]) => {levels.set(position.y, [...(levels.get(position.y) || []), Number(id)])})
  const ordered = [...levels].sort(([left], [right]) => left - right).map(([, ids]) => ids.sort((left, right) => base.positions[left].x - base.positions[right].x))
  const columns = Math.min(ordered.length, Math.max(1, Math.floor(viewportWidth / (NODE_WIDTH + 40))))
  const positions: Record<number, RuleTopologyPoint> = {}
  const bands: {top: number; height: number}[] = []
  const levelById = new Map<number, number>()
  let top = 20
  for (let offset = 0; offset < ordered.length; offset += columns) {
    const band = ordered.slice(offset, offset + columns)
    const row = bands.length
    const height = Math.max(...band.map((ids) => ids.length * NODE_HEIGHT + (ids.length - 1) * 28))
    bands.push({top, height})
    band.forEach((ids, column) => {
      const usedHeight = ids.length * NODE_HEIGHT + (ids.length - 1) * 28
      const x = 20 + (row % 2 ? columns - column - 1 : column) * (NODE_WIDTH + 40)
      ids.forEach((id, index) => {positions[id] = {x, y: top + (height - usedHeight) / 2 + index * (NODE_HEIGHT + 28)}; levelById.set(id, offset + column)})
    })
    top += height + 64
  }
  const width = columns * NODE_WIDTH + (columns - 1) * 40 + 40
  const height = top - 64 + 28
  const routes: Record<string, {path: string; arrow: string}> = {}
  edges.forEach(({from, to}) => {
    const source = positions[from]
    const target = positions[to]
    const sourceLevel = levelById.get(from)!
    const targetLevel = levelById.get(to)!
    const sourceBand = Math.floor(sourceLevel / columns)
    const targetBand = Math.floor(targetLevel / columns)
    const sourceDirection = sourceBand % 2 ? -1 : 1
    const targetDirection = targetBand % 2 ? -1 : 1
    const start = {x: source.x + (sourceDirection > 0 ? NODE_WIDTH : 0), y: source.y + NODE_HEIGHT / 2}
    const tip = {x: target.x + (targetDirection > 0 ? 0 : NODE_WIDTH), y: target.y + NODE_HEIGHT / 2}
    const end = {x: tip.x - targetDirection * 8, y: tip.y}
    const exitX = start.x + sourceDirection * 18
    const entryX = tip.x - targetDirection * 18
    let points: RuleTopologyPoint[]
    if (sourceBand === targetBand && targetLevel === sourceLevel + 1) {
      const middle = (start.x + end.x) / 2
      points = [start, {x: middle, y: start.y}, {x: middle, y: end.y}, end]
    } else if (sourceBand === targetBand) {
      const lane = bands[sourceBand].top + bands[sourceBand].height + 20
      points = [start, {x: exitX, y: start.y}, {x: exitX, y: lane}, {x: entryX, y: lane}, {x: entryX, y: end.y}, end]
    } else if (targetBand === sourceBand + 1) {
      const lane = (bands[sourceBand].top + bands[sourceBand].height + bands[targetBand].top) / 2
      points = [start, {x: exitX, y: start.y}, {x: exitX, y: lane}, {x: entryX, y: lane}, {x: entryX, y: end.y}, end]
    } else {
      const exitLane = bands[sourceBand].top + bands[sourceBand].height + 20
      const entryLane = bands[targetBand].top - 20
      const outside = start.x < width / 2 ? 8 : width - 8
      points = [start, {x: exitX, y: start.y}, {x: exitX, y: exitLane}, {x: outside, y: exitLane}, {x: outside, y: entryLane}, {x: entryX, y: entryLane}, {x: entryX, y: end.y}, end]
    }
    const path = topology.edgePath({x1: start.x, y1: start.y, x2: end.x, y2: end.y, laneY: 0, arrowTipY: tip.y, points})
    routes[topology.edgeKey(from, to)] = {path, arrow: `${tip.x} ${tip.y} ${end.x} ${end.y - 4} ${end.x} ${end.y + 4}`}
  })
  return {positions, width, height, routes}
}

function stageContext(stage: FaithSieveStage) {
  const branch = ({original: '原命题', negation: '否定', counterexample: '反例'} as Record<string, string>)[stage.parameters?.branch || ''] || stage.parameters?.branch
  const target = ({statement: '命题', proof: '证明'} as Record<string, string>)[stage.parameters?.target || ''] || stage.parameters?.target
  const obligation = String(stage.parameters?.obligation_id || '')
  const node = String(stage.parameters?.node_id || '')
  const edge = String(stage.parameters?.edge_id || '')
  const reference = node ? `结论 ${node}` : obligation ? `义务 ${obligation.replace(/^e(\d+)-o(\d+)$/, '$1.$2')}` : edge ? `步骤 ${edge.replace(/^e(\d+)$/, '$1')}` : ''
  return [reference, branch, target].filter(Boolean).join(' · ')
}

function stageOutcome(stage: FaithSieveStage, state: string) {
  if (state !== 'completed') return state === 'protocol_error' ? '协议异常' : faithSieveStatusLabel(state)
  if (stage.parameters?.node_id && stage.status === 'refuted') return '推理被反驳'
  return ({needs_revision: '需修订', graph_defect: '需修图', failed: '失败', error: '失败', inconclusive: '无结论', refuted: '已反驳', incorrect: '不成立', default_order: '使用默认顺序'} as Record<string, string>)[stage.status || ''] || ''
}

export function FaithSieveWorkflowGraph({stages, edges = [], runStatus, selectedKey, onSelect, title = 'Workflow', headingMeta, compact = false}: {stages: FaithSieveStage[]; edges?: FaithSieveEdge[]; runStatus: string; selectedKey?: string | null; onSelect: (stage: FaithSieveStage) => void; title?: string; headingMeta?: ReactNode; compact?: boolean}) {
  const root = useRef<HTMLDivElement>(null)
  const viewport = useRef<HTMLDivElement>(null)
  const expandButton = useRef<HTMLButtonElement>(null)
  const drag = useRef<{x: number; y: number; left: number; top: number} | null>(null)
  const [viewportSize, setViewportSize] = useState({width: 600, height: 400})
  const [zoom, setZoom] = useState<number | null>(null)
  const [expanded, setExpanded] = useState(false)
  const [dragging, setDragging] = useState(false)
  const graph = useMemo(() => {
    const ids = new Map(stages.map((stage, index) => [stage.key, index + 1]))
    const seen = new Set<string>()
    const unique = edges.filter((edge) => {
      const key = `${edge.source}:${edge.target}`
      if (!ids.has(edge.source) || !ids.has(edge.target) || edge.source === edge.target || seen.has(key)) return false
      seen.add(key)
      return true
    })
    const rules = stages.map((stage, index) => ({rule_id: index + 1, dependencies: unique.filter((edge) => edge.target === stage.key).map((edge) => ids.get(edge.source)!)}))
    const baseLayout = topology.layout(rules)
    const numericEdges = unique.map((edge) => ({from: ids.get(edge.source)!, to: ids.get(edge.target)!}))
    const layout = baseLayout ? flowLayout(baseLayout, numericEdges, viewportSize.width) : null
    const contexts = stages.map(stageContext)
    const repeats = new Map<string, number>()
    stages.forEach((stage, index) => {const key = `${stage.label}:${contexts[index]}`; repeats.set(key, (repeats.get(key) || 0) + 1)})
    const rounds = new Map<string, number>()
    const labels = contexts.map((context, index) => {
      const stage = stages[index]
      const key = `${stage.label}:${context}`
      rounds.set(key, (rounds.get(key) || 0) + 1)
      const repeated = repeats.get(key)! > 1
      const round = repeated ? rounds.get(key)! : stage.parameters?.attempt || 1
      return [context, (repeated || round > 1) ? `第 ${round} 轮` : ''].filter(Boolean).join(' · ')
    })
    return {ids, edges: unique, layout, labels, routes: layout?.routes || {}}
  }, [stages, edges, viewportSize.width])
  useEffect(() => {
    const element = viewport.current
    if (!element) return
    const update = () => {
      const width = element.clientWidth || element.getBoundingClientRect().width
      const height = element.clientHeight || element.getBoundingClientRect().height
      if (width > 0) setViewportSize({width, height: height || 400})
    }
    update()
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(update)
    observer?.observe(element)
    window.addEventListener('resize', update)
    return () => {observer?.disconnect(); window.removeEventListener('resize', update)}
  }, [Boolean(stages.length), expanded, compact])
  useEffect(() => {
    if (!expanded || !stages.length || !graph.layout) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const close = () => {setExpanded(false); setZoom(null); expandButton.current?.focus()}
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {event.preventDefault(); close()}
      if (event.key !== 'Tab') return
      const controls = root.current?.querySelectorAll<HTMLElement>('button:not([disabled]), [tabindex="0"]')
      if (!controls?.length) return
      const first = controls[0]
      const last = controls[controls.length - 1]
      if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus()}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus()}
    }
    document.addEventListener('keydown', onKey)
    expandButton.current?.focus()
    return () => {document.body.style.overflow = previousOverflow; document.removeEventListener('keydown', onKey)}
  }, [expanded, Boolean(stages.length), Boolean(graph.layout)])
  const layout = graph.layout
  const width = layout?.width || 0
  const height = layout?.height || 0
  const widthFit = layout ? Math.min(1, Math.max(1, viewportSize.width - INSET * 2) / width) : 1
  const availableHeight = expanded ? Math.max(180, viewportSize.height - INSET * 2) : 240 - INSET * 2 - 2
  // 详情随内容增高，优先保留节点字号；预览和展开图才缩放到完整视口。
  const fit = layout && (compact || expanded) ? Math.min(widthFit, availableHeight / height) : widthFit
  const scale = zoom ?? fit
  const canvasHeight = expanded ? viewportSize.height : Math.min(compact ? 240 : DETAIL_MAX_HEIGHT, Math.max(compact ? 140 : 180, height * fit + INSET * 2 + 2))
  const planeWidth = Math.max(viewportSize.width, width * scale + INSET * 2)
  const planeHeight = Math.max(canvasHeight - (expanded ? 0 : 2), height * scale + INSET * 2)
  // 选择仅更新详情；始终保留当前视野，轮询不能把图自动滚到末端。
  useEffect(() => {
    if (zoom !== null) return
    const element = viewport.current
    if (element) {element.scrollLeft = 0; element.scrollTop = 0}
  }, [zoom, fit])
  const headingMain = <div className="faithsieve-graph-heading-main">{title || expanded ? <h3>{title || 'Workflow'}</h3> : null}{headingMeta ? <div className="faithsieve-graph-heading-meta">{headingMeta}</div> : null}</div>
  if (!stages.length || !layout) return <div className={`faithsieve-graph${compact ? ' is-compact' : ''}`} aria-label="Workflow DAG"><div className="faithsieve-graph-heading">{headingMain}</div>{!stages.length ? <div className="submission-test-detail-hint">暂无阶段记录</div> : <div className="submission-action-feedback is-error" role="alert">阶段依赖无法绘制</div>}</div>
  const changeZoom = (factor: number) => setZoom(Math.min(2, Math.max(Math.min(fit, 0.1), scale * factor)))
  const canPan = width * scale + INSET * 2 > viewportSize.width || height * scale + INSET * 2 > canvasHeight
  const startDrag = (event: PointerEvent<HTMLDivElement>) => {
    if (!canPan || event.button !== 0 || (event.target as HTMLElement).closest('button')) return
    drag.current = {x: event.clientX, y: event.clientY, left: event.currentTarget.scrollLeft, top: event.currentTarget.scrollTop}
    event.currentTarget.setPointerCapture?.(event.pointerId)
    setDragging(true)
  }
  const moveDrag = (event: PointerEvent<HTMLDivElement>) => {
    if (!drag.current) return
    event.currentTarget.scrollLeft = drag.current.left - event.clientX + drag.current.x
    event.currentTarget.scrollTop = drag.current.top - event.clientY + drag.current.y
  }
  const stopDrag = () => {drag.current = null; setDragging(false)}
  return <div ref={root} className={`faithsieve-graph${compact ? ' is-compact' : ''}${expanded ? ' is-expanded' : ''}`} aria-label="Workflow DAG" role={expanded ? 'dialog' : undefined} aria-modal={expanded || undefined}>
    <div className="faithsieve-graph-heading">{headingMain}<div className="faithsieve-graph-controls"><button type="button" className="submission-icon-button" aria-label="缩小 Workflow 图" title="缩小" disabled={scale <= Math.min(fit, 0.1)} onClick={() => changeZoom(0.8)}><i className="fas fa-minus" aria-hidden="true" /></button><button type="button" className="submission-icon-button" aria-label="放大 Workflow 图" title="放大" disabled={scale >= 2} onClick={() => changeZoom(1.25)}><i className="fas fa-plus" aria-hidden="true" /></button><button type="button" className="submission-icon-button" aria-label="适应 Workflow 图" title={compact || expanded ? '适应完整图' : '适应宽度'} onClick={() => setZoom(null)}><i className="fas fa-compress" aria-hidden="true" /></button><button ref={expandButton} type="button" className="submission-icon-button" aria-label={expanded ? '收起 Workflow 图' : '展开 Workflow 图'} title={expanded ? '收起' : '展开'} onClick={() => {setExpanded((current) => !current); setZoom(null)}}><i className={`fas ${expanded ? 'fa-xmark' : 'fa-expand'}`} aria-hidden="true" /></button></div></div>
    <div ref={viewport} className={`faithsieve-graph-scroll${canPan ? ' can-pan' : ''}${dragging ? ' is-dragging' : ''}`} style={expanded ? undefined : {height: canvasHeight}} tabIndex={0} aria-label="Workflow 图" onPointerDown={startDrag} onPointerMove={moveDrag} onPointerUp={stopDrag} onPointerCancel={stopDrag} onDoubleClick={(event) => {if (!(event.target as HTMLElement).closest('button')) setZoom(zoom === null ? 1 : null)}}><div className="faithsieve-graph-size" style={{width: planeWidth, height: planeHeight}}><div className="faithsieve-graph-canvas" style={{width, height, left: (planeWidth - width * scale) / 2, top: (planeHeight - height * scale) / 2, transform: `scale(${scale})`}}>
      <svg className="faithsieve-graph-edges" width={width} height={height} aria-label="阶段依赖" role="img">{graph.edges.map((edge) => {const route = graph.routes[topology.edgeKey(graph.ids.get(edge.source)!, graph.ids.get(edge.target)!)]
        const selected = selectedKey === edge.source || selectedKey === edge.target
        return route ? <g key={`${edge.source}:${edge.target}`}><path className={`faithsieve-graph-edge${selected ? ' is-selected' : ''}`} data-source={edge.source} data-target={edge.target} d={route.path}><title>{stages.find((stage) => stage.key === edge.source)?.label} → {stages.find((stage) => stage.key === edge.target)?.label}</title></path><polygon className={`faithsieve-graph-arrow${selected ? ' is-selected' : ''}`} points={route.arrow} /></g> : null
      })}</svg>
      {stages.map((stage, index) => {const position = layout.positions[index + 1]; const state = faithSieveStageState(stage, runStatus)
        const context = graph.labels[index]
        const outcome = stageOutcome(stage, state)
        const issue = ['protocol_error', 'failed'].includes(state) || ['failed', 'error', 'refuted', 'incorrect'].includes(stage.status || '')
        const warning = ['needs_revision', 'graph_defect', 'inconclusive'].includes(stage.status || '')
        return <button type="button" key={stage.key} data-stage-key={stage.key} className={`faithsieve-graph-node is-${state}${issue ? ' is-issue' : warning ? ' is-warning' : ''}${selectedKey === stage.key ? ' is-selected' : ''}${context || outcome ? ' has-context' : ''}`} style={{left: position.x, top: position.y, width: NODE_WIDTH, height: NODE_HEIGHT}} aria-label={`${stage.label}，${faithSieveStageKind(stage.kind)}，${outcome || faithSieveStatusLabel(state)}${context ? `，${context}` : ''}`} aria-pressed={selectedKey === stage.key} title={`${stage.label}${context ? ` · ${context}` : ''} · ${outcome || faithSieveStatusLabel(state)}`} onClick={() => onSelect(stage)}><span className="faithsieve-graph-node-dot" aria-hidden="true" /><span className="faithsieve-graph-node-main"><span className="faithsieve-graph-node-label">{stage.label}</span>{context || outcome ? <span className="faithsieve-graph-node-context">{context ? <span className="faithsieve-graph-node-reference">{context}</span> : null}{outcome ? <span className={`faithsieve-graph-node-outcome${context ? ' has-reference' : ''}`}>{outcome}</span> : null}</span> : null}</span></button>
      })}
    </div></div></div>
  </div>
}
