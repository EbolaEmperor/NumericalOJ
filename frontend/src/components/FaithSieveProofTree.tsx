import {useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent} from 'react'

import {faithSieveDagPremises, layoutFaithSieveProofTree, type FaithSieveHistoricalProofTreeData, type FaithSieveLegacyProofEdge, type FaithSieveLegacyProofNode, type FaithSieveProofDagData, type FaithSieveProofDagNode, type FaithSieveProofEdge, type FaithSieveProofNode, type FaithSieveProofNodeVerificationMap, type FaithSieveProofPoint, type FaithSieveProofTreeData, type FaithSieveProofTreeLayout, type FaithSieveProofTreeSelection} from '../lib/faithSieveProofTree'
import {layoutFaithSieveProofDag, type FaithSieveProofDagLayout} from '../lib/faithSieveProofDagLayout'
import {FaithSieveReport} from './FaithSieveReport'
import './faithsieve-proof-tree.css'

const RADIUS = 19
const INSET = 24
const EMPTY_LAYOUT: FaithSieveProofTreeLayout = {positions: {}, width: 600, height: 300}

function edgeGeometry(from: FaithSieveProofPoint, to: FaithSieveProofPoint, route?: FaithSieveProofPoint[]) {
  // 保留 ELK 为跨层依赖计算的折点；拖动只更新圆周上的首末端。
  const bends = route?.slice(1, -1) || []
  // 偏移端口保留在路径中；圆周内的端口先裁掉，避免箭头末段因留白而反向。
  while (bends.length && Math.hypot(bends[0].x - from.x, bends[0].y - from.y) <= RADIUS) bends.shift()
  while (bends.length && Math.hypot(bends.at(-1)!.x - to.x, bends.at(-1)!.y - to.y) <= RADIUS + 3) bends.pop()
  const toward = (center: FaithSieveProofPoint, next: FaithSieveProofPoint, radius: number) => {
    const distance = Math.hypot(next.x - center.x, next.y - center.y) || 1
    return {x: center.x + (next.x - center.x) / distance * radius, y: center.y + (next.y - center.y) / distance * radius}
  }
  const start = toward(from, bends[0] || to, RADIUS)
  const end = toward(to, bends.at(-1) || from, RADIUS + 3)
  const last = bends.at(-1) || start
  const distance = Math.hypot(end.x - last.x, end.y - last.y) || 1
  const dx = (end.x - last.x) / distance
  const dy = (end.y - last.y) / distance
  const tip = {x: end.x - dx * 6, y: end.y - dy * 6}
  return {
    path: [start, ...bends, end].map((point, index) => `${index ? 'L' : 'M'} ${point.x} ${point.y}`).join(' '),
    arrow: `${end.x},${end.y} ${tip.x - dy * 3},${tip.y + dx * 3} ${tip.x + dy * 3},${tip.y - dx * 3}`,
  }
}

function MathText({text}: {text: string}) {return <FaithSieveReport text={text} className="faithsieve-proof-math" />}
function MathItems({items}: {items: string[]}) {return <ul>{items.map((item, index) => <li key={index}><MathText text={item} /></li>)}</ul>}
function StateDetails({node}: {node: FaithSieveProofNode | FaithSieveLegacyProofNode}) {
  if ('raw_state' in node) return node.raw_state ? <MathText text={node.raw_state} /> : null
  return <>{node.conditions.length ? <section><h5>条件</h5><MathItems items={node.conditions} /></section> : null}<section><h5>目标</h5><MathText text={node.goal} /></section>{node.scope.length ? <section><h5>作用域</h5><MathItems items={node.scope} /></section> : null}</>
}
function EdgeDetails({edge, tree}: {edge: FaithSieveProofEdge | FaithSieveLegacyProofEdge; tree: FaithSieveHistoricalProofTreeData}) {
  const parent = tree.nodes.find((node) => node.id === edge.from)!
  const child = tree.nodes.find((node) => node.id === edge.to)!
  return <>
    <div className="faithsieve-proof-step-reference"><span>{edge.from} → {edge.to}</span><span className="faithsieve-proof-separator">·</span><span>{edge.step_id}</span>{edge.source_location ? <><span className="faithsieve-proof-separator">·</span><span>{edge.source_location}</span></> : null}</div>
    {edge.source_text ? <section><h5>原文</h5><MathText text={edge.source_text} /></section> : null}
    {'raw_changes' in edge ? <>
      {edge.raw_input ? <section><h5>输入状态</h5><MathText text={edge.raw_input} /></section> : null}
      {edge.raw_output ? <section><h5>输出状态</h5><MathText text={edge.raw_output} /></section> : null}
      {edge.raw_changes ? <section><h5>条件变化</h5><MathText text={edge.raw_changes} /></section> : null}
    </> : <>{Object.entries(edge.changes).map(([kind, items]) => items.length ? <section key={kind}><h5>{({retained: '保留', added: '新增', consumed: '消耗', transformed: '变换'} as Record<string, string>)[kind]}</h5><MathItems items={items} /></section> : null)}</>}
    {edge.goal_relation ? <section><h5>目标关系</h5><MathText text={edge.goal_relation} /></section> : null}
    {edge.transition_type ? <section><h5>转移类型</h5><MathText text={edge.transition_type} /></section> : null}
    {'scope_text' in edge ? edge.scope_text ? <section><h5>作用域</h5><MathText text={edge.scope_text} /></section> : null : edge.scope.length ? <section><h5>作用域</h5><MathItems items={edge.scope} /></section> : null}
    <details className="faithsieve-proof-state-pair"><summary>状态 {edge.from} → {edge.to}</summary><div><section><h5>{parent.id}{parent.label !== parent.id ? ` · ${parent.label}` : ''}</h5><StateDetails node={parent} /></section><section><h5>{child.id}{child.label !== child.id ? ` · ${child.label}` : ''}</h5><StateDetails node={child} /></section></div></details>
  </>
}

function DagNodeDetails({node, graph, verification, select}: {node: FaithSieveProofDagNode; graph: FaithSieveProofDagData; verification: FaithSieveProofNodeVerificationMap; select: (id: string) => void}) {
  const premises = faithSieveDagPremises(graph, node.id)
  const result = verification[node.id]
  const source = graph.schema_version === 2 ? graph.nodes.find((item) => item.id === node.id) : undefined
  const outcome = result?.local_status === 'refuted' ? '推理被反驳' : result?.established ? '已成立' : result?.status === 'blocked' ? '前提待验证' : result?.status === 'not_established' ? '尚未确定' : '未验证'
  return <>
    {premises.length ? <section><h5>前置条件</h5><ul className="faithsieve-proof-premises">{premises.map((premise) => <li key={premise.id} className={result?.blocking_premise_ids.includes(premise.id) ? 'is-blocking' : undefined}><button type="button" onClick={() => select(premise.id)} className="faithsieve-proof-reference">{premise.id}</button><div>{premise.kind === 'external' ? <span className="faithsieve-proof-premise-kind">外部结果</span> : null}<MathText text={premise.statement} /></div></li>)}</ul></section> : null}
    <section><h5>{node.kind === 'given' ? '初始条件' : node.kind === 'external' ? '外部结果' : '目标'}</h5><MathText text={node.statement} /></section>
    <section><h5>结果</h5><div className={`faithsieve-proof-outcome${result?.local_status === 'refuted' ? ' is-issue' : ''}`}>{outcome}</div>{result?.local_status === 'passed' && !result.established ? <div className="faithsieve-proof-local-result">局部推理已验证</div> : null}</section>
    {source ? <details className="faithsieve-proof-ambiguities"><summary>原文</summary><div className="faithsieve-proof-source"><div className="faithsieve-proof-step-reference"><span>{source.source_type === 'problem' ? '题面' : '解答'}</span><span>{source.source_location}</span>{source.step_ids.length ? <span>{source.step_ids.join('、')}</span> : null}</div><MathText text={source.source_text} /></div></details> : null}
  </>
}

export interface FaithSieveProofTreeProps {
  tree: FaithSieveProofTreeData
  title?: string
  compact?: boolean
  nodeVerification?: FaithSieveProofNodeVerificationMap
  onSelect?: (selection: FaithSieveProofTreeSelection) => void
}

export function FaithSieveProofTree({tree, title, compact = false, nodeVerification = {}, onSelect}: FaithSieveProofTreeProps) {
  const dag = tree.schema_version === 2 || tree.schema_version === 3 ? tree : null
  const graphName = dag ? '证明依赖图' : '证明状态树'
  const defaultTitle = tree.schema_version === 3 ? graphName : `${graphName}（历史）`
  const initialId = dag ? dag.target_ids[0] : (tree as FaithSieveHistoricalProofTreeData).root_id
  const historicalLayout = useMemo(() => tree.schema_version === 1 ? layoutFaithSieveProofTree(tree) : null, [tree])
  const [dagResult, setDagResult] = useState<{graph: FaithSieveProofDagData; layout?: FaithSieveProofDagLayout; failed?: boolean} | null>(null)
  const [layoutRevision, setLayoutRevision] = useState(0)
  const dagLayout = dagResult?.graph === dag ? dagResult?.layout : undefined
  const readyLayout = historicalLayout || dagLayout
  const layout = readyLayout || EMPTY_LAYOUT
  const layoutFailed = !!dag && dagResult?.graph === dag && dagResult?.failed
  const root = useRef<HTMLDivElement>(null)
  const viewport = useRef<HTMLDivElement>(null)
  const expandButton = useRef<HTMLButtonElement>(null)
  const [selection, setSelection] = useState<FaithSieveProofTreeSelection>({kind: 'node', id: initialId})
  const [positions, setPositions] = useState<Record<string, FaithSieveProofPoint>>({})
  const [size, setSize] = useState({width: 600, height: 400})
  const [zoom, setZoom] = useState<number | 'fit' | null>(null)
  const [expanded, setExpanded] = useState(false)
  const [panning, setPanning] = useState(false)
  const drag = useRef<{kind: 'pan'; x: number; y: number; left: number; top: number} | {kind: 'node'; id: string; x: number; y: number; initial: FaithSieveProofPoint; moved: boolean} | null>(null)
  const suppressClick = useRef(false)
  const zoomCenter = useRef<FaithSieveProofPoint | null>(null)
  const selectedNode = selection.kind === 'node' ? tree.nodes.find((node) => node.id === selection.id) : undefined
  const selectedEdge = selection.kind === 'edge' ? tree.edges.find((edge) => edge.id === selection.id) : undefined
  const historicalEdge = tree.schema_version === 1 && selection.kind === 'edge' ? tree.edges.find((edge) => edge.id === selection.id) : undefined
  const selectedIds = new Set(selectedEdge ? [selectedEdge.from, selectedEdge.to] : selectedNode ? [selectedNode.id, ...(dag ? faithSieveDagPremises(dag, selectedNode.id).map((node) => node.id) : [])] : [])
  const point = (id: string) => positions[id] || layout.positions[id]
  const widthFit = Math.min(1, Math.max(1, size.width - INSET * 2) / layout.width)
  // DAG 默认完整落在当前栏宽内，长图向下滚动；历史状态树仍保留原来的默认字号。
  const defaultScale = dag ? widthFit : Math.max(0.92, widthFit)
  const normalHeight = Math.min(compact ? 240 : 720, Math.max(compact ? 180 : 300, layout.height * defaultScale + INSET * 2))
  const availableHeight = expanded ? size.height : normalHeight
  const fit = Math.min(widthFit, Math.max(1, availableHeight - INSET * 2) / layout.height)
  const scale = typeof zoom === 'number' ? zoom : zoom === 'fit' || compact ? fit : defaultScale
  const planeWidth = Math.max(size.width, layout.width * scale + INSET * 2)
  const planeHeight = Math.max(availableHeight, layout.height * scale + INSET * 2)
  const left = (planeWidth - layout.width * scale) / 2
  const top = (planeHeight - layout.height * scale) / 2

  useEffect(() => {
    if (!dag) return
    let current = true
    void layoutFaithSieveProofDag(dag).then(
      (result) => {if (current) setDagResult({graph: dag, layout: result})},
      () => {if (current) setDagResult({graph: dag, failed: true})},
    )
    return () => {current = false}
  }, [dag, layoutRevision])
  useEffect(() => {
    setPositions({}); setZoom(null)
    drag.current = null; zoomCenter.current = null; suppressClick.current = false; setPanning(false)
    setSelection((current) => (current.kind === 'node' ? tree.nodes : tree.edges).some((item) => item.id === current.id) ? current : {kind: 'node', id: initialId})
  }, [tree])
  useEffect(() => {
    const element = viewport.current
    if (!element) return
    const update = () => {const width = element.clientWidth || element.getBoundingClientRect().width; const height = element.clientHeight || element.getBoundingClientRect().height; if (width > 0) setSize({width, height: height || 400})}
    update()
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(update)
    observer?.observe(element)
    window.addEventListener('resize', update)
    return () => {observer?.disconnect(); window.removeEventListener('resize', update)}
  }, [expanded, compact])
  useLayoutEffect(() => {
    const element = viewport.current
    if (!element) return
    const center = zoomCenter.current
    element.scrollLeft = center ? center.x * scale + left - size.width / 2 : Math.max(0, (planeWidth - size.width) / 2)
    element.scrollTop = center ? center.y * scale + top - availableHeight / 2 : dag ? 0 : Math.max(0, (planeHeight - availableHeight) / 2)
    zoomCenter.current = null
  }, [scale, planeWidth, planeHeight, left, top, size.width, availableHeight, dag, readyLayout])
  useEffect(() => {
    if (!expanded) return
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape') {event.preventDefault(); setExpanded(false); setZoom(null); expandButton.current?.focus()}
      if (event.key !== 'Tab') return
      const controls = root.current?.querySelectorAll<HTMLElement>('button:not([disabled]), [tabindex="0"], summary')
      if (!controls?.length) return
      const first = controls[0]
      const last = controls[controls.length - 1]
      if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus()}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus()}
    }
    document.addEventListener('keydown', onKey)
    expandButton.current?.focus()
    return () => {document.body.style.overflow = previous; document.removeEventListener('keydown', onKey)}
  }, [expanded])

  const select = (next: FaithSieveProofTreeSelection) => {setSelection(next); onSelect?.(next)}
  const keyboardSelect = (event: KeyboardEvent<SVGGElement>, next: FaithSieveProofTreeSelection) => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); select(next)}}
  const changeZoom = (factor: number) => {
    const element = viewport.current
    if (element) zoomCenter.current = {x: (element.scrollLeft + size.width / 2 - left) / scale, y: (element.scrollTop + availableHeight / 2 - top) / scale}
    setZoom(Math.max(Math.min(fit, 0.1), Math.min(2.5, scale * factor)))
  }
  const startPan = (event: PointerEvent<HTMLDivElement>) => {
    if (!readyLayout || event.button !== 0 || (event.target as Element).closest('button, [data-proof-edge]')) return
    drag.current = {kind: 'pan', x: event.clientX, y: event.clientY, left: event.currentTarget.scrollLeft, top: event.currentTarget.scrollTop}
    event.currentTarget.setPointerCapture?.(event.pointerId); setPanning(true)
  }
  const startNode = (event: PointerEvent<HTMLButtonElement>, id: string) => {
    if (event.button !== 0) return
    event.stopPropagation()
    drag.current = {kind: 'node', id, x: event.clientX, y: event.clientY, initial: point(id), moved: false}
    event.currentTarget.setPointerCapture?.(event.pointerId)
  }
  const move = (event: PointerEvent<HTMLDivElement>) => {
    const current = drag.current
    if (!current) return
    if (current.kind === 'pan') {event.currentTarget.scrollLeft = current.left - event.clientX + current.x; event.currentTarget.scrollTop = current.top - event.clientY + current.y; return}
    const dx = event.clientX - current.x
    const dy = event.clientY - current.y
    if (Math.hypot(dx, dy) < 4 && !current.moved) return
    current.moved = true
    setPositions((old) => ({...old, [current.id]: {x: Math.max(RADIUS + 4, Math.min(layout.width - RADIUS - 4, current.initial.x + dx / scale)), y: Math.max(RADIUS + 4, Math.min(layout.height - RADIUS - 4, current.initial.y + dy / scale))}}))
  }
  const stop = () => {if (drag.current?.kind === 'node') suppressClick.current = drag.current.moved; drag.current = null; setPanning(false)}
  const selectNode = (id: string) => {if (suppressClick.current) {suppressClick.current = false; return} select({kind: 'node', id})}
  const selectedTitle = selectedNode ? `${selectedNode.id}${selectedNode.label !== selectedNode.id ? ` · ${selectedNode.label}` : ''}` : selectedEdge ? selectedEdge.id : ''
  const heading = expanded ? title || defaultTitle : title === undefined ? defaultTitle : title
  return <div ref={root} className={`faithsieve-proof-tree${expanded ? ' is-expanded' : ''}${compact ? ' is-compact' : ''}`} aria-label={graphName} role={expanded ? 'dialog' : undefined} aria-modal={expanded || undefined}>
    <div className="faithsieve-proof-heading">{heading ? <h3>{heading}</h3> : <span />}<div className="faithsieve-proof-controls">
      <button type="button" className="submission-icon-button" aria-label={`缩小${graphName}`} title="缩小" disabled={!readyLayout || scale <= Math.min(fit, 0.1)} onClick={() => changeZoom(0.8)}><i className="fas fa-minus" aria-hidden="true" /></button>
      <button type="button" className="submission-icon-button" aria-label={`放大${graphName}`} title="放大" disabled={!readyLayout || scale >= 2.5} onClick={() => changeZoom(1.25)}><i className="fas fa-plus" aria-hidden="true" /></button>
      <button type="button" className="submission-icon-button" aria-label={`适应${graphName}`} title="适应完整图" disabled={!readyLayout} onClick={() => {zoomCenter.current = null; setZoom('fit')}}><i className="fas fa-compress" aria-hidden="true" /></button>
      <button ref={expandButton} type="button" className="submission-icon-button" aria-label={expanded ? `收起${graphName}` : `展开${graphName}`} title={expanded ? '收起' : '展开'} onClick={() => {setExpanded((current) => !current); setZoom(null)}}><i className={`fas ${expanded ? 'fa-xmark' : 'fa-expand'}`} aria-hidden="true" /></button>
    </div></div>
    <div ref={viewport} className={`faithsieve-proof-viewport${panning ? ' is-panning' : ''}`} style={{height: expanded ? undefined : normalHeight}} tabIndex={0} aria-label={`${graphName}画布`} aria-busy={!readyLayout && !layoutFailed} onPointerDown={startPan} onPointerMove={move} onPointerUp={stop} onPointerCancel={stop} onDoubleClick={(event) => {if (readyLayout && !(event.target as Element).closest('button, [data-proof-edge]')) setZoom((current) => current === 'fit' ? 1 : 'fit')}}>
      {!readyLayout ? <div className="faithsieve-proof-layout-status">{layoutFailed ? <div role="alert"><span>证明依赖图布局失败</span><button type="button" className="submission-icon-button" onClick={() => {setDagResult(null); setLayoutRevision((revision) => revision + 1)}}>重新布局</button></div> : <span role="status" aria-label="证明依赖图布局状态">布局中…</span>}</div> : <div className="faithsieve-proof-plane" style={{width: planeWidth, height: planeHeight}}><div className="faithsieve-proof-canvas" style={{width: layout.width, height: layout.height, left, top, transform: `scale(${scale})`}}>
        <svg width={layout.width} height={layout.height} className="faithsieve-proof-edges" aria-label={dag ? '直接证明依赖' : '证明步骤'}>
          {tree.edges.map((edge) => {
            const from = point(edge.from)
            const to = point(edge.to)
            const geometry = edgeGeometry(from, to, dagLayout?.edgeRoutes[edge.id])
            const selected = selection.kind === 'edge' && selection.id === edge.id
            const related = selected || (dag && selectedNode ? edge.to === selectedNode.id : selectedIds.has(edge.from) || selectedIds.has(edge.to))
            const edgeName = dag ? `直接依赖 ${edge.from} 到 ${edge.to}` : `证明步骤 ${edge.id}，${'step_id' in edge ? edge.step_id : ''}，${edge.from} 到 ${edge.to}`
            return <g key={edge.id} data-proof-edge={edge.id} data-source={edge.from} data-target={edge.to} className={`faithsieve-proof-edge${related ? ' is-related' : ''}${selected ? ' is-selected' : ''}`} role="button" tabIndex={0} aria-label={edgeName} aria-pressed={selected} onClick={() => dag ? selectNode(edge.to) : select({kind: 'edge', id: edge.id})} onKeyDown={(event) => keyboardSelect(event, dag ? {kind: 'node', id: edge.to} : {kind: 'edge', id: edge.id})}>
              <path className="faithsieve-proof-edge-hit" d={geometry.path} />
              <path className="faithsieve-proof-edge-line" d={geometry.path} />
              <polygon className="faithsieve-proof-arrow" points={geometry.arrow} />
              {!dag ? <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 5} textAnchor="middle" className="faithsieve-proof-edge-label">{edge.id}</text> : null}
            </g>
          })}
        </svg>
        {tree.nodes.map((node) => {
          const position = point(node.id)
          const selected = selection.kind === 'node' && selection.id === node.id
          const given = dag ? 'kind' in node && node.kind === 'given' : node.id === initialId
          const external = !!dag && 'kind' in node && node.kind === 'external'
          const outcome = dag ? nodeVerification[node.id] : undefined
          const nodeName = dag ? given ? '初始条件' : external ? '外部结果' : '证明结论' : '证明状态'
          const nodeTitle = `${node.id}${node.label !== node.id ? ` · ${node.label}` : ''}${external ? ' · 外部结果' : ''}`
          return <button key={node.id} type="button" data-proof-node={node.id} className={`faithsieve-proof-node${given ? ' is-root' : ''}${external ? ' is-external' : ''}${dag?.target_ids.includes(node.id) ? ' is-target' : ''}${outcome?.established ? ' is-established' : outcome?.local_status === 'refuted' ? ' is-refuted' : ''}${selectedIds.has(node.id) ? ' is-related' : ''}${selected ? ' is-selected' : ''}`} style={{left: position.x - RADIUS, top: position.y - RADIUS, width: RADIUS * 2, height: RADIUS * 2}} title={nodeTitle} aria-label={`${nodeName} ${node.id}${node.label !== node.id ? `，${node.label}` : ''}`} aria-pressed={selected} onPointerDown={(event) => startNode(event, node.id)} onClick={() => selectNode(node.id)}><span>{node.id}</span></button>
        })}
      </div></div>}
    </div>
    {!compact && (selectedNode || selectedEdge) ? <div className="faithsieve-proof-details"><h4>{selectedTitle}</h4>{dag ? selectedNode && 'statement' in selectedNode ? <DagNodeDetails node={selectedNode} graph={dag} verification={nodeVerification} select={selectNode} /> : null : selectedNode && !('statement' in selectedNode) ? <StateDetails node={selectedNode} /> : historicalEdge ? <EdgeDetails tree={tree as FaithSieveHistoricalProofTreeData} edge={historicalEdge} /> : null}{tree.ambiguities.length ? <details className="faithsieve-proof-ambiguities"><summary>待澄清（{tree.ambiguities.length}）</summary><MathItems items={tree.ambiguities} /></details> : null}</div> : null}
  </div>
}
