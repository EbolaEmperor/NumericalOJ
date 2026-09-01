import {forwardRef, useLayoutEffect, useMemo, useRef, useState, type FocusEvent, type MouseEvent, type ReactNode, type RefObject} from 'react'

import type {JsonRecord} from '../api/types'

export type EloTrajectoryPoint = JsonRecord & {
  sequence?: number
  match_id?: number | null
  created_at?: string
  rating?: number
  delta?: number
  opponent?: string
  result?: string
  participated?: boolean
}

export type EloTrajectorySeries = JsonRecord & {
  submission_id?: number
  username?: string
  current_rating?: number
  points?: EloTrajectoryPoint[]
}

type TooltipState = {
  left: number
  top: number
  color: string
  series: EloTrajectorySeries
  point: EloTrajectoryPoint
}

const CHART_HEIGHT = 390
const CHART_PADDING = {left: 58, right: 26, top: 24, bottom: 43}

function finiteNumber(value: unknown, fallback = 0) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : fallback
}

export function ratingText(value: unknown) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric.toFixed(2) : '—'
}

function compactRating(value: unknown) {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric.toFixed(0) : '—'
}

function deltaText(value: unknown) {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return '—'
  return `${numeric >= 0 ? '+' : ''}${numeric.toFixed(2)}`
}

function axisDayKey(point?: EloTrajectoryPoint) {
  const value = String(point?.created_at || '')
  return value.length >= 10 ? value.slice(0, 10) : ''
}

function axisTimeText(point: EloTrajectoryPoint | undefined, showDate: boolean) {
  if (!point || finiteNumber(point.sequence) === 0) return '起始'
  const value = String(point.created_at || '')
  if (value.length < 16) return `T${finiteNumber(point.sequence)}`
  return (showDate ? value.slice(5, 16) : value.slice(11, 16)).replace('T', ' ')
}

export function seriesColor(index: number, count: number) {
  const start = 18
  const end = count <= 1 ? 42 : 72
  const lightness = count <= 1 ? 36 : start + (end - start) * index / (count - 1)
  return `hsl(207 55% ${lightness.toFixed(1)}%)`
}

function resultLabel(value: unknown) {
  return ({
    win: '胜',
    loss: '负',
    draw: '平',
    failed: '未结算',
    initial: '起始',
  } as Record<string, string>)[String(value || '')] || String(value || '')
}

function useChartWidth(shellRef: RefObject<HTMLDivElement | null>) {
  const [width, setWidth] = useState(760)
  useLayoutEffect(() => {
    const shell = shellRef.current
    if (!shell) return undefined
    const measure = () => setWidth(Math.max(280, Math.floor(shell.clientWidth || 760)))
    measure()
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', measure)
      return () => window.removeEventListener('resize', measure)
    }
    const observer = new ResizeObserver(measure)
    observer.observe(shell)
    return () => observer.disconnect()
  }, [shellRef])
  return width
}

function Tooltip({state}: {state: TooltipState | null}) {
  const point = state?.point
  const series = state?.series
  return <div className="elo-trajectory-tooltip" hidden={!state} style={state ? {left: state.left, top: state.top} : undefined}>
    {state && point && series ? <>
      <strong style={{color: state.color}}>{String(series.username || '')} · #{finiteNumber(series.submission_id)}</strong>
      {point.match_id == null
        ? <span>起始 ELO · {ratingText(point.rating)}</span>
        : <>
          <span>{String(point.created_at || `时间点 ${finiteNumber(point.sequence)}`)} · #{finiteNumber(point.match_id)} · {resultLabel(point.result)}</span>
          <span>{ratingText(point.rating)}（{deltaText(point.delta)}）</span>
          {point.opponent ? <span>对手 · {String(point.opponent)}</span> : null}
        </>}
      {point.created_at ? <span>{String(point.created_at)}</span> : null}
    </> : null}
  </div>
}

export const EloTrajectoryResult = forwardRef<HTMLElement, {series: EloTrajectorySeries[]}>(function EloTrajectoryResult({series}, forwardedRef) {
  const shellRef = useRef<HTMLDivElement>(null)
  const width = useChartWidth(shellRef)
  const [tooltip, setTooltip] = useState<TooltipState | null>(null)
  const geometry = useMemo(() => {
    const allPoints = series.flatMap((item) => Array.isArray(item.points) ? item.points : [])
    const maxSequence = allPoints.reduce((maximum, point) => Math.max(maximum, finiteNumber(point.sequence)), 0)
    const timelinePoints = Array.isArray(series[0]?.points) ? series[0].points : []
    const ratings = allPoints.map((point) => Number(point.rating)).filter(Number.isFinite)
    if (!ratings.length) return null
    let rawMin = Math.min(...ratings)
    let rawMax = Math.max(...ratings)
    if (rawMin === rawMax) {
      rawMin -= 25
      rawMax += 25
    }
    const yStep = Math.max(10, Math.ceil((rawMax - rawMin) / 5 / 10) * 10)
    const yMin = Math.floor((rawMin - yStep * 0.45) / yStep) * yStep
    let yMax = Math.ceil((rawMax + yStep * 0.45) / yStep) * yStep
    if (yMax <= yMin) yMax = yMin + yStep
    const plotWidth = width - CHART_PADDING.left - CHART_PADDING.right
    const plotHeight = CHART_HEIGHT - CHART_PADDING.top - CHART_PADDING.bottom
    const x = (sequence: unknown) => maxSequence <= 0
      ? CHART_PADDING.left
      : CHART_PADDING.left + finiteNumber(sequence) / maxSequence * plotWidth
    const y = (rating: unknown) => CHART_PADDING.top + (yMax - finiteNumber(rating)) / (yMax - yMin) * plotHeight
    return {maxSequence, timelinePoints, yMin, yMax, plotWidth, x, y}
  }, [series, width])
  const colors = series.map((_item, index) => seriesColor(index, series.length))

  const showTooltip = (event: MouseEvent<SVGCircleElement> | FocusEvent<SVGCircleElement>, item: EloTrajectorySeries, point: EloTrajectoryPoint, color: string) => {
    const shell = shellRef.current
    if (!shell) return
    const rect = shell.getBoundingClientRect()
    const clientX = 'clientX' in event && event.clientX ? event.clientX : rect.left + 80
    const clientY = 'clientY' in event && event.clientY ? event.clientY : rect.top + 80
    const rawLeft = clientX - rect.left + shell.scrollLeft + 12
    const rawTop = clientY - rect.top + shell.scrollTop + 12
    setTooltip({
      left: Math.max(8, Math.min(rawLeft, shell.scrollWidth - 260)),
      top: Math.max(8, Math.min(rawTop, shell.scrollHeight - 110)),
      color,
      series: item,
      point,
    })
  }

  return <section ref={forwardedRef} className="elo-trajectory-result" aria-label="得分轨迹">
    <div ref={shellRef} className="elo-trajectory-chart-shell">
      <div className="elo-trajectory-chart">
        {!geometry ? <div className="elo-observer-dropdown-state">所选提交暂无轨迹数据</div> : <svg className="elo-trajectory-svg" width={width} height={CHART_HEIGHT} viewBox={`0 0 ${width} ${CHART_HEIGHT}`} role="img" aria-label="所选提交按公共对战时间线排列的 ELO 得分变化曲线" style={{width: '100%'}}>
          {Array.from({length: 6}, (_unused, gridIndex) => {
            const value = geometry.yMin + (geometry.yMax - geometry.yMin) * gridIndex / 5
            const gridY = geometry.y(value)
            return <g key={`grid-${gridIndex}`}>
              <line className="elo-trajectory-grid-line" x1={CHART_PADDING.left} y1={gridY} x2={width - CHART_PADDING.right} y2={gridY} />
              <text className="elo-trajectory-axis-label" x={CHART_PADDING.left - 9} y={gridY + 3} textAnchor="end">{compactRating(value)}</text>
            </g>
          })}
          {(() => {
            const targetTickCount = Math.max(2, Math.floor(geometry.plotWidth / 110))
            const xTickStep = Math.max(1, Math.ceil(Math.max(1, geometry.maxSequence) / targetTickCount))
            const ticks: ReactNode[] = []
            let lastTickDay = ''
            for (let sequence = 0; sequence <= geometry.maxSequence; sequence += xTickStep) {
              const point = geometry.timelinePoints[sequence]
              const tickDay = sequence > 0 ? axisDayKey(point) : ''
              ticks.push(<text className="elo-trajectory-axis-label" x={geometry.x(sequence)} y={CHART_HEIGHT - 16} textAnchor={sequence === 0 ? 'start' : sequence === geometry.maxSequence ? 'end' : 'middle'} key={`tick-${sequence}`}>{axisTimeText(point, Boolean(tickDay) && tickDay !== lastTickDay)}</text>)
              if (tickDay) lastTickDay = tickDay
            }
            if (geometry.maxSequence > 0 && geometry.maxSequence % xTickStep !== 0) {
              const point = geometry.timelinePoints[geometry.maxSequence]
              const tickDay = axisDayKey(point)
              ticks.push(<text className="elo-trajectory-axis-label" x={geometry.x(geometry.maxSequence)} y={CHART_HEIGHT - 16} textAnchor="end" key="tick-final">{axisTimeText(point, Boolean(tickDay) && tickDay !== lastTickDay)}</text>)
            }
            return ticks
          })()}
          {series.map((item, seriesIndex) => {
            const points = Array.isArray(item.points) ? item.points : []
            const linePoints = points.filter((point, pointIndex) => pointIndex === 0 || point.participated)
            const path = linePoints.map((point, pointIndex) => `${pointIndex ? 'L' : 'M'}${geometry.x(point.sequence).toFixed(2)} ${geometry.y(point.rating).toFixed(2)}`).join(' ')
            const color = colors[seriesIndex]
            return <g key={finiteNumber(item.submission_id)}>
              {path ? <path className="elo-trajectory-line" d={path} stroke={color} /> : null}
              {points.filter((point) => point.participated).map((point) => <circle
                className="elo-trajectory-point"
                cx={geometry.x(point.sequence)}
                cy={geometry.y(point.rating)}
                r={point.match_id == null ? 3.3 : 4}
                fill={color}
                tabIndex={0}
                role="button"
                aria-label={`${String(item.username || '')} 在 ${String(point.created_at || '该时间点')} 对战后的 ELO ${ratingText(point.rating)}`}
                key={`${finiteNumber(item.submission_id)}-${finiteNumber(point.sequence)}`}
                onMouseEnter={(event) => showTooltip(event, item, point, color)}
                onMouseMove={(event) => showTooltip(event, item, point, color)}
                onFocus={(event) => showTooltip(event, item, point, color)}
                onMouseLeave={() => setTooltip(null)}
                onBlur={() => setTooltip(null)}
              />)}
            </g>
          })}
        </svg>}
      </div>
      <Tooltip state={tooltip} />
    </div>
    <div className="elo-trajectory-legend">{geometry ? series.map((item, index) => <div className="elo-trajectory-legend-item" key={finiteNumber(item.submission_id)}>
      <span className="elo-trajectory-legend-swatch" style={{backgroundColor: colors[index]}} />
      <span className="elo-trajectory-legend-copy"><strong>{String(item.username || '')} · #{finiteNumber(item.submission_id)}</strong></span>
      <b>{ratingText(item.current_rating)}</b>
    </div>) : null}</div>
  </section>
})
