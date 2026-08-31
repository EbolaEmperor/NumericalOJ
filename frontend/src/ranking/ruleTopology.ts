import {useMemo} from 'react'

export type RuleTopologyOptions = {nodeWidth?: number; nodeHeight?: number; marginX?: number; marginY?: number; columnGap?: number; rowGap?: number; slotPadding?: number; maxSlotStep?: number}
export type RuleTopologyRule = {rule_id?: unknown; dependencies?: unknown}
export type RuleTopologyEdge = {from: number; to: number}
export type RuleTopologyPoint = {x: number; y: number}
export type RuleTopologyRoute = {x1: number; y1: number; x2: number; y2: number; laneY: number; arrowTipY: number; points?: RuleTopologyPoint[]}
export type RuleTopologyLayout = {positions: Record<number, RuleTopologyPoint>; width: number; height: number}

function numberOption(options: RuleTopologyOptions, name: keyof RuleTopologyOptions, fallback: number) {
  const value = Number(options[name])
  return Number.isFinite(value) ? value : fallback
}

export function createRuleTopology(options: RuleTopologyOptions = {}) {
  const nodeWidth = numberOption(options, 'nodeWidth', 176)
  const nodeHeight = numberOption(options, 'nodeHeight', 96)
  const marginX = numberOption(options, 'marginX', 24)
  const marginY = numberOption(options, 'marginY', 20)
  const columnGap = numberOption(options, 'columnGap', 88)
  const rowGap = numberOption(options, 'rowGap', 72)
  const slotPadding = numberOption(options, 'slotPadding', 46)
  const maxSlotStep = numberOption(options, 'maxSlotStep', 18)
  const edgeKey = (from: number, to: number) => `${from}:${to}`

  const layout = (rules: RuleTopologyRule[]): RuleTopologyLayout | null => {
    const byId = new Map<number, RuleTopologyRule>()
    const indegree = new Map<number, number>()
    const adjacency = new Map<number, number[]>()
    rules.forEach((rule) => {
      const id = Number(rule.rule_id)
      byId.set(id, rule)
      indegree.set(id, 0)
      adjacency.set(id, [])
    })
    rules.forEach((rule) => {
      const id = Number(rule.rule_id)
      const dependencies = Array.isArray(rule.dependencies) ? rule.dependencies : []
      dependencies.forEach((value) => {
        const dependency = Number(value)
        if (!adjacency.has(dependency)) return
        adjacency.get(dependency)!.push(id)
        indegree.set(id, (indegree.get(id) || 0) + 1)
      })
    })
    const queue = [...indegree].filter(([, degree]) => degree === 0).map(([id]) => id).sort((left, right) => left - right)
    const order: number[] = []
    const level = new Map([...indegree.keys()].map((id) => [id, 0]))
    while (queue.length) {
      const id = queue.shift()!
      order.push(id)
      for (const nextId of [...(adjacency.get(id) || [])].sort((left, right) => left - right)) {
        level.set(nextId, Math.max(level.get(nextId) || 0, (level.get(id) || 0) + 1))
        indegree.set(nextId, (indegree.get(nextId) || 0) - 1)
        if (indegree.get(nextId) === 0) {
          queue.push(nextId)
          queue.sort((left, right) => left - right)
        }
      }
    }
    if (order.length !== rules.length) return null
    const columns = new Map<number, number[]>()
    let maxLevel = 0
    let maxRows = 1
    order.forEach((id) => {
      const currentLevel = level.get(id) || 0
      maxLevel = Math.max(maxLevel, currentLevel)
      columns.set(currentLevel, [...(columns.get(currentLevel) || []), id])
    })
    const positions: Record<number, RuleTopologyPoint> = {}
    const rowById = new Map<number, number>()
    ;[...columns.keys()].sort((left, right) => left - right).forEach((currentLevel) => {
      const column = columns.get(currentLevel)!
      column.sort((left, right) => {
        if (currentLevel === 0) return left - right
        const weight = (id: number) => {
          const dependencies = (Array.isArray(byId.get(id)?.dependencies) ? byId.get(id)!.dependencies as unknown[] : []).map(Number).filter((dependency) => rowById.has(dependency))
          return dependencies.length ? dependencies.reduce((sum, dependency) => sum + rowById.get(dependency)!, 0) / dependencies.length : Number.MAX_SAFE_INTEGER
        }
        return weight(left) - weight(right) || left - right
      })
      maxRows = Math.max(maxRows, column.length)
      column.forEach((id, row) => {
        rowById.set(id, row)
        positions[id] = {x: marginX + row * (nodeWidth + columnGap), y: marginY + currentLevel * (nodeHeight + rowGap)}
      })
    })
    return {positions, width: marginX * 2 + maxRows * nodeWidth + (maxRows - 1) * columnGap, height: marginY * 2 + (maxLevel + 1) * nodeHeight + maxLevel * rowGap}
  }

  const slotOffset = (index: number, count: number) => {
    if (count <= 1) return 0
    const span = Math.max(0, nodeWidth - slotPadding)
    const step = Math.min(maxSlotStep, span / Math.max(1, count - 1))
    return (index - (count - 1) / 2) * step
  }

  const buildRoutes = (edges: RuleTopologyEdge[], graphLayout: RuleTopologyLayout) => {
    type RouteItem = {
      fromId: number
      toId: number
      from: RuleTopologyPoint
      to: RuleTopologyPoint
      sourceOffset?: number
      targetOffset?: number
      routeX1?: number
      routeX2?: number
      routeLeft?: number
      routeRight?: number
      y1?: number
      y2?: number
      laneTop?: number
      laneBottom?: number
      laneY?: number
    }
    const items: RouteItem[] = []
    const bySource = new Map<number, RouteItem[]>()
    const byTarget = new Map<number, RouteItem[]>()
    const byBand = new Map<string, RouteItem[]>()
    const routes: Record<string, RuleTopologyRoute> = {}
    edges.forEach((edge) => {
      const from = graphLayout.positions[edge.from]
      const to = graphLayout.positions[edge.to]
      if (!from || !to) return
      const item: RouteItem = {fromId: edge.from, toId: edge.to, from, to}
      items.push(item)
      bySource.set(edge.from, [...(bySource.get(edge.from) || []), item])
      byTarget.set(edge.to, [...(byTarget.get(edge.to) || []), item])
      const band = `${Math.round(from.y + nodeHeight)}:${Math.round(to.y)}`
      byBand.set(band, [...(byBand.get(band) || []), item])
    })

    bySource.forEach((group) => group.sort((left, right) => left.to.x - right.to.x || left.toId - right.toId).forEach((item, index) => {item.sourceOffset = slotOffset(index, group.length)}))
    byTarget.forEach((group) => group.sort((left, right) => left.from.x - right.from.x || left.fromId - right.fromId).forEach((item, index) => {item.targetOffset = slotOffset(index, group.length)}))

    byBand.forEach((bandItems) => {
      const group = bandItems.sort((left, right) => left.from.x - right.from.x || left.to.x - right.to.x || left.fromId - right.fromId || left.toId - right.toId)
      group.forEach((item) => {
        item.routeX1 = item.from.x + nodeWidth / 2 + (item.sourceOffset || 0)
        item.routeX2 = item.to.x + nodeWidth / 2 + (item.targetOffset || 0)
        item.routeLeft = Math.min(item.routeX1, item.routeX2)
        item.routeRight = Math.max(item.routeX1, item.routeX2)
        item.y1 = item.from.y + nodeHeight
        item.y2 = item.to.y - 12
        const span = Math.max(1, item.y2 - item.y1)
        item.laneTop = item.y1 + Math.max(18, Math.min(26, span * .3))
        item.laneBottom = item.y2 - Math.max(18, Math.min(26, span * .3))
        if (item.laneBottom < item.laneTop + 10) {
          item.laneTop = item.y1 + span * .42
          item.laneBottom = item.y1 + span * .58
        }
      })
      const between = (value: number, start: number, end: number) => value > Math.min(start, end) + 2 && value < Math.max(start, end) - 2
      const intervalOverlap = (left: RouteItem, right: RouteItem, padding: number) => left.routeLeft! <= right.routeRight! + padding && right.routeLeft! <= left.routeRight! + padding
      const laneCandidates = (item: RouteItem) => {
        const center = (item.laneTop! + item.laneBottom!) / 2
        const candidates = [center]
        for (let distance = 8; center - distance >= item.laneTop! || center + distance <= item.laneBottom!; distance += 8) {
          if (center - distance >= item.laneTop!) candidates.push(center - distance)
          if (center + distance <= item.laneBottom!) candidates.push(center + distance)
        }
        return candidates
      }
      const crossingPenalty = (item: RouteItem, laneY: number, other: RouteItem) => {
        let score = 0
        if (item.routeRight! - item.routeLeft! >= 28) {
          if (other.routeX1! > item.routeLeft! + 2 && other.routeX1! < item.routeRight! - 2 && between(laneY, other.y1!, other.laneY!)) score += 1
          if (other.routeX2! > item.routeLeft! + 2 && other.routeX2! < item.routeRight! - 2 && between(laneY, other.laneY!, other.y2!)) score += 1
        }
        if (other.routeRight! - other.routeLeft! >= 28) {
          if (item.routeX1! > other.routeLeft! + 2 && item.routeX1! < other.routeRight! - 2 && between(other.laneY!, item.y1!, laneY)) score += 1
          if (item.routeX2! > other.routeLeft! + 2 && item.routeX2! < other.routeRight! - 2 && between(other.laneY!, laneY, item.y2!)) score += 1
        }
        return score
      }
      const placed: RouteItem[] = []
      group.slice().sort((left, right) => right.routeRight! - right.routeLeft! - (left.routeRight! - left.routeLeft!) || left.routeLeft! - right.routeLeft!).forEach((item) => {
        const center = (item.laneTop! + item.laneBottom!) / 2
        let best = center
        let bestScore = Number.POSITIVE_INFINITY
        laneCandidates(item).forEach((laneY) => {
          let score = Math.abs(laneY - center) * .02
          placed.forEach((other) => {
            if (item.routeRight! - item.routeLeft! >= 28 && other.routeRight! - other.routeLeft! >= 28 && Math.abs(other.laneY! - laneY) < 5 && intervalOverlap(item, other, 14)) score += 100
            score += crossingPenalty(item, laneY, other) * 16
          })
          if (score < bestScore) {bestScore = score; best = laneY}
        })
        item.laneY = best
        placed.push(item)
      })
    })

    const plannedRoutes: RuleTopologyRoute[] = []
    const crossLayerPoints = (item: RouteItem, x1: number, y1: number, x2: number, y2: number): RuleTopologyPoint[] | null => {
      const stepY = nodeHeight + rowGap
      const fromLevel = Math.round((item.from.y - marginY) / stepY)
      const toLevel = Math.round((item.to.y - marginY) / stepY)
      if (toLevel <= fromLevel + 1) return null
      const minX = 8
      const maxX = Math.max(minX, graphLayout.width - 8)
      const clampX = (x: number) => Math.max(minX, Math.min(maxX, x))
      const uniquePush = (list: number[], value: number) => {
        const rounded = Math.round(value * 10) / 10
        if (!list.includes(rounded)) list.push(rounded)
      }
      const yCandidates = (center: number, minY: number, maxY: number) => {
        const list: number[] = []
        ;[0, -8, 8, -16, 16, -24, 24].forEach((delta) => uniquePush(list, Math.max(minY, Math.min(maxY, center + delta))))
        return list
      }
      const blockedIntervals = () => {
        const intervals = Object.values(graphLayout.positions).flatMap((position) => {
          const level = Math.round((position.y - marginY) / stepY)
          return level > fromLevel && level < toLevel ? [[position.x - 12, position.x + nodeWidth + 12] as [number, number]] : []
        }).sort((left, right) => left[0] - right[0])
        const merged: Array<[number, number]> = []
        intervals.forEach((interval) => {
          const last = merged.at(-1)
          if (!last || interval[0] > last[1]) merged.push([...interval])
          else last[1] = Math.max(last[1], interval[1])
        })
        return merged
      }
      const xCandidates = (preferredX: number, intervals: Array<[number, number]>) => {
        const list: number[] = []
        ;[preferredX, x1, x2, minX, maxX].forEach((x) => uniquePush(list, clampX(x)))
        intervals.forEach((interval, index) => {
          uniquePush(list, clampX(interval[0] - 6))
          uniquePush(list, clampX(interval[1] + 6))
          if (index < intervals.length - 1) {
            const gapLeft = interval[1] + 6
            const gapRight = intervals[index + 1][0] - 6
            if (gapRight >= gapLeft) uniquePush(list, clampX((gapLeft + gapRight) / 2))
          }
        })
        return list.filter((x) => !intervals.some((interval) => x > interval[0] && x < interval[1]))
      }
      type Segment = RuleTopologyPoint & {x2: number; y2: number; vertical: boolean}
      const routeSegments = (points: RuleTopologyPoint[]) => points.slice(1).flatMap((end, index): Segment[] => {
        const start = points[index]
        if (Math.abs(start.x - end.x) < .5 && Math.abs(start.y - end.y) < .5) return []
        return [{x: start.x, y: start.y, x2: end.x, y2: end.y, vertical: Math.abs(start.x - end.x) < Math.abs(start.y - end.y)}]
      })
      const routePenalty = (points: RuleTopologyPoint[]) => {
        let score = 0
        const current = routeSegments(points)
        plannedRoutes.forEach((route) => {
          const otherPoints = route.points || [{x: route.x1, y: route.y1}, {x: route.x1, y: route.laneY}, {x: route.x2, y: route.laneY}, {x: route.x2, y: route.y2}]
          routeSegments(otherPoints).forEach((left) => current.forEach((right) => {
            if (left.vertical && right.vertical) {
              if (Math.abs(left.x - right.x) < 7 && Math.max(Math.min(left.y, left.y2), Math.min(right.y, right.y2)) <= Math.min(Math.max(left.y, left.y2), Math.max(right.y, right.y2)) + 10) score += 80
            } else if (!left.vertical && !right.vertical) {
              if (Math.abs(left.y - right.y) < 7 && Math.max(Math.min(left.x, left.x2), Math.min(right.x, right.x2)) <= Math.min(Math.max(left.x, left.x2), Math.max(right.x, right.x2)) + 10) score += 70
            } else {
              const vertical = left.vertical ? left : right
              const horizontal = left.vertical ? right : left
              if (vertical.x > Math.min(horizontal.x, horizontal.x2) + 3 && vertical.x < Math.max(horizontal.x, horizontal.x2) - 3 && horizontal.y > Math.min(vertical.y, vertical.y2) + 3 && horizontal.y < Math.max(vertical.y, vertical.y2) - 3) score += 18
            }
          }))
        })
        return score
      }
      const sourceCenterY = y1 + rowGap / 2
      const targetCenterY = item.to.y - rowGap / 2
      const sourceYs = yCandidates(sourceCenterY, y1 + 12, Math.min(y1 + rowGap - 10, y2 - 36))
      const targetYs = yCandidates(targetCenterY, Math.max(y1 + 36, item.to.y - rowGap + 10), y2 - 8)
      const intervals = blockedIntervals()
      const preferredX = x1 + (x2 - x1) * .5
      const corridorXs = xCandidates(preferredX, intervals)
      if (!corridorXs.length) corridorXs.push(clampX(preferredX), minX, maxX)
      let bestPoints: RuleTopologyPoint[] | null = null
      let bestScore = Number.POSITIVE_INFINITY
      sourceYs.forEach((sourceY) => targetYs.forEach((targetY) => corridorXs.forEach((corridorX) => {
        const points = [{x: x1, y: y1}, {x: x1, y: sourceY}, {x: corridorX, y: sourceY}, {x: corridorX, y: targetY}, {x: x2, y: targetY}, {x: x2, y: y2}]
        const score = routePenalty(points) + Math.abs(sourceY - sourceCenterY) * .5 + Math.abs(targetY - targetCenterY) * .5 + Math.abs(corridorX - preferredX) * .12
        if (score < bestScore) {bestScore = score; bestPoints = points}
      })))
      return bestPoints
    }

    items.forEach((item) => {
      const x1 = item.routeX1 ?? item.from.x + nodeWidth / 2 + (item.sourceOffset || 0)
      const y1 = item.y1 ?? item.from.y + nodeHeight
      const x2 = item.routeX2 ?? item.to.x + nodeWidth / 2 + (item.targetOffset || 0)
      const y2 = item.y2 ?? item.to.y - 12
      const span = Math.max(1, y2 - y1)
      let laneTop = y1 + Math.max(18, Math.min(26, span * .3))
      let laneBottom = y2 - Math.max(18, Math.min(26, span * .3))
      if (laneBottom < laneTop + 10) {laneTop = y1 + span * .42; laneBottom = y1 + span * .58}
      const route: RuleTopologyRoute = {x1, y1, x2, y2, laneY: item.laneY ?? (laneTop + laneBottom) / 2, arrowTipY: item.to.y - 2}
      const points = crossLayerPoints(item, x1, y1, x2, y2)
      if (points) {route.points = points; route.laneY = points[Math.max(1, points.length - 2)].y}
      plannedRoutes.push(route)
      routes[edgeKey(item.fromId, item.toId)] = route
    })
    return routes
  }

  const roundedPolylinePath = (points: RuleTopologyPoint[], radius: number) => {
    if (!points.length) return ''
    let path = `M ${points[0].x} ${points[0].y}`
    for (let index = 1; index < points.length - 1; index += 1) {
      const previous = points[index - 1]
      const current = points[index]
      const next = points[index + 1]
      const incoming = Math.hypot(current.x - previous.x, current.y - previous.y)
      const outgoing = Math.hypot(next.x - current.x, next.y - current.y)
      if (incoming < 2 || outgoing < 2) continue
      const cornerRadius = Math.min(radius, incoming / 2, outgoing / 2)
      const inX = current.x + (previous.x - current.x) * cornerRadius / incoming
      const inY = current.y + (previous.y - current.y) * cornerRadius / incoming
      const outX = current.x + (next.x - current.x) * cornerRadius / outgoing
      const outY = current.y + (next.y - current.y) * cornerRadius / outgoing
      path += ` L ${inX} ${inY} Q ${current.x} ${current.y} ${outX} ${outY}`
    }
    const last = points.at(-1)!
    return `${path} L ${last.x} ${last.y}`
  }

  const edgePath = (route: RuleTopologyRoute) => {
    if (route.points?.length) return roundedPolylinePath(route.points, 10)
    const {x1, y1, x2, y2, laneY} = route
    const difference = x2 - x1
    if (Math.abs(difference) < 2) return `M ${x1} ${y1} L ${x2} ${y2}`
    if (Math.abs(difference) < 28) {
      const soft = Math.min(18, Math.max(8, (y2 - laneY) / 2))
      return `M ${x1} ${y1} L ${x1} ${laneY} C ${x1} ${laneY + soft}, ${x2} ${laneY + soft}, ${x2} ${laneY + soft * 2} L ${x2} ${y2}`
    }
    const direction = difference >= 0 ? 1 : -1
    const radius = Math.min(14, Math.max(6, Math.abs(difference) / 2), Math.max(6, (y2 - laneY) / 2))
    return `M ${x1} ${y1} L ${x1} ${laneY - radius} Q ${x1} ${laneY} ${x1 + direction * radius} ${laneY} L ${x2 - direction * radius} ${laneY} Q ${x2} ${laneY} ${x2} ${laneY + radius} L ${x2} ${y2}`
  }
  return {layout, buildRoutes, edgePath, edgeKey}
}

export function useRuleTopology(rules: RuleTopologyRule[], options: RuleTopologyOptions) {
  const {nodeWidth, nodeHeight, marginX, marginY, columnGap, rowGap, slotPadding, maxSlotStep} = options
  const engine = useMemo(() => createRuleTopology({nodeWidth, nodeHeight, marginX, marginY, columnGap, rowGap, slotPadding, maxSlotStep}), [nodeWidth, nodeHeight, marginX, marginY, columnGap, rowGap, slotPadding, maxSlotStep])
  return useMemo(() => {
    const graphLayout = engine.layout(rules)
    const edges = rules.flatMap((rule) => (Array.isArray(rule.dependencies) ? rule.dependencies : []).map((dependency) => ({from: Number(dependency), to: Number(rule.rule_id)})))
    return {engine, layout: graphLayout, edges, routes: graphLayout ? engine.buildRoutes(edges, graphLayout) : {}}
  }, [engine, rules])
}
