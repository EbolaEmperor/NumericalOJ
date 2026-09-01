// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {afterEach, describe, expect, it} from 'vitest'

import {EloTrajectoryResult, seriesColor, type EloTrajectorySeries} from './EloTrajectoryChart'

afterEach(cleanup)

const series: EloTrajectorySeries[] = [
  {
    submission_id: 71,
    username: 'alice',
    current_rating: 1516,
    points: [
      {sequence: 0, match_id: null, created_at: '2026-08-24 09:00:00', rating: 1500, delta: 0, result: 'initial', participated: false},
      {sequence: 1, match_id: 81, created_at: '2026-08-24 10:00:00', rating: 1516, delta: 16, opponent: 'bob', result: 'win', participated: true},
      {sequence: 2, match_id: 82, created_at: '2026-08-24 11:00:00', rating: 1516, delta: 0, opponent: 'carol', result: 'failed', participated: true},
    ],
  },
  {
    submission_id: 72,
    username: 'bob',
    current_rating: 1484,
    points: [
      {sequence: 0, match_id: null, created_at: '2026-08-24 09:30:00', rating: 1500, delta: 0, result: 'initial', participated: false},
      {sequence: 1, match_id: 81, created_at: '2026-08-24 10:00:00', rating: 1484, delta: -16, opponent: 'alice', result: 'loss', participated: true},
      {sequence: 2, match_id: 82, created_at: '2026-08-24 11:00:00', rating: 1484, delta: 0, result: 'unchanged', participated: false},
    ],
  },
]

describe('EloTrajectoryResult', () => {
  it('复刻 Jinja 版坐标轴、网格、参赛点和单色阶图例', () => {
    const view = render(<EloTrajectoryResult series={series} />)

    expect(view.container.querySelectorAll('.elo-trajectory-grid-line')).toHaveLength(6)
    expect(view.container.querySelectorAll('.elo-trajectory-line')).toHaveLength(2)
    expect(view.container.querySelectorAll('.elo-trajectory-point')).toHaveLength(3)
    expect(view.container.querySelectorAll('.elo-trajectory-axis-label')).toHaveLength(9)
    expect(screen.getByText('起始')).toBeTruthy()
    expect(screen.getByText('alice · #71')).toBeTruthy()
    expect(screen.getByText('1516.00')).toBeTruthy()
    expect(seriesColor(0, 2)).toBe('hsl(207 55% 18.0%)')
    expect(seriesColor(1, 2)).toBe('hsl(207 55% 72.0%)')
  })

  it('复刻 Jinja 版数据点悬浮详情', () => {
    const view = render(<EloTrajectoryResult series={series} />)
    const point = view.container.querySelector<SVGCircleElement>('.elo-trajectory-point')
    expect(point).not.toBeNull()
    fireEvent.mouseEnter(point!, {clientX: 180, clientY: 120})

    expect(screen.getAllByText('alice · #71')).toHaveLength(2)
    expect(screen.getByText('1516.00（+16.00）')).toBeTruthy()
    expect(screen.getByText('对手 · bob')).toBeTruthy()
    expect(screen.getAllByText('2026-08-24 10:00:00').length).toBeGreaterThan(0)
  })
})
