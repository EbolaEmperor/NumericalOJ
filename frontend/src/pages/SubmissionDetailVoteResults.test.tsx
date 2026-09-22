// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {afterEach, describe, expect, it, vi} from 'vitest'

vi.mock('../markdown/mathjaxRuntime', () => ({
  clearMath: vi.fn(),
  typesetMath: vi.fn(async () => undefined),
}))

import {WrittenVoteResults} from './SubmissionDetailPage'

afterEach(cleanup)

describe('提交详情评委切换', () => {
  it('循环回到同一评委时重新创建评语容器，避免复用 MathJax 修改过的 DOM', () => {
    const {container} = render(<WrittenVoteResults
      attempt={{
        id: 7,
        status: 'needs_manual_review',
        consensus_score: null,
        manual_override: false,
        manual_score: null,
        needs_manual_review: true,
        votes: [
          {index: 1, model: 'qwen3.7-flash', status: 'completed', score: 3, comment: '第一位评委 $x_1$'},
          {index: 2, model: 'deepseek-flash', status: 'completed', score: 4, comment: '第二位评委 $x_2$'},
        ],
      }}
      manualComment=""
    />)

    const firstRoot = container.querySelector('#studentCommentRendered')
    expect(firstRoot).not.toBeNull()
    expect(screen.getByText(/第一位评委/)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', {name: '下一位评委'}))
    const secondRoot = container.querySelector('#studentCommentRendered')
    expect(secondRoot).not.toBe(firstRoot)
    expect(screen.getByText(/第二位评委/)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', {name: '下一位评委'}))
    const returnedRoot = container.querySelector('#studentCommentRendered')
    expect(returnedRoot).not.toBe(firstRoot)
    expect(returnedRoot).not.toBe(secondRoot)
    expect(screen.getAllByText(/第一位评委/)).toHaveLength(1)
  })
})
