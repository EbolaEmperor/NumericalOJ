// @vitest-environment jsdom

import {describe, expect, it} from 'vitest'

import {defaultTestPointIndex, mergeSubmissionDetailSnapshot} from './SubmissionDetailPage'

describe('提交详情实时快照', () => {
  it('缺失 Prompt 字段时保留原始 Prompt，并接收生成后的代码', () => {
    const current = {
      success: true,
      submission: {id: 7, problem_id: 2, generated_from_prompt: true, code: ''},
      test_points: [],
    }

    const merged = mergeSubmissionDetailSnapshot(current, {
      status: 'Pending',
      code: 'print(42)\n',
      test_points: [],
    })

    expect(merged?.submission.generated_from_prompt).toBe(true)
    expect(merged?.submission.code).toBe('print(42)\n')
  })

  it('终态默认选择第一个失败测试点', () => {
    expect(defaultTestPointIndex([
      {status: 'Accepted'},
      {status: 'Wrong Answer'},
      {status: 'Runtime Error'},
    ])).toBe(1)
    expect(defaultTestPointIndex([{status: 'Accepted'}])).toBe(0)
  })
})
