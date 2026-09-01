// @vitest-environment jsdom

import {beforeEach, describe, expect, it} from 'vitest'

import {
  loadSubmissionOrigin,
  normalizeSubmissionOrigin,
  rememberSubmissionOrigin,
  submissionNavigationState,
  submissionOriginFromState,
} from './submissionNavigation'

beforeEach(() => window.sessionStorage.clear())

describe('submissionNavigation', () => {
  it('保留提交列表的分页和全部筛选参数', () => {
    const origin = '/submissions?page=3&q=lean+proof&status=Accepted&problem_id=42'

    expect(submissionNavigationState(origin)).toEqual({submissionOrigin: origin})
    expect(submissionOriginFromState({submissionOrigin: origin})).toBe(origin)
  })

  it('保留从题目页进入提交详情的来源', () => {
    expect(normalizeSubmissionOrigin('/problems/42?tab=submissions#recent'))
      .toBe('/problems/42?tab=submissions#recent')
  })

  it('拒绝站外地址、协议相对地址和另一条提交详情地址', () => {
    expect(normalizeSubmissionOrigin('https://example.com/submissions')).toBe('')
    expect(normalizeSubmissionOrigin('//example.com/submissions')).toBe('')
    expect(normalizeSubmissionOrigin('/submissions/123')).toBe('')
  })

  it('刷新提交详情后仍能从会话存储恢复来源', () => {
    const origin = '/submissions?page=4&status=Wrong+Answer'
    rememberSubmissionOrigin(123, origin)

    expect(loadSubmissionOrigin(123)).toBe(origin)
    expect(loadSubmissionOrigin(124)).toBe('')
  })
})
