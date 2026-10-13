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

  it('关闭公开评分后清除已缓存分数、评语和评委结果，保留原稿转写', () => {
    const current = {
      success: true,
      result_visible: true,
      submission: {id: 7, problem_id: 2, problem_type: 2, result_visible: true, status: 'Accepted', score: 5, code: '原评语'},
      test_points: [],
      submission_latex_text: '学生答案',
      submission_latex_html: '<p>学生答案</p>',
      written_submission: {show_latex_transcription: true, vote: {id: 9, votes: [{index: 1, score: 5, comment: 'AI 评语'}]}},
    }

    const merged = mergeSubmissionDetailSnapshot(current, {status: '评分未公开', result_visible: false, score: null, written_comment: '', written_vote: null, is_judging: false})

    expect(merged?.submission).toMatchObject({score: null, code: '', result_visible: false, is_judging: false})
    expect(merged?.result_visible).toBe(false)
    expect(merged?.written_submission).toEqual({show_latex_transcription: true, vote: null})
    expect(merged?.submission_latex_text).toBe('学生答案')
    expect(merged?.submission_latex_html).toBe('<p>学生答案</p>')

    const published = mergeSubmissionDetailSnapshot(merged, {status: 'Accepted', result_visible: true, score: 5, written_comment: '审核后评语', written_vote: current.written_submission.vote})
    expect(published?.submission).toMatchObject({score: 5, code: '审核后评语', result_visible: true})
    expect(published?.written_submission?.vote).toEqual(current.written_submission.vote)
  })

  it('隐藏标记主动清理缺失字段的旧快照，显式 vote:null 也能独立清除评委缓存', () => {
    const current = {success: true, submission: {id: 7, problem_id: 2, score: 4, code: '旧评语'}, test_points: [], written_submission: {vote: {votes: [{score: 4}]}}}
    expect(mergeSubmissionDetailSnapshot(current, {result_visible: false})?.submission).toMatchObject({score: null, code: ''})
    expect(mergeSubmissionDetailSnapshot(current, {written_vote: null})?.written_submission?.vote).toBeNull()
  })
})
