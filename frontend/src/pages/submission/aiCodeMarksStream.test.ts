import {afterEach, describe, expect, it, vi} from 'vitest'

import {aiCodeMarksStreamInternals, streamAiCodeMarks} from './aiCodeMarksStream'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('AI 代码诊断流', () => {
  it('解析 reasoning、result 和 done 帧', async () => {
    const body = [
      'event: reasoning\ndata: {"delta":"先看失败点"}\n\n',
      'event: result\ndata: {"success":true,"issues":[{"line_start":2}]}\n\n',
      'event: done\ndata: {}\n\n',
    ].join('')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body, {
      status: 200,
      headers: {'Content-Type': 'text/event-stream'},
    })))
    const events: string[] = []

    await streamAiCodeMarks(42, (event) => events.push(event.name))

    expect(fetch).toHaveBeenCalledWith('/ask_ai_code_marks_stream', expect.objectContaining({
      method: 'POST',
      credentials: 'same-origin',
      body: JSON.stringify({submission_id: 42}),
    }))
    expect(events).toEqual(['reasoning', 'result', 'done'])
  })

  it('保留多行 data 并把流内 error 转成异常', async () => {
    expect(aiCodeMarksStreamInternals.decodeFrame('event: progress\ndata: {"message":\ndata: "整理中"}'))
      .toEqual({name: 'progress', payload: {message: '整理中'}})
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      'event: error\ndata: {"message":"模型不可用"}\n\n',
      {status: 200},
    )))

    await expect(streamAiCodeMarks(7, () => undefined)).rejects.toThrow('模型不可用')
  })
})
