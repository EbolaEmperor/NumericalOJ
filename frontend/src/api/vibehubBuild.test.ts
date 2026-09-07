import {afterEach, expect, it, vi} from 'vitest'
import {submitVibeHubBuild} from './vibehubBuild'

afterEach(() => vi.unstubAllGlobals())

it('分块 UTF-8 日志立即交付，最终结果到达后才完成', async () => {
  let controller!: ReadableStreamDefaultController<Uint8Array>
  vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream<Uint8Array>({start(value) {controller = value}}), {headers: {'Content-Type': 'application/x-ndjson'}})))
  const events: string[] = []
  let done = false
  const pending = submitVibeHubBuild('/api/vibehub/projects', {method: 'POST'}, (event) => events.push(event.event)).then((result) => {done = true; return result})
  await Promise.resolve()
  const bytes = new TextEncoder().encode('{"event":"log","message":"中文缓存"}\n')
  controller.enqueue(bytes.slice(0, 29)); controller.enqueue(bytes.slice(29))
  await vi.waitFor(() => expect(events).toEqual(['log']))
  expect(done).toBe(false)
  controller.enqueue(new TextEncoder().encode('{"event":"result","success":true,"project":{"latest_version":4}}\n'))
  expect((await pending).project).toEqual({latest_version: 4})
})

it('结构化构建失败及提前断开不会被当成成功', async () => {
  for (const body of ['{"event":"error","message":"Dockerfile 无效","http_status":400}\n', '{"event":"heartbeat"}\n']) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body, {headers: {'Content-Type': 'application/x-ndjson'}})))
    await expect(submitVibeHubBuild('/api/vibehub/projects', {}, () => undefined)).rejects.toThrow(body.includes('error') ? 'Dockerfile 无效' : '最终结果尚未确认')
  }
})
