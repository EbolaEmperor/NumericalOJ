import {afterEach, describe, expect, it, vi} from 'vitest'

import {apiFetch, queryString} from './client'

afterEach(() => vi.unstubAllGlobals())

describe('apiFetch', () => {
  it('keeps same-origin credentials and JSON request headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({success: true, value: 7}),
      {status: 200, headers: {'Content-Type': 'application/json'}},
    ))
    vi.stubGlobal('fetch', fetchMock)

    await expect(apiFetch('/api/example')).resolves.toMatchObject({value: 7})
    expect(fetchMock).toHaveBeenCalledWith('/api/example', expect.objectContaining({
      credentials: 'same-origin',
    }))
    const headers = fetchMock.mock.calls[0][1].headers as Headers
    expect(headers.get('Accept')).toBe('application/json')
    expect(headers.get('X-Requested-With')).toBe('XMLHttpRequest')
  })

  it('normalizes failed API envelopes into ApiError', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({success: false, message: '权限不足'}),
      {status: 403, headers: {'Content-Type': 'application/json'}},
    )))

    await expect(apiFetch('/api/private')).rejects.toMatchObject({
      status: 403,
      message: '权限不足',
    })
  })
})

it('queryString omits empty values and encodes the rest', () => {
  expect(queryString({page: 2, q: '矩阵 空间', status: ''}))
    .toBe('?page=2&q=%E7%9F%A9%E9%98%B5+%E7%A9%BA%E9%97%B4')
})
