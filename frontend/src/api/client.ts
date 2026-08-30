import type {ApiEnvelope} from './types'

export class ApiError extends Error {
  readonly status: number
  readonly payload: ApiEnvelope | null

  constructor(message: string, status: number, payload: ApiEnvelope | null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload
  }
}

export async function apiFetch<T extends ApiEnvelope>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  headers.set('X-Requested-With', 'XMLHttpRequest')
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers,
  })
  const contentType = response.headers.get('content-type') || ''
  let payload: ApiEnvelope | null = null
  if (contentType.includes('application/json')) {
    payload = (await response.json()) as ApiEnvelope
  }
  if (!response.ok || !payload?.success) {
    throw new ApiError(
      payload?.message || `请求失败（${response.status}）`,
      response.status,
      payload,
    )
  }
  return payload as T
}

export function queryString(values: Record<string, unknown>): string {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value))
    }
  })
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '发生未知错误'
}
