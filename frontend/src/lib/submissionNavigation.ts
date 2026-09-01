const STORAGE_PREFIX = 'numoj.submission.origin.'

export type SubmissionNavigationState = {submissionOrigin: string}

export function normalizeSubmissionOrigin(value: unknown) {
  const text = typeof value === 'string' ? value.trim() : ''
  if (!text.startsWith('/') || text.startsWith('//') || text.includes('\\') || text.includes('\0')) return ''
  try {
    const url = new URL(text, 'https://numericaloj.local')
    if (url.origin !== 'https://numericaloj.local') return ''
    if (/^\/submissions\/[^/?#]+\/?$/.test(url.pathname)) return ''
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return ''
  }
}

export function submissionNavigationState(origin: string): SubmissionNavigationState {
  return {submissionOrigin: normalizeSubmissionOrigin(origin) || '/submissions'}
}

export function submissionOriginFromState(state: unknown) {
  if (!state || typeof state !== 'object') return ''
  return normalizeSubmissionOrigin((state as {submissionOrigin?: unknown}).submissionOrigin)
}

export function loadSubmissionOrigin(submissionId: unknown, storage: Storage | null = typeof window === 'undefined' ? null : window.sessionStorage) {
  if (!storage) return ''
  try { return normalizeSubmissionOrigin(storage.getItem(`${STORAGE_PREFIX}${String(submissionId || '')}`)) } catch { return '' }
}

export function rememberSubmissionOrigin(submissionId: unknown, origin: unknown, storage: Storage | null = typeof window === 'undefined' ? null : window.sessionStorage) {
  const normalized = normalizeSubmissionOrigin(origin)
  if (!storage || !normalized) return
  try { storage.setItem(`${STORAGE_PREFIX}${String(submissionId || '')}`, normalized) } catch { /* 隐私模式或存储配额异常时仍可依赖路由 state。 */ }
}
