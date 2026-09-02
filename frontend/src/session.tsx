import {useQuery, useQueryClient} from '@tanstack/react-query'
import {createContext, useContext, type PropsWithChildren} from 'react'

import {apiFetch} from './api/client'
import type {SessionPayload} from './api/types'

interface SessionContextValue {
  session: SessionPayload | undefined
  loading: boolean
  refresh: () => Promise<void>
}

const SessionContext = createContext<SessionContextValue | null>(null)
const NAVIGATION_CACHE_TTL_MS = 10_000

function withSessionNavigationCache(payload: SessionPayload) {
  if (!payload.user) return payload
  const selectedClass = new URLSearchParams(window.location.search).get('class_en') || ''
  const key = ['numoj.layoutNavigation.v1', payload.user.id, '/api/layout-navigation', selectedClass].join(':')
  try {
    const cached = JSON.parse(window.sessionStorage.getItem(key) || 'null') as {savedAt?: number; data?: {counts?: Record<string, number>; agent_active?: boolean}} | null
    if (cached?.savedAt && cached.data && Date.now() - cached.savedAt < NAVIGATION_CACHE_TTL_MS) {
      return {...payload, navigation: {...payload.navigation, counts: cached.data.counts || {}, agent_active: Boolean(cached.data.agent_active)}}
    }
    window.sessionStorage.setItem(key, JSON.stringify({savedAt: Date.now(), data: {success: true, counts: payload.navigation.counts, agent_active: payload.navigation.agent_active}}))
  } catch { /* 隐私模式或容量受限时退化为实时响应。 */ }
  return payload
}

export function SessionProvider({children}: PropsWithChildren) {
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['session'],
    queryFn: async () => withSessionNavigationCache(await apiFetch<SessionPayload>('/api/v1/session')),
    staleTime: 10_000,
    retry: 1,
  })

  return (
    <SessionContext.Provider
      value={{
        session: query.data,
        loading: query.isPending,
        refresh: async () => {
          await queryClient.invalidateQueries({queryKey: ['session']})
        },
      }}
    >
      {children}
    </SessionContext.Provider>
  )
}

export function useSession() {
  const value = useContext(SessionContext)
  if (!value) throw new Error('useSession 必须在 SessionProvider 内使用')
  return value
}
