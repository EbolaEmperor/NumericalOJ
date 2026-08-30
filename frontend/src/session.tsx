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

export function SessionProvider({children}: PropsWithChildren) {
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['session'],
    queryFn: () => apiFetch<SessionPayload>('/api/v1/session'),
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
