export type JsonRecord = Record<string, unknown>

export interface ApiEnvelope {
  success: boolean
  message?: string
  [key: string]: unknown
}

export interface User {
  id: number
  username: string
  email?: string
  is_admin: number
}

export interface NavigationItem {
  id: string
  label: string
  path: string
  icon: string
  group: 'workspace' | 'admin'
  spa: boolean
}

export interface SessionPayload extends ApiEnvelope {
  api_version: string
  user: User | null
  navigation: {
    items: NavigationItem[]
    counts: Record<string, number>
    agent_active: boolean
    selected_class_en?: string
  }
  capabilities: {
    spa: boolean
    legacy_ui_available: boolean
    streaming: boolean
    class_adjust_enabled: boolean
    mail_service_configured: boolean
  }
}

export interface ProblemSummary extends JsonRecord {
  id: number
  problem_id?: number
  competition_id?: number
  kind?: 'problem' | 'ranking'
  title: string
  type?: number
  lang?: string
  max_score?: number
  submission_count?: number
  complete_count?: number
  ddl?: string
  is_completed?: boolean
}

export interface SubmissionSummary extends JsonRecord {
  id: number
  problem_id: number
  problem_title?: string
  display_problem_title?: string
  username?: string
  status?: string
  score?: number
  created_at?: string
}

export interface CompetitionSummary extends JsonRecord {
  id: number
  title: string
  summary?: string
  scoring_mode?: string
  max_score?: number
  is_active?: number
}
