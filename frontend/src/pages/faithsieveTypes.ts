import type {ApiEnvelope} from '../api/types'
import type {FaithSieveCostSummary} from '../lib/faithSieveCost'

export interface FaithSieveResult {verdict?: string; score?: number | null; comment?: string; comment_html?: string}
export type FaithSieveExecutionMode = 'workflow' | 'skill'
export interface FaithSieveRun {
  id: number; attempt_id: string; submission_id: number; problem_id: number; problem_title?: string
  execution_mode?: FaithSieveExecutionMode
  session_id?: string | null; task_id?: string | null; judge_status?: string | null
  username?: string; student_name?: string; user_id?: number; requested_by?: string
  status: string; message?: string; created_at?: string; submission_created_at?: string; updated_at?: string; started_at?: string; finished_at?: string
  retry_eligible?: boolean
  result?: FaithSieveResult | null
  cost?: FaithSieveCostSummary | null
  runtime?: {harness?: string; endpoint_id?: number | null; model?: string | null; model_source?: string | null}
  detail_url?: string
}
export type FaithSieveProofFormat = 'dependency_dag' | 'json' | 'legacy_markdown'
export interface FaithSieveArtifact {path: string; name?: string; language?: string; size?: number; stage_key?: string; stage_keys?: string[]; format?: FaithSieveProofFormat; schema_version?: 1 | 2 | 3}
export interface FaithSieveProofTreeReference extends FaithSieveArtifact {node_verification?: unknown}
export interface FaithSieveCheck {label: string; kind?: string; state?: string; status?: string; report?: string; exit_code?: number | null}
export interface FaithSieveEdge {source: string; target: string}
export interface FaithSieveStage {
  key: string; sequence: number | null; role: string; label: string; kind: string; state: string; status?: string
  report?: string; report_html?: string; parameters?: {node_id?: string | number; edge_id?: string | number; obligation_id?: string | number; branch?: string; attempt?: number; target?: string}
  created_at?: string; updated_at?: string; session_id?: string | null; task_id?: string | null
  judge_status?: string | null
  artifacts?: FaithSieveArtifact[]; checks?: FaithSieveCheck[]
}
export interface FaithSieveListResponse extends ApiEnvelope {
  runs: FaithSieveRun[]; page: number; per_page: number; total: number; total_pages: number; page_numbers?: number[]
}
export interface FaithSieveDetailResponse extends ApiEnvelope {
  run: FaithSieveRun
  submission: {id: number; problem_id: number; username?: string; student_name?: string; created_at?: string; status?: string; score?: number | null; comment?: string; comment_html?: string; pdf_url?: string; detail_url?: string} | null
  problem: {id: number; title: string; content?: string; content_html?: string; max_score?: number} | null
  workflow: {stages: FaithSieveStage[]; edges?: FaithSieveEdge[]; proof_tree?: FaithSieveProofTreeReference | null; summary?: {stage_count: number; shown_stage_count: number; truncated: boolean}; source?: {status?: string; report?: string; artifact?: string; preprocessing?: {label?: string; state?: string; report?: string; exit_code?: number; pages?: {page: number; rendered: boolean}[]}}; artifacts: FaithSieveArtifact[]; warnings: string[]}
  result?: FaithSieveResult | null
}
export interface FaithSieveArtifactResponse extends ApiEnvelope {artifact: FaithSieveArtifact & {content: string; content_html?: string; mime_type?: string; proof_tree?: unknown; proof_tree_format?: FaithSieveProofFormat; proof_node_verification?: unknown}}
export interface FaithSieveRetryResponse extends ApiEnvelope {attempt_id: string; status: 'queued' | 'running'}

export const faithSieveListQueryKey = (search: string) => ['faithsieve-list', search] as const
export const faithSieveDetailQueryKey = (attemptId: string | undefined) => ['faithsieve-detail', attemptId] as const
export function faithSieveIsActive(status: string | undefined) {return status === 'queued' || status === 'running'}
export function faithSieveStatusLabel(status: string | undefined) {
  return ({queued: '排队中', running: '运行中', completed: '已完成', failed: '失败', endpoint_error: '失败', inconclusive: '无结论', pending: '进行中', protocol_error: '协议错误', stopped: '未完成'} as Record<string, string>)[status || ''] || status || '—'
}
export function faithSieveStageState(stage: FaithSieveStage, runStatus: string) {return stage.state === 'endpoint_error' ? 'failed' : stage.state === 'pending' ? (runStatus === 'queued' ? 'queued' : runStatus === 'running' ? 'running' : 'stopped') : stage.state === 'protocol_error' ? 'protocol_error' : 'completed'}
export function faithSieveStageKind(kind: string) {return ({llm: 'LLM', judge: 'Judge', code: '代码', result: '结果'} as Record<string, string>)[kind] || kind}
export function faithSieveVerdictClass(status: string) {return ({queued: 'pending', running: 'running', completed: 'accepted', failed: 'error', endpoint_error: 'error', inconclusive: 'unknown', protocol_error: 'error', stopped: 'unknown'} as Record<string, string>)[status] || 'unknown'}
export function faithSieveScore(result: FaithSieveResult | null | undefined) {return result && ['correct', 'incorrect'].includes(result.verdict || '') ? result.score ?? null : null}
export function faithSieveExecutionMode(run: FaithSieveRun): FaithSieveExecutionMode {return run.execution_mode === 'workflow' ? 'workflow' : 'skill'}
export function faithSieveRunDetailUrl(run: FaithSieveRun) {
  if (faithSieveExecutionMode(run) === 'skill') return run.session_id ? `/agents/${encodeURIComponent(run.session_id)}` : null
  return run.detail_url || `/admin/faithsieve/${run.attempt_id}`
}

export function faithSieveWorkflowWithResult(stages: FaithSieveStage[], edges: FaithSieveEdge[] = [], result?: FaithSieveResult | null) {
  if (!result) return {stages, edges}
  const key = 'faithsieve-result'
  const sources = new Set(edges.filter((edge) => edge.source !== edge.target && stages.some((stage) => stage.key === edge.target)).map((edge) => edge.source))
  const terminal = stages.filter((stage) => !sources.has(stage.key))
  return {
    stages: [...stages, {key, sequence: null, role: 'result', label: '评测结果', kind: 'result', state: 'completed', status: result.verdict, report: result.comment, report_html: result.comment_html} satisfies FaithSieveStage],
    edges: [...edges, ...terminal.map((stage) => ({source: stage.key, target: key}))],
  }
}
