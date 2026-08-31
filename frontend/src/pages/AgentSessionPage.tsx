import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useState, type FormEvent} from 'react'
import {Link, useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {Identicon} from '../components/Identicon'
import {ErrorState, LoadingState} from '../components/PageState'

interface SessionResponse extends ApiEnvelope {
  agent_session: JsonRecord
  turns: JsonRecord[]
  current_state: JsonRecord
  agent_message_state: JsonRecord
  can_resume: boolean
}
interface WorkspaceResponse extends ApiEnvelope {tree: JsonRecord[]; unavailable?: boolean}

const statusLabels: Record<string, string> = {pending: '等待中', running: '运行中', completed: '已完成', failed: '失败', canceled: '已停止', cancelled: '已停止', cleanupfailed: '清理失败', cleanup_failed: '清理失败'}
const harnessLabels: Record<string, string> = {claude_code: 'Claude Code', 'claude-code': 'Claude Code', codex: 'Codex', opencode: 'OpenCode', pi: 'Pi'}
const effortLabels: Record<string, string> = {default: '默认', off: '关闭', minimal: '最少', low: '低', medium: '中', high: '高', xhigh: '极高', max: '最大'}

function harnessName(value: unknown) {
  const text = String(value || 'Harness')
  return harnessLabels[text] || text
}

function harnessIcon(value: unknown) {
  const normalized = String(value || '').toLowerCase().replaceAll('_', '-')
  const key = ['codex', 'opencode', 'pi'].includes(normalized) ? normalized : 'claude-code'
  return `harness-logo harness-logo--${key}`
}

function WorkspaceNode({node}: {node: JsonRecord}) {
  const children = Array.isArray(node.children) ? node.children as JsonRecord[] : []
  const path = String(node.path || node.relative_path || node.name || '')
  const name = String(node.name || path.split('/').pop() || path)
  const directory = String(node.type || node.kind || '').toLowerCase() === 'directory' || children.length > 0
  if (directory) return <details className="agent-tree-directory" data-tree-path={path} open><summary><i className="fas fa-chevron-right agent-tree-chevron" /><i className="fas fa-folder agent-tree-icon" /><span className="agent-tree-label">{name}</span></summary><div className="agent-tree-children">{children.map((child, index) => <WorkspaceNode node={child} key={String(child.path || child.relative_path || child.name || index)} />)}</div></details>
  return <button className="agent-tree-file" type="button" title={path}><span /><i className="fas fa-file agent-tree-icon" /><span className="agent-tree-label">{name}</span>{node.size != null ? <small className="agent-tree-size">{Number(node.size) < 1024 ? `${Number(node.size)} B` : `${Math.ceil(Number(node.size) / 1024)} KB`}</small> : null}</button>
}

function RichHtml({html}: {html: unknown}) {
  return <div className="numoj-markdown" dangerouslySetInnerHTML={{__html: String(html || '')}} />
}

export default function AgentSessionPage() {
  const {sessionId = ''} = useParams()
  const queryClient = useQueryClient()
  const [message, setMessage] = useState('')
  const [attachments, setAttachments] = useState<File[]>([])
  const result = useQuery({
    queryKey: ['agent-session', sessionId],
    queryFn: () => apiFetch<SessionResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}`),
    refetchInterval: (query) => ['pending', 'running'].includes(String(query.state.data?.current_state?.status || '').toLowerCase()) ? 2000 : false,
  })
  const workspace = useQuery({
    queryKey: ['agent-session', sessionId, 'workspace'],
    queryFn: () => apiFetch<WorkspaceResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/workspace`),
    enabled: result.isSuccess,
    refetchInterval: (query) => ['pending', 'running'].includes(String(result.data?.current_state?.status || '').toLowerCase()) && !query.state.error ? 3000 : false,
  })
  const send = useMutation({
    mutationFn: () => {
      const body = new FormData()
      body.append('message', message)
      body.append('message_id', crypto.randomUUID())
      attachments.forEach((file) => body.append('attachments', file))
      return apiFetch<ApiEnvelope>(`/api/agent/sessions/${encodeURIComponent(sessionId)}`, {method: 'POST', body})
    },
    onSuccess: async () => {setMessage(''); setAttachments([]); await queryClient.invalidateQueries({queryKey: ['agent-session', sessionId]})},
  })
  useEffect(() => {if (result.data?.agent_session?.title) document.title = `${String(result.data.agent_session.title)} - Numerical OJ`}, [result.data])
  if (result.isPending) return <LoadingState label="正在读取 Agent 会话" />
  if (result.isError) return <ErrorState message={result.error.message} />
  const session = result.data.agent_session
  const turns = result.data.turns || []
  const state = result.data.current_state || {}
  const status = String(state.status || session.status || 'completed').toLowerCase()
  const running = ['pending', 'running'].includes(status)
  const canResume = Boolean(result.data.can_resume) && !Boolean(session.is_legacy)
  const usage = state.session_token_usage as JsonRecord | undefined
  const reasoningEffort = String(session.reasoning_effort || 'default').toLowerCase()
  const resumeBlockedMessage = session.is_legacy
    ? '旧任务没有可恢复的 workspace，无法继续会话'
    : !result.data.can_resume
      ? '只有会话发起者可以继续发送消息'
      : ['cleanupfailed', 'cleanup_failed'].includes(status)
        ? '身份配置清理失败，请管理员处理后再继续'
        : '本轮未建立可恢复的原生会话，请新建 Agent 会话'
  const submit = (event: FormEvent) => {event.preventDefault(); if (message.trim()) send.mutate()}
  return <main className="agent-session" data-agent-session data-running={running} data-status={status}>
    <section className="agent-conversation-pane" aria-label="Agent 会话">
      <header className="agent-session-header">
        <Link className="agent-session-back" to="/agents" aria-label="返回 Agent 任务列表" title="返回会话列表"><i className="fas fa-chevron-left" /></Link>
        <div className="agent-session-title"><h1>{String(session.title || 'Agent 会话')}</h1><span className={`agent-status-chip agent-status-chip--${status}`} role="status"><i /><span>{statusLabels[status] || status}</span></span></div>
        <div className="agent-session-header-side"><dl className="agent-session-usage" aria-label="会话累计 Token 用量"><div className="agent-session-usage-fact agent-session-usage-fact--input"><dt><span aria-hidden="true">INPUT</span><span className="visually-hidden">输入 Token</span></dt><dd>{String(usage?.input_tokens || '—')}</dd></div><div className="agent-session-usage-fact agent-session-usage-fact--cached"><dt><span aria-hidden="true">CACHED</span><span className="visually-hidden">缓存输入占比</span></dt><dd>{String(usage?.cached_input_tokens || '—')}</dd></div><div className="agent-session-usage-fact agent-session-usage-fact--output"><dt><span aria-hidden="true">OUTPUT</span><span className="visually-hidden">输出 Token</span></dt><dd>{String(usage?.output_tokens || '—')}</dd></div><div className="agent-session-usage-fact agent-session-usage-fact--cost"><dt><span aria-hidden="true">COST</span><span className="visually-hidden">费用（人民币）</span></dt><dd>{String(usage?.cost || '—')}</dd></div></dl><div className="agent-session-requester" role="group" aria-label={`发起者：${String(session.requested_by || '')}`} title={`发起者：${String(session.requested_by || '')}`}><Identicon seed={String(session.requested_by || '')} className="numoj-avatar agent-session-avatar" /><span className="agent-session-requester-copy"><small>发起者</small><strong>{String(session.requested_by || '')}</strong></span></div><button className="agent-workspace-mobile-toggle" type="button" aria-label="打开 Workspace" aria-expanded="false"><i className="fas fa-folder-tree" /></button></div>
      </header>
      <div className="agent-conversation-scroll"><div className="agent-conversation-feed">{turns.map((turn, index) => <article className="agent-turn" key={String(turn.task_id || index)}><section className="agent-user-message"><div className="agent-user-message-row"><div className="agent-user-bubble"><RichHtml html={turn.user_message_html || turn.user_message} /></div></div></section><section className="agent-response">{turn.has_detail ? <details className="agent-turn-details"><summary><span><i className="fas fa-chevron-right" />工作详情</span>{turn.duration ? <small>{String(turn.duration)}</small> : null}</summary><div className="agent-turn-trace"><div className="agent-work-block-placeholder">工作详情可按需加载</div></div></details> : null}<div className="agent-conclusion"><RichHtml html={turn.conclusion_html || turn.final_response_html || turn.conclusion} /></div></section></article>)}{running ? <article className="agent-turn agent-turn--live"><section className="agent-response"><details className="agent-turn-details" open><summary><span><i className="fas fa-chevron-right" />Agent 正在工作</span><span className="agent-live-mark"><i />LIVE</span></summary><div className="agent-turn-trace"><div className="agent-working-placeholder"><span className="math-curve-loader" data-math-curve-loader data-size="sm"><span className="math-curve-loader__label">Agent 正在工作</span></span></div></div></details></section></article> : null}</div></div>
      <footer className="agent-resume-dock"><form className={`agent-resume-composer${running ? ' is-running' : ''}${!canResume ? ' is-blocked' : ''}`} onSubmit={submit}><label className="visually-hidden" htmlFor="agentResumeMessage">继续会话</label><textarea id="agentResumeMessage" rows={2} maxLength={100000} placeholder="继续这项任务…" value={message} onChange={(event) => setMessage(event.target.value)} disabled={!canResume} required /><div className="agent-resume-footer"><div className="agent-resume-runtime"><span className="agent-resume-harness"><i className={harnessIcon(session.harness)} />{harnessName(session.harness_label || session.harness)}</span><span className="agent-resume-model"><i className="fas fa-microchip" data-model-family-logo data-model-name={String(session.endpoint_model || session.model || '')} />{String(session.endpoint_model || session.model || '模型节点')}</span><span className="agent-resume-effort" aria-label={`推理等级：${reasoningEffort === 'default' ? '使用 Harness 原生默认' : effortLabels[reasoningEffort] || reasoningEffort}`}><span className="agent-effort-logo" aria-hidden="true" />{effortLabels[reasoningEffort] || reasoningEffort}</span><button className="agent-context-meter" type="button" aria-label="上下文用量暂不可用"><svg viewBox="0 0 20 20" aria-hidden="true" focusable="false"><circle className="agent-context-meter-track" cx="10" cy="10" r="7.5" /><circle className="agent-context-meter-value" cx="10" cy="10" r="7.5" pathLength="100" /></svg></button></div><div className="agent-resume-actions"><label className="agent-resume-attach" title="添加附件" aria-label="添加附件"><input className="visually-hidden" type="file" multiple onChange={(event) => setAttachments(Array.from(event.target.files || []))} disabled={!canResume} /><i className="fas fa-plus" /></label><button className="agent-resume-send" type="submit" disabled={!canResume || !message.trim() || send.isPending} aria-label={running ? '加入队列' : '发送消息'}><i className="fas fa-arrow-up" /></button></div></div>{send.isError ? <p className="agent-resume-feedback" role="alert">{errorMessage(send.error)}</p> : !canResume ? <p className="agent-resume-feedback">{resumeBlockedMessage}</p> : null}</form></footer>
    </section>
    <div className="agent-splitter agent-splitter--workspace" role="separator" tabIndex={0} aria-label="调整 Workspace 宽度" aria-orientation="vertical" aria-valuemin={12} aria-valuemax={45} aria-valuenow={22} />
    <aside className="agent-workspace-pane" aria-label="Workspace 文件"><header className="agent-workspace-header"><div><span>WORKSPACE</span><strong>文件</strong></div><div><span className={`agent-workspace-sync${workspace.isFetching ? ' is-syncing' : workspace.isError ? ' is-error' : ''}`} title={workspace.isFetching ? '正在同步 Workspace' : workspace.isError ? '无法读取 Workspace' : 'Workspace 已同步'}><i className={`fas ${workspace.isFetching ? 'fa-sync-alt' : workspace.isError ? 'fa-times-circle' : 'fa-check'}`} /></span><button type="button" aria-label="关闭 Workspace"><i className="fas fa-times" /></button></div></header><div className="agent-workspace-tree" aria-label="Workspace 目录结构">{workspace.isPending ? <div className="agent-workspace-loading"><span className="math-curve-loader" data-size="xs"><span className="math-curve-loader__label">正在读取 Workspace</span></span></div> : workspace.isError ? <div className="agent-workspace-empty">无法读取 Workspace</div> : workspace.data.tree.length ? workspace.data.tree.map((node, index) => <WorkspaceNode node={node} key={String(node.path || node.relative_path || node.name || index)} />) : <div className="agent-workspace-empty">Workspace 还是空的。</div>}</div></aside>
  </main>
}
