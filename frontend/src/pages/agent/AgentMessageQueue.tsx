import {useMutation} from '@tanstack/react-query'
import {useState, type ChangeEvent, type FormEvent} from 'react'

import {apiFetch, errorMessage} from '../../api/client'
import type {ApiEnvelope, JsonRecord} from '../../api/types'
import {
  attachmentName,
  attachmentPath,
  messageAttachments,
  messageCopy,
  messageId,
  messageStatus,
  queuedMessages,
} from './legacyBehavior'

interface MutationResponse extends ApiEnvelope {session_state?: JsonRecord; agent_message?: JsonRecord}

function QueueEditor({message, sessionId, close, applyState, reportError}: {message: JsonRecord; sessionId: string; close: () => void; applyState: (state: JsonRecord) => void; reportError: (message: string) => void}) {
  const [copy, setCopy] = useState(messageCopy(message))
  const [removed, setRemoved] = useState<Set<string>>(() => new Set())
  const [files, setFiles] = useState<File[]>([])
  const id = messageId(message)
  const update = useMutation({
    mutationFn: () => {
      const body = new FormData()
      body.append('message', copy)
      removed.forEach((path) => body.append('remove_attachment', path))
      files.forEach((file) => body.append('attachments', file, file.name))
      return apiFetch<MutationResponse>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/messages/${encodeURIComponent(id)}/update`, {method: 'POST', body})
    },
    onSuccess: (payload) => {if (payload.session_state) applyState(payload.session_state); close()},
    onError: (error) => reportError(errorMessage(error)),
  })
  const toggleAttachment = (path: string) => setRemoved((current) => {const next = new Set(current); if (next.has(path)) next.delete(path); else next.add(path); return next})
  const choose = (event: ChangeEvent<HTMLInputElement>) => setFiles(Array.from(event.target.files || []))
  const submit = (event: FormEvent) => {event.preventDefault(); if (copy.trim() && !update.isPending) update.mutate()}
  return <form className="agent-queue-editor" onSubmit={submit}><textarea name="message" maxLength={100000} required aria-label="编辑排队消息" value={copy} onChange={(event) => setCopy(event.target.value)} autoFocus />{messageAttachments(message).length ? <div className="agent-queue-editor-attachments">{messageAttachments(message).map((attachment, index) => {const path = attachmentPath(attachment); const name = attachmentName(attachment); const isRemoved = removed.has(path); return <span className={`agent-queue-edit-attachment${isRemoved ? ' is-removed' : ''}`} key={`${path}:${index}`}><span title={name}>{name}</span><button type="button" aria-label={`${isRemoved ? '恢复' : '移除'}附件 ${name}`} onClick={() => toggleAttachment(path)}><i className="fas fa-times" /></button></span>})}</div> : null}<div className="agent-queue-editor-footer"><label><i className="fas fa-paperclip" /><span>{files.length ? `新增 ${files.length} 个附件` : '添加附件'}</span><input className="visually-hidden" type="file" multiple onChange={choose} /></label><div><button type="button" onClick={close}>取消</button><button type="submit" disabled={!copy.trim() || update.isPending}>{update.isPending ? '保存中…' : '保存'}</button></div></div></form>
}

export function AgentMessageQueue({sessionId, state, currentTaskId, running, hardBlocked, blocked, applyState, reportError}: {sessionId: string; state: JsonRecord; currentTaskId: string; running: boolean; hardBlocked: boolean; blocked: boolean; applyState: (state: JsonRecord) => void; reportError: (message: string) => void}) {
  const [editing, setEditing] = useState('')
  const messages = queuedMessages(state)
  const paused = state.queue_paused === true
  const steerSupported = state.steer_supported === true
  const mutate = useMutation({
    mutationFn: ({action, message}: {action: 'delete' | 'send-now' | 'resume'; message?: JsonRecord}) => {
      const body = new FormData()
      if (action === 'send-now') body.append('expected_task_id', currentTaskId)
      const endpoint = action === 'resume'
        ? `/api/agent/sessions/${encodeURIComponent(sessionId)}/queue/resume`
        : `/api/agent/sessions/${encodeURIComponent(sessionId)}/messages/${encodeURIComponent(messageId(message || {}))}/${action}`
      return apiFetch<MutationResponse>(endpoint, {method: 'POST', body})
    },
    onSuccess: (payload) => {if (payload.session_state) applyState(payload.session_state)},
    onError: (error) => reportError(errorMessage(error)),
  })
  if (!messages.length && !paused) return null
  return <section className="agent-message-queue" aria-label="排队消息"><header className="agent-message-queue-header"><div><i className="fas fa-layer-group" /><strong>接下来</strong><span aria-live="polite" aria-atomic="true">{messages.length}</span></div>{paused && messages.length ? <button type="button" disabled={hardBlocked || mutate.isPending} onClick={() => mutate.mutate({action: 'resume'})}>{mutate.isPending ? <><span className="spinner-border spinner-border-sm" /><span>继续中</span></> : <><i className="fas fa-play" /><span>继续队列</span></>}</button> : null}</header>{paused ? <div className="agent-queue-paused"><i className="fas fa-pause-circle" /><span>{String(state.queue_pause_reason || '上一轮没有正常结束，队列已暂停')}</span></div> : null}<ol className="agent-message-queue-list" aria-label="等待执行的消息">{messages.map((message, index) => {const id = messageId(message); const status = messageStatus(message); const queued = status === 'queued'; const canSendNow = queued && running && Boolean(currentTaskId) && steerSupported && !blocked; return <li className={`agent-queue-item${mutate.isPending && mutate.variables?.message && messageId(mutate.variables.message) === id ? ' is-pending' : ''}${editing === id ? ' is-editing' : ''}`} key={id}>{editing === id ? <QueueEditor message={message} sessionId={sessionId} close={() => setEditing('')} applyState={applyState} reportError={reportError} /> : <><div className="agent-queue-body"><div className="agent-queue-copy"><span className="agent-queue-position">{String(index + 1).padStart(2, '0')}</span>{messageCopy(message)}</div><div className="agent-queue-meta"><span>{status === 'dispatching' ? '准备发送' : messageAttachments(message).length ? `${messageAttachments(message).length} 个附件` : '等待上一轮结束'}</span>{message.error_message ? <span title={String(message.error_message)}>{String(message.error_message)}</span> : null}</div></div><div className="agent-queue-actions"><button className="agent-queue-action agent-queue-action--send" type="button" title="立刻发送" aria-label="立刻发送" disabled={!canSendNow || mutate.isPending} onClick={() => mutate.mutate({action: 'send-now', message})}><i className="fas fa-paper-plane" /></button><button className="agent-queue-action" type="button" title="编辑排队消息" aria-label="编辑排队消息" disabled={hardBlocked || !queued || mutate.isPending} onClick={() => setEditing(id)}><i className="fas fa-pen" /></button><button className="agent-queue-action agent-queue-action--danger" type="button" title="删除排队消息" aria-label="删除排队消息" disabled={hardBlocked || !queued || mutate.isPending} onClick={() => mutate.mutate({action: 'delete', message})}><i className="fas fa-trash-alt" /></button></div></>}</li>})}</ol></section>
}
