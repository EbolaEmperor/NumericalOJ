import type {JsonRecord} from '../../api/types'
import {
  attachmentName,
  attachmentPath,
  composerFileSize,
} from './legacyBehavior'

export function PendingAttachmentStrip({files, remove, variant = 'create'}: {files: File[]; remove: (index: number) => void; variant?: 'create' | 'resume'}) {
  if (!files.length) return null
  if (variant === 'resume') return <div className="agent-resume-attachments" aria-label="待上传附件">{files.map((file, index) => <span className="agent-resume-file-chip" key={`${file.name}:${file.size}:${file.lastModified}`}><i className={`fas ${file.type.startsWith('image/') ? 'fa-image' : 'fa-paperclip'}`} aria-hidden="true" /><span title={file.name}>{file.name}</span><button type="button" aria-label={`移除附件 ${file.name}`} onClick={() => remove(index)}><i className="fas fa-times" aria-hidden="true" /></button></span>)}</div>
  return <div className="agent-attachment-strip" aria-label="已选择的附件">{files.map((file, index) => <span className="agent-attachment-chip" key={`${file.name}:${file.size}:${file.lastModified}`} title={file.name}><i className={`fas ${file.type.startsWith('image/') ? 'fa-image' : 'fa-paperclip'}`} aria-hidden="true" /><span className="agent-attachment-chip-copy"><strong>{file.name}</strong><small>{composerFileSize(file.size)}</small></span><button className="agent-attachment-remove" type="button" aria-label={`移除附件 ${file.name}`} onClick={() => remove(index)}><i className="fas fa-times" aria-hidden="true" /></button></span>)}</div>
}

export function SavedAttachments({attachments, sessionId, openFile}: {attachments: JsonRecord[]; sessionId: string; openFile: (path: string) => void}) {
  if (!attachments.length) return null
  return <div className="agent-message-attachments">{attachments.map((attachment, index) => {
    const path = attachmentPath(attachment)
    const name = attachmentName(attachment)
    const download = `/api/agent/sessions/${encodeURIComponent(sessionId)}/workspace/file?path=${encodeURIComponent(path)}&download=1`
    return <span className="agent-message-attachment" key={`${path}:${name}:${index}`}><i className="fas fa-paperclip" aria-hidden="true" />{path ? <button type="button" title={`预览 ${name}`} onClick={() => openFile(path)}>{name}</button> : <span>{name}</span>}{attachment.size ? <small>{String(attachment.size)}</small> : null}{path ? <a href={download} download={name} title={`下载 ${name}`} aria-label={`下载 ${name}`}><i className="fas fa-download" aria-hidden="true" /></a> : null}</span>
  })}</div>
}
