import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {Fragment, useEffect, useMemo, useRef, useState, type FormEvent} from 'react'

import {ApiError, apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {MonacoEditor, type MonacoEditorInstance} from '../components/MonacoEditor'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {LoadingState} from '../components/PageState'
import {useNativeDialog} from '../components/useNativeDialog'
import {copyText} from '../lib/clipboard'
import {descriptorsFromFiles, digestSha256, extractDropDescriptors, type RepositoryUploadDescriptor} from './repositoryUpload'

interface TreeResponse extends ApiEnvelope {
  entries?: JsonRecord[]
  tree?: JsonRecord[]
  structure_version?: number
  entry_count?: number
  total_size?: number
  quota?: {
    file_bytes?: number
    total_bytes?: number
    used_bytes?: number
  }
}
interface FileResponse extends ApiEnvelope {id?: number; entry_id?: number; filename?: string; name?: string; parent_id?: number | null; relative_path?: string; content?: string; file_version?: number}
interface SaveResponse extends ApiEnvelope {entry?: JsonRecord; file_version?: number; version?: number; structure_version?: number}
interface IndexResponse extends ApiEnvelope {job_id?: number; job?: JsonRecord; has_active?: boolean}
interface SearchResponse extends ApiEnvelope {hits?: JsonRecord[]; embedding_model?: string}
interface DeletePreview extends ApiEnvelope {confirmation_token?: string; path?: string; kind?: string; entry_count?: number; file_count?: number; directory_count?: number; total_size?: number}
interface UploadPreview extends ApiEnvelope {session_id?: string; status?: string; structure_version?: number; base_structure_version?: number; ready?: boolean; files?: JsonRecord[]; directories?: JsonRecord[]; entries?: JsonRecord[]; committed?: JsonRecord[]; committed_count?: number}
type Entry = JsonRecord & {depth: number}
type DialogName = 'upload' | 'manage' | 'delete' | null
type InlineCreate = {kind: 'file' | 'directory'; parentId: number | null; value: string; error: string; saving: boolean}
type SaveSnapshot = {id: number; content: string; version?: number; relativePath: string}
type SaveConflict = {snapshot: SaveSnapshot; message: string}
type UploadPhase = 'idle' | 'preparing' | 'uploading' | 'finalizing' | 'needs_encoding' | 'ready' | 'committing' | 'error'
type UploadItem = RepositoryUploadDescriptor & {
  key: string
  rawSha256?: string
  token?: string
  receivedBytes: number
  serverStatus: string
  serverMessage: string
  pathError: string
  candidateEncoding: string
  encodingPreview: string
  encodingPreviewTruncated: boolean
  encodingHasDisallowedControl: boolean
  encodingConfirmed: boolean
  encoding: string
  resolution: 'overwrite' | 'skip' | 'rename' | 'exclude'
  renameTarget: string
  error: string
}

const ACTIVE_INDEX_STORAGE_KEY = 'repositoryIndexJobId'

function storedIndexJobId() {
  try {
    const value = Number(window.localStorage.getItem(ACTIVE_INDEX_STORAGE_KEY) || 0)
    return Number.isInteger(value) && value > 0 ? value : null
  } catch {
    return null
  }
}

function indexJobRunning(job?: JsonRecord | null) {
  return Boolean(job && ['queued', 'pending', 'running'].includes(String(job.status || '').toLowerCase()))
}

function Icon({name}: {name: string}) {return <svg className="repository-icon"><use href={`#repo-icon-${name}`} /></svg>}

function markedName(name: string, query: string) {
  if (!query) return name
  const index = name.toLocaleLowerCase().indexOf(query.toLocaleLowerCase())
  if (index < 0) return name
  return <>{name.slice(0, index)}<mark>{name.slice(index, index + query.length)}</mark>{name.slice(index + query.length)}</>
}

function formatBytes(value: number) {
  const bytes = Number.isFinite(value) && value > 0 ? value : 0
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MiB`
}

function decoratedEntries(values: JsonRecord[]): Entry[] {
  const byId = new Map(values.map((item) => [Number(item.id || item.entry_id || 0), item]))
  const depthFor = (item: JsonRecord, seen = new Set<number>()): number => {
    const parent = Number(item.parent_id || 0)
    if (!parent || seen.has(parent)) return 0
    const parentEntry = byId.get(parent)
    if (!parentEntry) return 0
    seen.add(parent)
    return Math.min(8, 1 + depthFor(parentEntry, seen))
  }
  return values.map((item) => ({...item, depth: depthFor(item)}))
}

function outlineSymbols(content: string, filename: string) {
  const symbols: Array<{type: string; kind: string; name: string; line: number}> = []
  const extension = filename.split('.').pop()?.toLowerCase()
  content.split('\n').forEach((line, index) => {
    let match: RegExpMatchArray | null = null
    if (extension === 'py') {
      match = line.match(/^\s*class\s+([A-Za-z_]\w*)/)
      if (match) symbols.push({type: 'C', kind: 'class', name: match[1], line: index + 1})
      match = line.match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)/)
      if (match) symbols.push({type: 'ƒ', kind: 'function', name: match[1], line: index + 1})
      return
    }
    match = line.match(/^\s*(?:class|struct)\s+([A-Za-z_]\w*)/)
    if (match) symbols.push({type: 'C', kind: 'class', name: match[1], line: index + 1})
    match = line.match(/^\s*(?:function\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:\{|=>)/)
    if (match && !['if', 'for', 'while', 'switch', 'catch'].includes(match[1])) symbols.push({type: 'ƒ', kind: 'function', name: match[1], line: index + 1})
  })
  return symbols
}

function languageForFilename(filename: string) {
  const extension = filename.split('.').pop()?.toLowerCase()
  const languages: Record<string, string> = {
    c: 'c', cc: 'cpp', cpp: 'cpp', cxx: 'cpp', h: 'cpp', hpp: 'cpp',
    js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript',
    py: 'python', m: 'matlab', lean: 'lean4', json: 'json', html: 'html', css: 'css',
  }
  return languages[extension || ''] || 'plaintext'
}

function languageLabelForFilename(filename: string) {
  const extension = filename.split('.').pop()?.toLowerCase()
  const labels: Record<string, string> = {
    c: 'C', cc: 'C++ Source', cpp: 'C++ Source', cxx: 'C++ Source',
    h: 'C / C++ Header', hpp: 'C / C++ Header', java: 'Java',
    js: 'JavaScript', jsx: 'JavaScript', json: 'JSON', m: 'MATLAB / Octave',
    md: 'Markdown', py: 'Python', rs: 'Rust', sh: 'Shell',
    ts: 'TypeScript', tsx: 'TypeScript', yaml: 'YAML', yml: 'YAML',
  }
  return labels[extension || ''] || 'Plain Text'
}

function validateUploadPath(value: string) {
  const path = value.normalize('NFC').replace(/^\.\//, '')
  const parts = path.split('/')
  const valid = Boolean(path) && !path.startsWith('/') && !path.includes('\\') && parts.every((part) => Boolean(part) && part !== '.' && part !== '..')
  return {path, valid, message: valid ? '' : '请输入不含空段、反斜杠、“.” 或“..”的相对路径'}
}

function suggestedRenamePath(path: string) {
  const slash = path.lastIndexOf('/')
  const directory = slash >= 0 ? path.slice(0, slash + 1) : ''
  const name = slash >= 0 ? path.slice(slash + 1) : path
  const dot = name.lastIndexOf('.')
  return `${directory}${dot > 0 ? name.slice(0, dot) : name}-copy${dot > 0 ? name.slice(dot) : ''}`
}

function uploadItemsFromDescriptors(descriptors: RepositoryUploadDescriptor[]) {
  const seen = new Set<string>()
  return descriptors.map((descriptor, index): UploadItem => {
    const checked = validateUploadPath(descriptor.relativePath)
    const duplicate = seen.has(checked.path.toLocaleLowerCase())
    seen.add(checked.path.toLocaleLowerCase())
    return {
      ...descriptor,
      relativePath: checked.path,
      key: `${descriptor.kind}:${checked.path}:${index}`,
      receivedBytes: 0,
      serverStatus: 'pending',
      serverMessage: '',
      pathError: checked.valid && !duplicate ? '' : duplicate ? '上传清单中已有相同路径' : checked.message,
      candidateEncoding: '',
      encodingPreview: '',
      encodingPreviewTruncated: false,
      encodingHasDisallowedControl: false,
      encodingConfirmed: false,
      encoding: '等待识别',
      resolution: 'overwrite',
      renameTarget: suggestedRenamePath(checked.path),
      error: checked.valid && !duplicate ? '' : duplicate ? '上传清单中已有相同路径' : checked.message,
    }
  })
}

function Dialog({title, kicker, onClose, children, footer, className = '', closeLabel = '关闭', footerClassName = ''}: {title: string; kicker: string; onClose: () => void; children: React.ReactNode; footer: React.ReactNode; className?: string; closeLabel?: string; footerClassName?: string}) {
  const ref = useNativeDialog(true)
  return <dialog ref={ref} className={`repository-dialog${className ? ` ${className}` : ''}`} onCancel={(event) => {event.preventDefault(); onClose()}}>
    <header><div><p>{kicker}</p><h2>{title}</h2></div><button className="repository-icon-button" type="button" onClick={onClose} aria-label={closeLabel}><Icon name="close" /></button></header>
    <div className="repository-dialog-body">{children}</div>
    <footer className={footerClassName || undefined}>{footer}</footer>
  </dialog>
}

export default function RepositoryPage() {
  const queryClient = useQueryClient()
  const editorRef = useRef<MonacoEditorInstance | null>(null)
  const draftRef = useRef<string | null>(null)
  const saveInFlightRef = useRef<Promise<boolean> | null>(null)
  const saveCurrentFileRef = useRef<(options?: {silent?: boolean; drain?: boolean}) => Promise<boolean>>(() => Promise.resolve(true))
  const openSequenceRef = useRef(0)
  const uploadSequenceRef = useRef(0)
  const inlineCreateRef = useRef<HTMLInputElement>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const [draft, setDraft] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [expanded, setExpanded] = useState<number[]>([])
  const [focusedDirectory, setFocusedDirectory] = useState<number | null>(null)
  const [inlineCreate, setInlineCreate] = useState<InlineCreate | null>(null)
  const [mobileFiles, setMobileFiles] = useState(false)
  const [inspector, setInspector] = useState<'outline' | 'semantic'>('outline')
  const [semanticQuery, setSemanticQuery] = useState('')
  const [cursor, setCursor] = useState({line: 1, column: 1})
  const [dialog, setDialog] = useState<DialogName>(null)
  const [manageMode, setManageMode] = useState<'rename' | 'move'>('move')
  const [mergeDirectories, setMergeDirectories] = useState(false)
  const [contextMenu, setContextMenu] = useState<{entry: Entry; left: number; top: number} | null>(null)
  const [actionEntry, setActionEntry] = useState<Entry | null>(null)
  const [entryName, setEntryName] = useState('')
  const [destination, setDestination] = useState('')
  const [uploadItems, setUploadItems] = useState<UploadItem[]>([])
  const [uploadSessionId, setUploadSessionId] = useState('')
  const [uploadStructureVersion, setUploadStructureVersion] = useState<number | undefined>()
  const [uploadPhase, setUploadPhase] = useState<UploadPhase>('idle')
  const [uploadError, setUploadError] = useState('')
  const [uploadDrag, setUploadDrag] = useState(false)
  const [draggedEntryId, setDraggedEntryId] = useState<number | null>(null)
  const [treeDropTargetId, setTreeDropTargetId] = useState<number | null | 'root'>(null)
  const [externalDragDepth, setExternalDragDepth] = useState(0)
  const [externalDropTarget, setExternalDropTarget] = useState<number | null>(null)
  const uploadFilesRef = useRef<HTMLInputElement>(null)
  const uploadFolderRef = useRef<HTMLInputElement>(null)
  const manageNameRef = useRef<HTMLInputElement>(null)
  const manageDestinationRef = useRef<HTMLSelectElement>(null)
  const [deletePreview, setDeletePreview] = useState<DeletePreview | null>(null)
  const [saveConflict, setSaveConflict] = useState<SaveConflict | null>(null)
  const [conflictReloadConfirmed, setConflictReloadConfirmed] = useState(false)
  const [indexJobId, setIndexJobId] = useState<number | null>(storedIndexJobId)
  const handledIndexTerminal = useRef<number | null>(null)
  const [notice, setNotice] = useState<{title: string; message: string; error?: boolean} | null>(null)

  const context = useQuery({queryKey: ['repository', 'context'], queryFn: () => apiFetch<ApiEnvelope>('/api/repository/context')})
  const tree = useQuery({queryKey: ['repository', 'tree'], queryFn: () => apiFetch<TreeResponse>('/api/repository/tree')})
  const file = useQuery({queryKey: ['repository', 'file', selected], queryFn: () => apiFetch<FileResponse>(`/api/repository/file/${selected}`), enabled: selected != null})
  const activeIndex = useQuery({queryKey: ['repository', 'index', 'active'], queryFn: () => apiFetch<IndexResponse>('/api/repository/index/status/active'), enabled: context.isSuccess})
  const indexStatus = useQuery({queryKey: ['repository', 'index', indexJobId], queryFn: () => apiFetch<IndexResponse>(`/api/repository/index/status/${indexJobId}`), enabled: indexJobId != null, retry: false, refetchInterval: (query) => indexJobId != null && indexJobRunning(query.state.data?.job) ? 1500 : false})

  const entries = useMemo(() => decoratedEntries(tree.data?.entries || tree.data?.tree || []), [tree.data])
  const entryMap = useMemo(() => new Map(entries.map((item) => [Number(item.id || item.entry_id || 0), item])), [entries])
  const visibleEntryIds = useMemo(() => {
    const query = filter.trim().toLowerCase()
    if (!query) return null
    const ids = new Set<number>()
    entries.forEach((entry) => {
      const path = String(entry.relative_path || entry.path || entry.name || '').toLowerCase()
      if (!path.includes(query)) return
      let item: Entry | undefined = entry
      while (item) {
        const id = Number(item.id || item.entry_id || 0)
        if (!id || ids.has(id)) break
        ids.add(id)
        item = entryMap.get(Number(item.parent_id || 0))
      }
    })
    return ids
  }, [entries, entryMap, filter])
  const treeRows = useMemo(() => {
    const byParent = new Map<number, Entry[]>()
    entries.forEach((entry) => {
      const parent = Number(entry.parent_id || 0)
      byParent.set(parent, [...(byParent.get(parent) || []), entry])
    })
    const rows: Array<{type: 'entry'; entry: Entry; depth: number} | {type: 'inline'; depth: number}> = []
    const walk = (parentId: number, depth: number) => {
      if (!filter.trim() && inlineCreate?.parentId === (parentId || null)) rows.push({type: 'inline', depth})
      ;(byParent.get(parentId) || []).forEach((entry) => {
        const id = Number(entry.id || entry.entry_id || 0)
        if (visibleEntryIds && !visibleEntryIds.has(id)) return
        rows.push({type: 'entry', entry, depth})
        if (String(entry.kind || entry.type) === 'directory' && (visibleEntryIds || expanded.includes(id))) walk(id, depth + 1)
      })
    }
    walk(0, 0)
    return rows
  }, [entries, expanded, filter, inlineCreate?.parentId, visibleEntryIds])
  const directories = entries.filter((item) => String(item.kind || item.type) === 'directory')
  const files = entries.filter((item) => String(item.kind || item.type) !== 'directory')
  const usedBytes = Number(tree.data?.quota?.used_bytes ?? tree.data?.total_size ?? files.reduce((sum, item) => sum + Number(item.file_size || item.size || 0), 0))
  const maxFileBytes = Number(tree.data?.quota?.file_bytes || 2 * 1024 * 1024)
  const maxRepositoryBytes = Number(tree.data?.quota?.total_bytes || 32 * 1024 * 1024)
  const currentEntry = selected == null ? null : entryMap.get(selected) || null
  const content = draft ?? file.data?.content ?? ''
  const relativePath = String(file.data?.relative_path || currentEntry?.relative_path || currentEntry?.path || file.data?.filename || currentEntry?.name || '')
  const name = String((selected ? relativePath : '') || file.data?.filename || currentEntry?.name || '尚未打开文件')
  const ext = name.includes('.') ? name.split('.').pop()?.toUpperCase() : '—'
  const symbols = useMemo(() => outlineSymbols(content, name), [content, name])
  const currentIndexJob = indexStatus.data?.job || activeIndex.data?.job || null

  useEffect(() => {
    const activeId = Number(activeIndex.data?.job?.id || 0)
    if (!indexJobId && activeId && indexJobRunning(activeIndex.data?.job)) setIndexJobId(activeId)
  }, [activeIndex.data?.job, indexJobId])
  useEffect(() => {
    if (!indexJobId) return
    try {window.localStorage.setItem(ACTIVE_INDEX_STORAGE_KEY, String(indexJobId))} catch { /* 当前标签页仍可继续轮询 */ }
  }, [indexJobId])
  useEffect(() => {
    const job = indexStatus.data?.job
    const jobId = Number(job?.id || indexJobId || 0)
    if (!job || !jobId || indexJobRunning(job) || handledIndexTerminal.current === jobId) return
    handledIndexTerminal.current = jobId
    try {window.localStorage.removeItem(ACTIVE_INDEX_STORAGE_KEY)} catch { /* 忽略本地存储不可用 */ }
    const status = String(job.status || '').toLowerCase()
    if (status === 'success' || status === 'completed') setNotice({title: '结构化整理完成', message: `${Number(job.total_chunks || 0)} 个函数片段 · ${Number(job.total_classes || 0)} 个类`})
    else if (status === 'failed') setNotice({title: '结构化整理失败', message: String(job.error_message || '请稍后重试。'), error: true})
    else if (status === 'canceled') setNotice({title: '结构化整理已取消', message: String(job.error_message || '任务已停止。')})
    void queryClient.invalidateQueries({queryKey: ['repository', 'index', 'active']}).finally(() => setIndexJobId(null))
  }, [indexJobId, indexStatus.data?.job, queryClient])
  useEffect(() => {
    if (!indexJobId || !indexStatus.isError) return
    try {window.localStorage.removeItem(ACTIVE_INDEX_STORAGE_KEY)} catch { /* 忽略本地存储不可用 */ }
    setNotice({title: '无法读取整理进度', message: errorMessage(indexStatus.error), error: true})
    setIndexJobId(null)
  }, [indexJobId, indexStatus.error, indexStatus.isError])

  const refreshTree = async () => {await queryClient.invalidateQueries({queryKey: ['repository']})}
  const save = useMutation({
    mutationFn: (snapshot: SaveSnapshot) => apiFetch<SaveResponse>('/api/repository/file', {method: 'POST', body: JSON.stringify({file_id: snapshot.id, content: snapshot.content, expected_structure_version: tree.data?.structure_version, expected_file_version: snapshot.version})}),
  })
  const createEntry = useMutation({
    mutationFn: async () => {
      if (!inlineCreate) throw new Error('没有正在创建的项目')
      if (!await persistBeforeTransition()) throw new Error('当前编辑文件未能自动保存，已停止创建')
      const payload = {parent_id: inlineCreate.parentId, name: inlineCreate.value.trim(), expected_structure_version: tree.data?.structure_version}
      if (inlineCreate.kind === 'directory') return apiFetch<ApiEnvelope>('/api/repository/directory', {method: 'POST', body: JSON.stringify(payload)})
      return apiFetch<ApiEnvelope & {file_id?: number; entry_id?: number}>('/api/repository/file', {method: 'POST', body: JSON.stringify({...payload, content: ''})})
    },
    onMutate: () => setInlineCreate((value) => value ? {...value, saving: true, error: ''} : value),
    onSuccess: async (data) => {
      const created = inlineCreate
      setInlineCreate(null)
      if (created?.parentId) setExpanded((items) => items.includes(created.parentId!) ? items : [...items, created.parentId!])
      setNotice({title: created?.kind === 'directory' ? '目录已创建' : '文件已创建', message: created?.value.trim() || ''})
      await refreshTree()
      const id = Number(('file_id' in data && data.file_id) || ('entry_id' in data && data.entry_id) || 0)
      if (created?.kind === 'file' && id) setSelected(id)
      if (created?.kind === 'directory' && id) setFocusedDirectory(id)
    },
    onError: (error) => setInlineCreate((value) => value ? {...value, saving: false, error: errorMessage(error)} : value),
  })
  const moveEntry = useMutation({
    mutationFn: async (direct?: {entry: Entry; destinationId: number | null}) => {
      const entry = direct?.entry || actionEntry
      if (!entry) throw new Error('没有选中项目')
      if (!await persistBeforeTransition()) throw new Error('当前编辑文件未能自动保存，已停止移动')
      const destinationId = direct ? direct.destinationId : destination ? Number(destination) : null
      return apiFetch<ApiEnvelope>(`/api/repository/entry/${Number(entry.id)}/move`, {method: 'POST', body: JSON.stringify({destination_parent_id: destinationId, new_name: direct ? String(entry.name || '') : entryName, expected_structure_version: tree.data?.structure_version, conflict_policy: direct ? 'error' : mergeDirectories ? 'merge' : 'error'})})
    },
    onSuccess: async (_data, direct) => {setDialog(null); const moved = direct?.entry || actionEntry; const target = direct?.destinationId ?? (destination ? Number(destination) : null); setNotice({title: !direct && mergeDirectories ? '目录已合并' : '位置已更新', message: `${String(moved?.name || entryName)} 已移动到 ${target ? `repository / ${String(entryMap.get(target)?.relative_path || entryMap.get(target)?.name || '')}` : 'repository /'}`}); await refreshTree()},
  })
  const previewDelete = useMutation({
    mutationFn: (entry: Entry) => apiFetch<DeletePreview>(`/api/repository/entry/${Number(entry.id)}/delete-preview`, {method: 'POST'}),
    onSuccess: (preview) => {setDeletePreview(preview); setDialog('delete')},
  })
  const deleteEntry = useMutation({
    mutationFn: () => {
      if (!actionEntry || !deletePreview?.confirmation_token) throw new Error('删除确认信息无效')
      return apiFetch<ApiEnvelope>(`/api/repository/entry/${Number(actionEntry.id)}`, {method: 'DELETE', body: JSON.stringify({confirmation_token: deletePreview.confirmation_token})})
    },
    onSuccess: async () => {if (selected === Number(actionEntry?.id) || (String(actionEntry?.kind) === 'directory' && relativePath.startsWith(`${String(actionEntry?.relative_path || actionEntry?.name || '')}/`))) {setSelected(null); draftRef.current = null; setDraft(null)}; setDialog(null); setDeletePreview(null); setNotice({title: '已删除', message: String(actionEntry?.relative_path || actionEntry?.name || '')}); await refreshTree()},
  })
  const applyUploadPayload = (payload: UploadPreview, items: UploadItem[]) => {
    const serverEntries = payload.entries || [
      ...(payload.directories || []).map((item) => ({kind: 'directory', ...item})),
      ...(payload.files || []).map((item) => ({kind: 'file', ...item})),
    ]
    serverEntries.forEach((serverItem) => {
      const kind = String(serverItem.kind || (serverItem.token ? 'file' : 'directory'))
      const item = items.find((candidate) => candidate.kind === kind && candidate.relativePath === String(serverItem.relative_path || ''))
      if (!item) return
      item.token = String(serverItem.token || item.token || '')
      item.receivedBytes = Math.max(item.receivedBytes, Number(serverItem.received_size || 0))
      item.serverStatus = String(serverItem.status || item.serverStatus)
      item.serverMessage = String(serverItem.message || '')
      item.pathError = String(serverItem.path_error || item.pathError || '')
      item.candidateEncoding = String(serverItem.candidate_encoding || '')
      item.encodingPreview = String(serverItem.encoding_preview || '')
      item.encodingPreviewTruncated = Boolean(serverItem.encoding_preview_truncated)
      item.encodingHasDisallowedControl = Boolean(serverItem.encoding_preview_has_disallowed_control)
      item.encoding = serverItem.source_encoding ? `${String(serverItem.source_encoding).toUpperCase()}${serverItem.newline_normalized ? ' → UTF-8 / LF' : ''}` : item.candidateEncoding ? `候选 ${item.candidateEncoding}` : item.encoding
      if (item.serverStatus === 'invalid') {item.error = item.serverMessage || item.pathError || '服务端校验未通过'; item.resolution = item.kind === 'directory' ? 'exclude' : 'rename'}
      if (item.serverStatus === 'blocking_conflict') {
        item.resolution = item.kind === 'directory' ? 'exclude' : 'rename'
        if (item.kind === 'file' && !item.renameTarget) item.renameTarget = suggestedRenamePath(item.relativePath)
      }
    })
    if (payload.session_id) setUploadSessionId(payload.session_id)
    setUploadStructureVersion(payload.structure_version ?? payload.base_structure_version)
    if (payload.status === 'preview_ready' || payload.ready) setUploadPhase('ready')
    else if (payload.status === 'needs_confirmation') setUploadPhase('needs_encoding')
    else if (payload.status === 'receiving') setUploadPhase('uploading')
    setUploadItems([...items])
  }
  const upload = useMutation({
    mutationFn: async () => {
      if (!uploadItems.length) throw new Error('请选择文件或目录')
      if (uploadItems.some((item) => item.error && !item.serverStatus)) throw new Error('请先修正或排除无效路径')
      const sequence = uploadSequenceRef.current
      const items = uploadItems.map((item) => ({...item}))
      let sessionId = uploadSessionId
      const sessionUrl = (suffix = '') => `/api/repository/upload/session/${encodeURIComponent(sessionId)}${suffix}`
      const ensureCurrent = () => {if (sequence !== uploadSequenceRef.current) throw new Error('上传已取消')}
      const refreshSession = async () => {
        const payload = await apiFetch<UploadPreview>(sessionUrl())
        ensureCurrent(); applyUploadPayload(payload, items)
        return payload
      }
      const uploadChunk = async (item: UploadItem, offset: number, retries = 0): Promise<void> => {
        if (item.kind !== 'file' || offset >= item.file.size) {item.receivedBytes = item.kind === 'file' ? item.file.size : 0; return}
        ensureCurrent()
        const chunk = item.file.slice(offset, Math.min(offset + 1024 * 1024, item.file.size))
        try {
          const result = await apiFetch<ApiEnvelope & {offset?: number}>(sessionUrl(`/file/${encodeURIComponent(item.token || '')}/chunk`), {method: 'PUT', headers: {'Content-Type': 'application/octet-stream', 'Upload-Offset': String(offset), 'Upload-Length': String(item.file.size), 'Upload-Chunk-SHA256': await digestSha256(chunk)}, body: chunk})
          const nextOffset = Number(result.offset)
          if (!Number.isFinite(nextOffset) || nextOffset <= offset) throw new Error('服务端没有推进上传 offset')
          item.receivedBytes = nextOffset
          setUploadItems([...items])
          await uploadChunk(item, nextOffset, 0)
        } catch (error) {
          const expectedOffset = error instanceof ApiError ? Number((error.payload as JsonRecord | null)?.expected_offset) : Number.NaN
          if (error instanceof ApiError && error.status === 409 && Number.isFinite(expectedOffset) && expectedOffset >= 0 && retries < 3) return uploadChunk(item, expectedOffset, retries + 1)
          if (retries >= 2) throw error
          await refreshSession()
          await uploadChunk(item, item.receivedBytes, retries + 1)
        }
      }
      const finalize = async (encodings: JsonRecord) => {
        setUploadPhase('finalizing')
        const preview = await apiFetch<UploadPreview>(sessionUrl('/finalize'), {method: 'POST', body: JSON.stringify({encodings})})
        ensureCurrent(); applyUploadPayload(preview, items)
        return preview
      }

      if (uploadPhase === 'needs_encoding') {
        const encodings: JsonRecord = {}
        items.forEach((item) => {if (item.serverStatus === 'encoding_confirmation_required' && item.encodingConfirmed) encodings[item.token || item.relativePath] = item.candidateEncoding})
        await finalize(encodings)
        return {committed: false, count: 0}
      }
      if (uploadPhase === 'ready') {
        if (!await persistBeforeTransition()) throw new Error('当前编辑文件未能自动保存，已停止写入上传内容')
        setUploadPhase('committing')
        const resolutions: JsonRecord = {}
        const renameTargets: JsonRecord = {}
        items.forEach((item) => {
          if (['conflict', 'blocking_conflict', 'invalid'].includes(item.serverStatus)) {
            resolutions[item.relativePath] = item.resolution
            if (item.resolution === 'rename') renameTargets[item.relativePath] = validateUploadPath(item.renameTarget).path
          }
        })
        const result = await apiFetch<UploadPreview>(sessionUrl('/commit'), {method: 'POST', body: JSON.stringify({expected_structure_version: uploadStructureVersion, resolutions, rename_targets: renameTargets})})
        ensureCurrent()
        return {committed: true, count: Number(result.committed_count ?? result.committed?.length ?? items.filter((item) => item.kind === 'file' && item.resolution !== 'skip' && item.resolution !== 'exclude').length)}
      }

      setUploadError('')
      if (!sessionId) {
        if (items.some((item) => item.error)) throw new Error('上传清单中有重复或无效路径，请先排除')
        setUploadPhase('preparing')
        await Promise.all(items.map(async (item) => {if (item.kind === 'file' && !item.rawSha256) item.rawSha256 = await digestSha256(item.file)}))
        ensureCurrent(); setUploadItems([...items])
        const parentId = actionEntry && String(actionEntry.kind) === 'directory' ? Number(actionEntry.id) : Number(actionEntry?.parent_id || 0) || null
        const created = await apiFetch<UploadPreview>('/api/repository/upload/session', {method: 'POST', body: JSON.stringify({parent_id: parentId, expected_structure_version: tree.data?.structure_version, entries: items.map((item) => item.kind === 'directory' ? {kind: 'directory', relative_path: item.relativePath} : {kind: 'file', relative_path: item.relativePath, size: item.file.size, sha256: item.rawSha256})})})
        ensureCurrent()
        sessionId = String(created.session_id || '')
        if (!sessionId) throw new Error('上传会话创建失败')
        setUploadSessionId(sessionId); applyUploadPayload(created, items)
      } else {
        const resumed = await refreshSession()
        if (resumed.status === 'preview_ready') return {committed: false, count: 0}
        if (resumed.status === 'needs_confirmation') return {committed: false, count: 0}
      }
      setUploadPhase('uploading')
      for (const item of items) if (item.kind === 'file' && item.token) await uploadChunk(item, item.receivedBytes)
      await finalize({})
      return {committed: false, count: 0}
    },
    onSuccess: async (result) => {
      if (!result.committed) return
      setDialog(null); setUploadItems([]); setUploadSessionId(''); setUploadPhase('idle')
      setNotice({title: '上传完成', message: `${result.count} 个文件已加入仓库`})
      await refreshTree()
    },
    onError: (error) => {setUploadPhase('error'); setUploadError(errorMessage(error))},
  })
  const buildIndex = useMutation({
    mutationFn: () => apiFetch<IndexResponse>('/api/repository/index/build', {method: 'POST'}),
    onSuccess: async (data) => {if (data.job_id) {handledIndexTerminal.current = null; setIndexJobId(Number(data.job_id))} setNotice({title: '结构化整理已启动', message: data.message || '正在建立代码索引'}); await queryClient.invalidateQueries({queryKey: ['repository', 'index']})},
  })
  const cancelIndex = useMutation({
    mutationFn: () => {const id = Number(currentIndexJob?.id || indexJobId); return apiFetch<ApiEnvelope>(`/api/repository/index/${id}/cancel`, {method: 'POST'})},
    onSuccess: async () => {setNotice({title: '整理已取消', message: '仓库文件没有被修改'}); await queryClient.invalidateQueries({queryKey: ['repository', 'index']})},
  })
  const semanticSearch = useMutation({mutationFn: () => apiFetch<SearchResponse>('/api/repository/index/search', {method: 'POST', body: JSON.stringify({query: semanticQuery})})})

  async function saveCurrentFile(options: {silent?: boolean; drain?: boolean} = {}): Promise<boolean> {
    if (saveConflict) return false
    if (draftRef.current == null || selected == null || !file.data) return true
    if (saveInFlightRef.current) {
      const succeeded = await saveInFlightRef.current
      if (succeeded && options.drain && draftRef.current != null) return saveCurrentFile(options)
      return succeeded
    }
    const snapshot: SaveSnapshot = {id: selected, content: draftRef.current, version: file.data.file_version, relativePath}
    if (new TextEncoder().encode(snapshot.content).length > maxFileBytes) {
      setNotice({title: '文件无法保存', message: `规范化 UTF-8 内容超过单文件 ${formatBytes(maxFileBytes)} 限制`, error: true})
      return false
    }
    const operation = (async () => {
      try {
        const result = await save.mutateAsync(snapshot)
        const savedEntry = result.entry || {}
        const savedVersion = Number(savedEntry.file_version ?? result.file_version ?? result.version ?? snapshot.version)
        queryClient.setQueryData<FileResponse>(['repository', 'file', snapshot.id], (previous) => ({...(previous || {success: true}), ...savedEntry, content: snapshot.content, file_version: Number.isFinite(savedVersion) ? savedVersion : previous?.file_version}))
        if (selected === snapshot.id && draftRef.current === snapshot.content) {draftRef.current = null; setDraft(null)}
        if (!options.silent) setNotice({title: '文件已保存', message: snapshot.relativePath})
        await queryClient.invalidateQueries({queryKey: ['repository', 'tree']})
        return true
      } catch (error) {
        if (error instanceof ApiError && (error.status === 409 || error.status === 404 || error.payload?.code === 'not_found')) {
          setConflictReloadConfirmed(false)
          setSaveConflict({snapshot: {...snapshot, content: draftRef.current ?? snapshot.content}, message: error.message})
        } else {
          setNotice({title: '保存失败', message: errorMessage(error), error: true})
        }
        return false
      }
    })()
    saveInFlightRef.current = operation
    let succeeded = false
    try {
      succeeded = await operation
    } finally {
      if (saveInFlightRef.current === operation) saveInFlightRef.current = null
    }
    if (succeeded && options.drain && selected === snapshot.id && draftRef.current != null) return saveCurrentFile(options)
    return succeeded
  }
  saveCurrentFileRef.current = saveCurrentFile

  function persistBeforeTransition() {
    if (saveConflict) return Promise.resolve(false)
    return saveCurrentFile({silent: true, drain: true})
  }

  async function openFile(entryId: number, line?: number) {
    const entry = entryMap.get(entryId)
    if (!entry || String(entry.kind || entry.type) === 'directory') return false
    if (selected === entryId) {if (line) jumpToLine(line); setMobileFiles(false); return true}
    const sequence = ++openSequenceRef.current
    if (!await persistBeforeTransition() || sequence !== openSequenceRef.current) return false
    try {
      const payload = await queryClient.fetchQuery({queryKey: ['repository', 'file', entryId], queryFn: () => apiFetch<FileResponse>(`/api/repository/file/${entryId}`), staleTime: 0})
      if (sequence !== openSequenceRef.current) return false
      queryClient.setQueryData(['repository', 'file', entryId], payload)
      draftRef.current = null; setDraft(null); setSelected(entryId); setFocusedDirectory(Number(entry.parent_id || 0) || null); setMobileFiles(false)
      if (line) window.requestAnimationFrame(() => window.requestAnimationFrame(() => jumpToLine(line)))
      return true
    } catch (error) {
      setNotice({title: '打开文件失败', message: errorMessage(error), error: true})
      return false
    }
  }

  const backupConflict = async (mode: 'copy' | 'download') => {
    if (!saveConflict) return
    if (mode === 'copy') {
      try {
        await copyText(saveConflict.snapshot.content)
        setNotice({title: '本地内容已复制', message: saveConflict.snapshot.relativePath})
      } catch (error) {
        setNotice({title: '复制本地内容失败', message: errorMessage(error), error: true})
      }
      return
    }
    const link = document.createElement('a')
    const url = URL.createObjectURL(new Blob([saveConflict.snapshot.content], {type: 'text/plain;charset=utf-8'}))
    link.href = url; link.download = `${saveConflict.snapshot.relativePath.split('/').pop() || 'repository-file'}.local-conflict`; link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  const reloadAfterConflict = async () => {
    if (!saveConflict || !conflictReloadConfirmed) return
    try {
      const payload = await apiFetch<FileResponse>(`/api/repository/file/${saveConflict.snapshot.id}`)
      queryClient.setQueryData(['repository', 'file', saveConflict.snapshot.id], payload)
      draftRef.current = null; setDraft(null); setSaveConflict(null); setConflictReloadConfirmed(false)
      setNotice({title: '已重新载入', message: saveConflict.snapshot.relativePath})
      await refreshTree()
    } catch (error) {
      if (error instanceof ApiError && (error.status === 404 || error.payload?.code === 'not_found')) {
        setSelected(null); draftRef.current = null; setDraft(null); setSaveConflict(null)
        setNotice({title: '文件已被删除', message: '本地修改已丢弃，编辑器已关闭。', error: true})
      } else setNotice({title: '重新载入失败', message: errorMessage(error), error: true})
    }
  }

  const actionDirectoryId = () => focusedDirectory || Number(currentEntry?.parent_id || 0) || null
  const externalDirectoryAtTarget = (target: EventTarget | null) => {
    const row = target instanceof Element ? target.closest<HTMLElement>('.repository-tree-row[data-entry-kind="directory"]') : null
    const rowId = Number(row?.dataset.entryId || 0)
    return rowId || actionDirectoryId()
  }
  const isExternalFileDrag = (event: React.DragEvent) => Array.from(event.dataTransfer.types || []).includes('Files') && !Array.from(event.dataTransfer.types || []).includes('application/x-numoj-entry-id')
  const cancelUploadSession = async (clearItems = true) => {
    uploadSequenceRef.current += 1
    const sessionId = uploadSessionId
    setUploadSessionId(''); setUploadStructureVersion(undefined); setUploadPhase('idle'); setUploadError('')
    if (clearItems) setUploadItems([])
    if (sessionId) {
      try {await apiFetch<ApiEnvelope>(`/api/repository/upload/session/${encodeURIComponent(sessionId)}`, {method: 'DELETE'})} catch { /* 会话可能已过期或提交，关闭仍然继续。 */ }
    }
  }
  const addUploadDescriptors = async (descriptors: RepositoryUploadDescriptor[], append = true) => {
    await cancelUploadSession(false)
    const combined = append ? [...uploadItems.map((item): RepositoryUploadDescriptor => item.kind === 'file' ? {kind: 'file', relativePath: item.relativePath, file: item.file} : {kind: 'directory', relativePath: item.relativePath}), ...descriptors] : descriptors
    setUploadItems(uploadItemsFromDescriptors(combined)); setDialog('upload')
  }
  const removeUploadItem = async (key: string) => {
    await cancelUploadSession(false)
    const remaining = uploadItems.filter((item) => item.key !== key).map((item): RepositoryUploadDescriptor => item.kind === 'file' ? {kind: 'file', relativePath: item.relativePath, file: item.file} : {kind: 'directory', relativePath: item.relativePath})
    setUploadItems(uploadItemsFromDescriptors(remaining))
  }
  const canDropEntry = (source: Entry, destinationId: number | null) => {
    if (destinationId === Number(source.parent_id || 0) || (!destinationId && !source.parent_id)) return false
    if (destinationId === Number(source.id)) return false
    const destinationEntry = destinationId ? entryMap.get(destinationId) : null
    return !(String(source.kind || source.type) === 'directory' && destinationEntry && String(destinationEntry.relative_path || '').startsWith(`${String(source.relative_path || '')}/`))
  }
  const openCreate = (kind: 'file' | 'directory') => {
    const parentId = actionDirectoryId()
    setFilter('')
    if (parentId) setExpanded((items) => items.includes(parentId) ? items : [...items, parentId])
    setInlineCreate({kind, parentId, value: '', error: '', saving: false})
  }
  const openManage = (entry: Entry, mode: 'rename' | 'move' = 'move') => {setActionEntry(entry); setManageMode(mode); setMergeDirectories(false); setEntryName(String(entry.name || '')); setDestination(entry.parent_id == null ? '' : String(entry.parent_id)); setDialog('manage')}
  const showContextMenu = (entry: Entry, anchor: HTMLElement) => {
    const rect = anchor.getBoundingClientRect()
    setContextMenu({entry, left: Math.max(8, Math.min(window.innerWidth - 158, rect.right - 150)), top: Math.max(8, Math.min(window.innerHeight - 121, rect.bottom + 4))})
  }
  const openDelete = (entry: Entry) => {setActionEntry(entry); setDeletePreview(null); setDialog('delete'); previewDelete.mutate(entry)}
  const jumpToLine = (line: number) => {
    const editor = editorRef.current as MonacoEditorInstance & {setPosition?: (position: {lineNumber: number; column: number}) => void; revealLineInCenter?: (line: number) => void}
    if (!editor) return
    editor.setPosition?.({lineNumber: line, column: 1})
    editor.revealLineInCenter?.(line)
    editor.focus()
  }
  useEffect(() => {draftRef.current = draft}, [draft])
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {event.preventDefault(); void saveCurrentFileRef.current()}
    }
    const beforeUnload = (event: BeforeUnloadEvent) => {if (draftRef.current != null) {event.preventDefault(); event.returnValue = ''}}
    const linkClick = (event: MouseEvent) => {
      if (draftRef.current == null) return
      const guardedEvent = event as MouseEvent & {numojUnsavedPromptShown?: boolean}
      if (guardedEvent.numojUnsavedPromptShown) return
      const link = event.target instanceof Element ? event.target.closest<HTMLAnchorElement>('a[href]') : null
      if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self') || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return
      guardedEvent.numojUnsavedPromptShown = true
      if (!window.confirm('当前文件有未保存的修改，确定离开吗？')) {event.preventDefault(); event.stopPropagation()}
    }
    document.addEventListener('keydown', keydown)
    document.addEventListener('click', linkClick, true)
    window.addEventListener('beforeunload', beforeUnload)
    return () => {document.removeEventListener('keydown', keydown); document.removeEventListener('click', linkClick, true); window.removeEventListener('beforeunload', beforeUnload)}
  })
  useEffect(() => {
    if (!inlineCreate || inlineCreate.saving) return
    const timer = window.requestAnimationFrame(() => inlineCreateRef.current?.focus())
    return () => window.cancelAnimationFrame(timer)
  }, [inlineCreate?.kind, inlineCreate?.parentId, inlineCreate?.saving])
  useEffect(() => {
    if (!contextMenu) return
    const close = (event: PointerEvent) => {if (!(event.target as Element | null)?.closest('.repository-context-menu')) setContextMenu(null)}
    const escape = (event: KeyboardEvent) => {if (event.key === 'Escape') setContextMenu(null)}
    document.addEventListener('pointerdown', close)
    window.addEventListener('resize', () => setContextMenu(null), {once: true})
    document.addEventListener('keydown', escape)
    return () => {document.removeEventListener('pointerdown', close); document.removeEventListener('keydown', escape)}
  }, [contextMenu])
  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(null), 4200)
    return () => window.clearTimeout(timer)
  }, [notice])
  useEffect(() => {
    if (dialog !== 'manage') return
    const timer = window.setTimeout(() => {
      if (manageMode === 'rename') {
        manageNameRef.current?.focus()
        manageNameRef.current?.select()
      } else {
        manageDestinationRef.current?.focus()
      }
    }, 0)
    return () => window.clearTimeout(timer)
  }, [dialog, manageMode])
  const submitMove = (event: FormEvent) => {event.preventDefault(); moveEntry.mutate()}
  const submitSearch = (event: FormEvent) => {event.preventDefault(); if (semanticQuery.trim()) semanticSearch.mutate()}

  if (context.isPending || tree.isPending) return <LoadingState label="正在挂载代码仓库" />
  const repositoryError = context.error || tree.error

  const indexStage = String(currentIndexJob?.stage || currentIndexJob?.status || '')
  const indexPercent = Number(currentIndexJob?.percentage || currentIndexJob?.progress || 0)
  const indexRunning = Boolean(currentIndexJob && !['success', 'failed', 'canceled', 'completed'].includes(String(currentIndexJob.status || '').toLowerCase()))
  const operationError = save.error || createEntry.error || moveEntry.error || previewDelete.error || deleteEntry.error || upload.error || buildIndex.error || cancelIndex.error
  const uploadFileCount = uploadItems.filter((item) => item.kind === 'file').length
  const uploadDirectoryCount = uploadItems.length - uploadFileCount
  const uploadTotalBytes = uploadItems.reduce((sum, item) => sum + (item.kind === 'file' ? item.file.size : 0), 0)
  const uploadReceivedBytes = uploadItems.reduce((sum, item) => sum + item.receivedBytes, 0)
  const uploadCanProceed = (() => {
    if (upload.isPending || !uploadItems.length) return false
    if (uploadPhase === 'idle' || uploadPhase === 'error') return uploadItems.every((item) => !item.error) || Boolean(uploadSessionId)
    if (uploadPhase === 'needs_encoding') return uploadItems.every((item) => item.serverStatus !== 'encoding_confirmation_required' || (item.encodingConfirmed && !item.encodingHasDisallowedControl))
    if (uploadPhase !== 'ready') return false
    return uploadItems.some((item) => item.resolution !== 'skip' && item.resolution !== 'exclude') && uploadItems.every((item) => !['conflict', 'blocking_conflict', 'invalid'].includes(item.serverStatus) || item.resolution !== 'rename' || validateUploadPath(item.renameTarget).valid)
  })()
  const uploadSummary = uploadPhase === 'preparing' ? '正在计算 SHA-256 校验值…' : uploadPhase === 'uploading' ? `正在上传 ${formatBytes(uploadReceivedBytes)} / ${formatBytes(uploadTotalBytes)}` : uploadPhase === 'finalizing' ? '正在识别编码并检查冲突…' : uploadPhase === 'needs_encoding' ? '请确认标记文件的候选编码' : uploadPhase === 'ready' ? `${uploadFileCount} 个文件可写入${uploadDirectoryCount ? ` · ${uploadDirectoryCount} 个目录` : ''}` : uploadPhase === 'committing' ? '正在写入仓库…' : uploadPhase === 'error' ? uploadError || '上传检查失败' : uploadItems.length ? `${uploadFileCount} 个文件待检查${uploadDirectoryCount ? ` · ${uploadDirectoryCount} 个目录` : ''}` : '尚未选择文件'
  const uploadButtonLabel: Record<UploadPhase, string> = {idle: '检查文件', preparing: '正在计算校验值…', uploading: '正在分块上传…', finalizing: '正在检查…', needs_encoding: '确认编码并继续', ready: '写入仓库', committing: '正在写入…', error: '重试检查'}
  const uploadState = (item: UploadItem) => {
    if (item.serverStatus === 'encoding_confirmation_required') return <><label className="repository-encoding-confirm"><input type="checkbox" checked={item.encodingConfirmed} disabled={item.encodingHasDisallowedControl} onChange={(event) => setUploadItems((items) => items.map((candidate) => candidate.key === item.key ? {...candidate, encodingConfirmed: event.target.checked} : candidate))} />按 {item.candidateEncoding || '候选编码'} 解码（已查看预览）</label></>
    if (item.kind === 'directory' && item.serverStatus === 'merge') return <span className="conflict">合并目录</span>
    if (item.kind === 'directory' && item.serverStatus === 'new') return <span>新建目录</span>
    if (['conflict', 'blocking_conflict', 'invalid'].includes(item.serverStatus)) {
      const blocking = item.serverStatus !== 'conflict'
      return <><select aria-label={blocking ? '路径冲突处理方式' : '同名文件处理方式'} value={item.resolution} onChange={(event) => setUploadItems((items) => items.map((candidate) => candidate.key === item.key ? {...candidate, resolution: event.target.value as UploadItem['resolution'], renameTarget: event.target.value === 'rename' && !candidate.renameTarget ? suggestedRenamePath(candidate.relativePath) : candidate.renameTarget} : candidate))}>{!blocking ? <option value="overwrite">覆盖现有</option> : null}<option value={blocking && item.kind === 'directory' ? 'exclude' : 'skip'}>{blocking ? '排除' : '跳过'}</option>{item.kind === 'file' ? <option value="rename">另存为</option> : null}</select>{item.resolution === 'rename' ? <input type="text" maxLength={1024} value={item.renameTarget} aria-label="另存为相对路径" onChange={(event) => setUploadItems((items) => items.map((candidate) => candidate.key === item.key ? {...candidate, renameTarget: event.target.value} : candidate))} /> : null}</>
    }
    if (item.error) return <><span className="error">{item.error}</span><input type="text" maxLength={1024} value={item.relativePath} aria-label="修正上传相对路径" onChange={(event) => {const checked = validateUploadPath(event.target.value); setUploadItems((items) => items.map((candidate) => candidate.key === item.key ? {...candidate, relativePath: checked.path, pathError: checked.message, error: checked.message} : candidate))}} /></>
    if (uploadPhase === 'uploading' || item.serverStatus === 'receiving') return <span className="progress">{item.kind === 'file' && item.file.size ? Math.floor(item.receivedBytes / item.file.size * 100) : 100}%</span>
    if (item.serverStatus === 'new') return <span>新增</span>
    if (item.serverStatus === 'uploaded') return <span>已校验</span>
    return <span>待检查</span>
  }
  const inlineCreateRow = (depth: number) => inlineCreate ? <div className={`repository-tree-row repository-tree-inline${inlineCreate.error ? ' is-invalid' : ''}`} style={{'--tree-depth': depth, '--tree-indent': `${Math.min(depth, 8) * 13}px`} as React.CSSProperties} role="treeitem" aria-level={depth + 1}>
    <span className="repository-tree-toggle is-placeholder" />
    <span className={`repository-tree-glyph${inlineCreate.kind === 'directory' ? '' : ' file'}`}><Icon name={inlineCreate.kind === 'directory' ? 'folder' : 'file'} /></span>
    <span className="repository-tree-inline-field"><input ref={inlineCreateRef} type="text" maxLength={255} autoComplete="off" aria-label={inlineCreate.kind === 'directory' ? '新目录名称' : '新文件名称'} aria-invalid={Boolean(inlineCreate.error)} placeholder={inlineCreate.kind === 'directory' ? '新建目录' : 'untitled.txt'} value={inlineCreate.value} disabled={inlineCreate.saving} onChange={(event) => setInlineCreate((value) => value ? {...value, value: event.target.value, error: ''} : value)} onKeyDown={(event) => {if (event.key === 'Escape') {event.preventDefault(); setInlineCreate(null)} else if (event.key === 'Enter') {event.preventDefault(); if (inlineCreate.value.trim()) createEntry.mutate()}}} />{inlineCreate.error ? <small role="alert">{inlineCreate.error}</small> : <small>Enter 创建 · Esc 取消</small>}</span>
    <span className="repository-tree-inline-status">{inlineCreate.saving ? '…' : ''}</span>
  </div> : null

  return <section className={`repository-workbench${mobileFiles ? ' is-files-open' : ''}${currentIndexJob ? ' has-index-progress' : ''}`} aria-label="个人代码仓库">
    <svg className="repository-symbols" aria-hidden="true"><symbol id="repo-icon-folder" viewBox="0 0 24 24"><path d="M3 7.5V6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" /></symbol><symbol id="repo-icon-folder-plus" viewBox="0 0 24 24"><path d="M3 7.5V6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" /><path d="M12 10v6m-3-3h6" /></symbol><symbol id="repo-icon-file-plus" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6M12 12v6m-3-3h6" /></symbol><symbol id="repo-icon-file" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6" /></symbol><symbol id="repo-icon-upload" viewBox="0 0 24 24"><path d="M12 16V4m-5 5 5-5 5 5M5 20h14" /></symbol><symbol id="repo-icon-chevron" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6" /></symbol><symbol id="repo-icon-more" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1" /><circle cx="12" cy="12" r="1" /><circle cx="19" cy="12" r="1" /></symbol><symbol id="repo-icon-save" viewBox="0 0 24 24"><path d="M5 3h12l2 2v16H5zM8 3v6h8V3m-1 14H9" /></symbol><symbol id="repo-icon-tree" viewBox="0 0 24 24"><path d="M6 4v12m0-7h6m-6 7h6M12 6h8v6h-8zM12 14h8v6h-8z" /></symbol><symbol id="repo-icon-panel" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4v16" /></symbol><symbol id="repo-icon-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></symbol><symbol id="repo-icon-close" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18" /></symbol><symbol id="repo-icon-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3m-8 0 1 14h8l1-14M10 11v6m4-6v6" /></symbol><symbol id="repo-icon-move" viewBox="0 0 24 24"><path d="M12 2v20M2 12h20m-4-4 4 4-4 4M8 6l4-4 4 4M6 8l-4 4 4 4m2 2 4 4 4-4" /></symbol><symbol id="repo-icon-edit" viewBox="0 0 24 24"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z" /></symbol><symbol id="repo-icon-check" viewBox="0 0 24 24"><path d="m5 12 4 4L19 6" /></symbol></svg>
    <header className="repository-header"><button className="repository-mobile-files" type="button" aria-expanded={mobileFiles} onClick={() => setMobileFiles((value) => !value)}><Icon name="panel" /><span>文件</span></button><div className="repository-heading"><p>CODE REPOSITORY · PERSONAL</p><div><h1>代码仓库</h1><span>{repositoryError ? '正在读取仓库…' : `${files.length} FILES · ${directories.length} DIRS · ${formatBytes(usedBytes)}`}</span></div></div><div className="repository-header-actions"><button className="repository-button repository-button-dark" type="button" disabled={buildIndex.isPending || indexRunning} onClick={() => buildIndex.mutate()}><Icon name="tree" /><span>{indexRunning ? '正在整理' : '结构化整理'}</span></button></div></header>
    <div className={`repository-index-progress${currentIndexJob ? ` ${indexRunning ? 'is-running' : 'is-terminal'}${String(currentIndexJob.status).toLowerCase() === 'failed' ? ' is-failed' : ''}` : ''}`} role="status" aria-live="polite" aria-hidden={currentIndexJob ? 'false' : 'true'}><div className="repository-index-copy"><span className="repository-index-dot" aria-hidden="true" /><strong>{currentIndexJob ? String(currentIndexJob.message || indexStage || '结构化整理') : '准备文件'}</strong><small>{currentIndexJob ? String(currentIndexJob.detail || currentIndexJob.filename || '正在建立代码索引') : '正在建立处理队列'}</small></div><div className="repository-progress-track" aria-hidden="true"><span style={{width: `${Math.max(0, Math.min(100, indexPercent))}%`}} /></div><span className="repository-index-detail">{currentIndexJob ? `${indexPercent}% · ${indexStage.toUpperCase()}` : '0% · INDEXING'}</span><button className="repository-index-cancel" type="button" hidden={!indexRunning} disabled={!indexRunning} onClick={() => cancelIndex.mutate()}>取消整理</button></div>
    <div className="repository-workspace">
      <div className="repository-drawer-backdrop" hidden={!mobileFiles} onClick={() => setMobileFiles(false)} />
      <aside className={`repository-files-pane${externalDragDepth ? ' is-external-dragover' : ''}`} aria-label="仓库文件" onDragEnter={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); setExternalDragDepth((value) => value + 1); setExternalDropTarget(externalDirectoryAtTarget(event.target))}} onDragOver={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; setExternalDropTarget(externalDirectoryAtTarget(event.target))}} onDragLeave={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); setExternalDragDepth((value) => Math.max(0, value - 1))}} onDrop={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); event.stopPropagation(); const targetId = externalDirectoryAtTarget(event.target); setExternalDragDepth(0); setExternalDropTarget(targetId); setActionEntry(targetId ? entryMap.get(targetId) || null : null); void extractDropDescriptors(event.dataTransfer).then((items) => addUploadDescriptors(items, false)).catch((error) => setNotice({title: '无法读取拖入内容', message: errorMessage(error), error: true}))}}><div className="repository-pane-head"><span className="repository-pane-copy"><span className="repository-pane-label">FILES</span><span className="repository-pane-count">{files.length} FILES</span></span><span className="repository-file-tools"><button className="repository-file-tool" type="button" aria-label="新建文件" onClick={() => openCreate('file')}><Icon name="file-plus" /></button><button className="repository-file-tool" type="button" aria-label="新建目录" onClick={() => openCreate('directory')}><Icon name="folder-plus" /></button><button className="repository-file-tool" type="button" aria-label="上传文件或文件夹" onClick={() => {setActionEntry(entryMap.get(actionDirectoryId() || 0) || currentEntry); setDialog('upload')}}><Icon name="upload" /></button></span></div><label className="repository-file-search"><Icon name="search" /><input type="search" placeholder="筛选文件与目录" value={filter} onChange={(event) => setFilter(event.target.value)} /></label><div className={`repository-tree${draggedEntryId ? ' is-internal-dragging' : ''}${treeDropTargetId === 'root' ? ' is-root-drop-target' : ''}`} role="tree" aria-label="代码仓库目录树" onDragOver={(event) => {if (!draggedEntryId || isExternalFileDrag(event)) return; const anyRow = (event.target as Element).closest<HTMLElement>('.repository-tree-row[data-entry-id]'); const directoryRow = (event.target as Element).closest<HTMLElement>('.repository-tree-row[data-entry-kind="directory"]'); const destinationId = directoryRow ? Number(directoryRow.dataset.entryId) : anyRow ? Number.NaN : null; const source = entryMap.get(draggedEntryId); if (!source || Number.isNaN(destinationId) || !canDropEntry(source, destinationId)) return; event.preventDefault(); event.dataTransfer.dropEffect = 'move'; setTreeDropTargetId(destinationId || 'root')}} onDrop={(event) => {if (!draggedEntryId || isExternalFileDrag(event)) return; const anyRow = (event.target as Element).closest<HTMLElement>('.repository-tree-row[data-entry-id]'); const directoryRow = (event.target as Element).closest<HTMLElement>('.repository-tree-row[data-entry-kind="directory"]'); const destinationId = directoryRow ? Number(directoryRow.dataset.entryId) : anyRow ? Number.NaN : null; const source = entryMap.get(draggedEntryId); setDraggedEntryId(null); setTreeDropTargetId(null); if (!source || Number.isNaN(destinationId) || !canDropEntry(source, destinationId)) return; event.preventDefault(); moveEntry.mutate({entry: source, destinationId})}} onDragEnd={() => {setDraggedEntryId(null); setTreeDropTargetId(null)}}>{repositoryError ? <div className="repository-tree-empty">仓库加载失败。<br />{repositoryError.message}</div> : <>{treeRows.map((row, index) => {
        if (row.type === 'inline') return <Fragment key={`inline-${row.depth}`}>{inlineCreateRow(row.depth)}</Fragment>
        const entry = row.entry
        const id = Number(entry.id || entry.entry_id || 0)
        const directory = String(entry.kind || entry.type) === 'directory'
        const hasChildren = entries.some((item) => Number(item.parent_id || 0) === id)
        const isExpanded = expanded.includes(id)
        const query = filter.trim().toLowerCase()
        const path = String(entry.relative_path || entry.path || entry.name || '')
        const directSearchHit = Boolean(query && path.toLowerCase().includes(query))
        const visibleName = directSearchHit ? path : String(entry.name || entry.filename || path || 'untitled')
        return <div className={`repository-tree-row${isExpanded ? ' is-expanded' : ''}${selected === id || focusedDirectory === id ? ' is-active' : ''}${directSearchHit ? ' is-search-hit' : ''}${draggedEntryId === id ? ' is-dragging' : ''}${treeDropTargetId === id ? ' is-drop-target' : ''}`} draggable style={{'--tree-depth': row.depth, '--tree-indent': `${Math.min(row.depth, 8) * 13}px`} as React.CSSProperties} data-entry-id={id} data-entry-kind={directory ? 'directory' : 'file'} role="treeitem" aria-level={row.depth + 1} aria-expanded={directory ? isExpanded : undefined} title={path} key={`${id}-${index}`} onDragStart={(event) => {setDraggedEntryId(id); event.dataTransfer.effectAllowed = 'move'; event.dataTransfer.setData('application/x-numoj-entry-id', String(id)); event.dataTransfer.setData('text/plain', path)}}><button className={`repository-tree-toggle${!directory || !hasChildren ? ' is-placeholder' : ''}`} type="button" tabIndex={!directory || !hasChildren ? -1 : 0} aria-label={isExpanded ? '折叠目录' : '展开目录'} onClick={() => setExpanded((items) => items.includes(id) ? items.filter((item) => item !== id) : [...items, id])}><Icon name="chevron" /></button><span className={`repository-tree-glyph${directory ? '' : ' file'}`}><Icon name={directory ? 'folder' : 'file'} /></span><button className="repository-tree-main" type="button" onDoubleClick={() => {if (directory) openCreate('file')}} onClick={() => {if (directory) {setFocusedDirectory(id); setExpanded((items) => items.includes(id) ? items.filter((item) => item !== id) : [...items, id])} else void openFile(id)}}><span className={`repository-tree-name${directSearchHit ? ' is-path' : ''}`}>{markedName(visibleName, directSearchHit ? query : '')}</span></button><button className="repository-tree-menu" type="button" aria-label={`${String(entry.name || '')} 的操作菜单`} onClick={(event) => {event.stopPropagation(); showContextMenu(entry, event.currentTarget)}}><Icon name="more" /></button></div>
      })}{!treeRows.length ? <div className="repository-tree-empty">{entries.length ? '没有匹配的文件或目录。' : <>仓库还是空的。<br />新建文件、目录，或拖入本地文件夹。</>}</div> : null}</>}</div><footer className="repository-files-foot"><span>PRIVATE WORKSPACE</span><span>{formatBytes(usedBytes)} / {formatBytes(maxRepositoryBytes)} · {formatBytes(maxFileBytes)} EACH</span></footer><div className="repository-file-drop-overlay" aria-hidden={externalDragDepth ? 'false' : 'true'}><span><Icon name="upload" /></span><strong>松开以添加到此目录</strong><small>{externalDropTarget ? `${String(entryMap.get(externalDropTarget)?.relative_path || entryMap.get(externalDropTarget)?.name || 'ROOT').toUpperCase()} · MULTI-FILE / FOLDER` : 'ROOT · MULTI-FILE / FOLDER'}</small></div></aside>
      <main className="repository-editor-pane" aria-label="代码编辑器"><header className="repository-editor-bar"><div className="repository-file-tab"><span className="repository-tab-ext">{ext}</span><strong>{name}</strong>{draft != null ? <span className="repository-modified">● MODIFIED</span> : null}</div><div className="repository-editor-actions"><button className="repository-icon-button" type="button" title="保存（Ctrl/Cmd + S）" aria-label="保存文件" disabled={!selected || save.isPending} onClick={() => void saveCurrentFile()}><Icon name="save" /></button><button className="repository-icon-button" type="button" title="移动或重命名" aria-label="移动或重命名当前文件" disabled={!currentEntry} onClick={() => currentEntry && openManage(currentEntry)}><Icon name="move" /></button><button className="repository-icon-button repository-icon-danger" type="button" title="删除文件" aria-label="删除当前文件" disabled={!currentEntry || previewDelete.isPending} onClick={() => currentEntry && openDelete(currentEntry)}><Icon name="trash" /></button></div></header><div className="repository-editor-shell"><div className="repository-breadcrumbs">{!selected ? <><span>repository</span><span>›</span><b>选择一个文件开始编辑</b></> : <><span>repository</span>{relativePath.split('/').filter(Boolean).map((piece, index, pieces) => <Fragment key={`${piece}-${index}`}><span>›</span>{index === pieces.length - 1 ? <b>{piece}</b> : <span>{piece}</span>}</Fragment>)}</>}</div>{!selected ? <div className="repository-empty-editor"><span className="repository-empty-mark"><Icon name="file-plus" /></span><strong>从左侧打开文件</strong><p>也可以新建文件，或将一组文件与文件夹直接拖入文件区。</p></div> : file.isPending ? <div className="repository-editor-loading"><MathCurveLoader size="lg" label="代码编辑器正在加载" /></div> : file.isError ? <div className="repository-empty-editor"><span className="repository-empty-mark"><Icon name="file" /></span><strong>文件读取失败</strong><p>{errorMessage(file.error)}</p><button className="repository-button" type="button" onClick={() => void file.refetch()}>重试读取</button></div> : <div className="repository-editor-stage"><MonacoEditor language={languageForFilename(name)} problemId={selected || 0} value={content} onChange={(value) => {draftRef.current = value; setDraft(value)}} idPrefix="repository" ariaLabel="代码仓库编辑器输入区" shellBaseClassName="repository-monaco-shell" hostClassName="repository-monaco-container" fallbackClassName="repository-code-fallback" onReady={({editor, monaco}) => {
        editorRef.current = editor
        const cursorEditor = editor as MonacoEditorInstance & {onDidChangeCursorPosition?: (listener: (event: {position?: {lineNumber?: number; column?: number}}) => void) => {dispose: () => void}}
        const subscription = cursorEditor.onDidChangeCursorPosition?.((event) => setCursor({line: Number(event.position?.lineNumber || 1), column: Number(event.position?.column || 1)}))
        const commandEditor = editor as MonacoEditorInstance & {addCommand?: (keybinding: number, handler: () => void) => unknown}
        const keyApi = monaco as typeof monaco & {KeyMod?: {CtrlCmd?: number}; KeyCode?: {KeyS?: number}}
        const saveBinding = Number(keyApi.KeyMod?.CtrlCmd || 0) | Number(keyApi.KeyCode?.KeyS || 0)
        if (saveBinding) commandEditor.addCommand?.(saveBinding, () => {void saveCurrentFileRef.current()})
        return () => {subscription?.dispose(); if (editorRef.current === editor) editorRef.current = null}
      }} /></div>}</div><footer className="repository-editor-status"><span><b>{selected ? languageLabelForFilename(name).toUpperCase() : 'NO FILE'}</b><span>UTF-8</span><span>LF</span></span><span><span>{selected ? `Ln ${cursor.line}, Col ${cursor.column}` : 'Ln —, Col —'}</span><b>{!selected ? 'IDLE' : file.isError ? 'ERROR' : save.isPending ? 'SAVING' : draft != null ? 'UNSAVED' : 'SAVED'}</b></span></footer></main>
      <aside className="repository-inspector" aria-label="代码结构与语义检索"><div className="repository-inspector-tabs" role="tablist"><button className={inspector === 'outline' ? 'active' : ''} type="button" role="tab" aria-selected={inspector === 'outline'} onClick={() => setInspector('outline')}>OUTLINE</button><button className={inspector === 'semantic' ? 'active' : ''} type="button" role="tab" aria-selected={inspector === 'semantic'} onClick={() => setInspector('semantic')}>SEMANTIC</button></div>{inspector === 'outline' ? <section className="repository-inspector-panel active"><p className="repository-inspector-note">从当前文件提取结构。选择符号可定位到对应代码行。</p><div className="repository-outline-list">{symbols.map((symbol) => <button className="repository-outline-item" type="button" key={`${symbol.line}-${symbol.name}`} onClick={() => jumpToLine(symbol.line)}><span className="repository-symbol">{symbol.type}</span><strong>{symbol.name}</strong><small>L{symbol.line}</small></button>)}{!selected || !symbols.length ? <div className="repository-inspector-empty">{selected ? '当前文件没有识别到结构。' : '打开文件后显示结构。'}</div> : null}</div></section> : <section className="repository-inspector-panel active"><form className="repository-semantic-search" onSubmit={submitSearch}><label><Icon name="search" /><input type="search" placeholder="描述你要找的代码" value={semanticQuery} onChange={(event) => setSemanticQuery(event.target.value)} /></label><button type="submit" disabled={semanticSearch.isPending}>{semanticSearch.isPending ? '…' : '检索'}</button></form><p className="repository-inspector-note">{semanticSearch.data ? `找到 ${(semanticSearch.data.hits || []).length} 个结果 · ${semanticSearch.data.embedding_model || 'SEMANTIC'}` : '先完成结构化整理，再用自然语言检索函数。'}</p><div className="repository-semantic-list">{(semanticSearch.data?.hits || []).map((hit, index) => <button className="repository-semantic-hit" type="button" key={String(hit.chunk_id || index)} onClick={() => {const target = entries.find((entry) => String(entry.relative_path || entry.path) === String(hit.filename)); if (target) void openFile(Number(target.id), Number(hit.start_line || 1))}}><span><strong>{String(hit.qualified_name || hit.filename || '代码片段')}</strong><em>{Math.round(Number(hit.score || 0) * 100)}%</em></span><small>{String(hit.filename || '')} · L{String(hit.start_line || '—')}</small><p>{String(hit.summary || hit.signature || '')}</p></button>)}{semanticSearch.isError ? <div className="repository-inspector-empty">{errorMessage(semanticSearch.error)}</div> : semanticSearch.data && !(semanticSearch.data.hits || []).length ? <div className="repository-inspector-empty">没有找到匹配的代码。</div> : null}</div></section>}</aside>
    </div>
    <div className={`repository-toast${notice || operationError ? ' is-visible' : ''}${notice?.error || operationError ? ' is-error' : ''}`} role="status" aria-live="polite"><span><Icon name={notice?.error || operationError ? 'close' : 'check'} /></span><div><strong>{operationError ? '操作失败' : notice?.title || '操作完成'}</strong><p>{operationError ? errorMessage(operationError) : notice?.message || ''}</p></div></div>

    {contextMenu ? <div className="repository-context-menu" role="menu" style={{left: contextMenu.left, top: contextMenu.top}}><button type="button" onClick={() => {const entry = contextMenu.entry; setContextMenu(null); openManage(entry, 'rename')}}><Icon name="edit" />重命名</button><button type="button" onClick={() => {const entry = contextMenu.entry; setContextMenu(null); openManage(entry, 'move')}}><Icon name="move" />移动到…</button><button className="danger" type="button" onClick={() => {const entry = contextMenu.entry; setContextMenu(null); openDelete(entry)}}><Icon name="trash" />删除</button></div> : null}

    {dialog === 'manage' && actionEntry ? <Dialog kicker="ORGANIZE ENTRY" title={manageMode === 'rename' ? `重命名${String(actionEntry.kind) === 'directory' ? '目录' : '文件'}` : '移动或重命名'} className="repository-move-dialog" onClose={() => setDialog(null)} footer={<><button className="repository-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="repository-button repository-button-primary" type="submit" form="repositoryMoveForm" disabled={!entryName.trim() || moveEntry.isPending}>应用更改</button></>}><form id="repositoryMoveForm" onSubmit={submitMove}><label className="repository-field"><span>名称</span><input ref={manageNameRef} required maxLength={255} autoComplete="off" value={entryName} onChange={(event) => setEntryName(event.target.value)} /></label><label className="repository-field"><span>目标目录</span><select ref={manageDestinationRef} value={destination} onChange={(event) => setDestination(event.target.value)}><option value="">repository /</option>{directories.filter((item) => Number(item.id) !== Number(actionEntry.id) && !String(item.relative_path || '').startsWith(`${String(actionEntry.relative_path || '')}/`)).map((item) => <option value={String(item.id)} key={String(item.id)}>repository / {String(item.relative_path || item.name)}</option>)}</select><small>也可以在文件树中直接把文件或目录拖到目标文件夹。</small></label>{String(actionEntry.kind) === 'directory' ? <label className="repository-move-merge"><input type="checkbox" checked={mergeDirectories} onChange={(event) => setMergeDirectories(event.target.checked)} /><span><strong>同名目录时递归合并</strong><small>只合并目录；任意深层文件重名或类型冲突都会取消整个操作。</small></span></label> : null}</form></Dialog> : null}
    {dialog === 'delete' && actionEntry ? <Dialog kicker="DESTRUCTIVE ACTION" title={`删除${String(actionEntry.kind) === 'directory' ? '目录' : '文件'}`} className="repository-delete-dialog" onClose={() => setDialog(null)} footer={<><button className="repository-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="repository-button repository-button-danger" type="button" disabled={!deletePreview?.confirmation_token || deleteEntry.isPending} onClick={() => deleteEntry.mutate()}>{deleteEntry.isPending ? '正在删除…' : deletePreview ? '确认永久删除' : previewDelete.isError ? '无法删除' : '正在核对…'}</button></>}>{deletePreview ? <p>将永久删除 <strong>{String(deletePreview.path || actionEntry.relative_path || actionEntry.name)}</strong>。<span className="repository-delete-facts"><b>{Number(deletePreview.file_count || 0)}</b> 个文件 · <b>{Number(deletePreview.directory_count || 0)}</b> 个目录 · <b>{formatBytes(Number(deletePreview.total_size || 0))}</b></span>{selected === Number(actionEntry.id) || (String(actionEntry.kind) === 'directory' && relativePath.startsWith(`${String(actionEntry.relative_path || actionEntry.name || '')}/`)) ? <span className="repository-delete-warning">当前编辑器中的 <strong>{relativePath}</strong> 位于删除范围内{draft != null ? '，其中尚有未保存内容' : ''}；确认后编辑器会关闭。</span> : null}<span>此操作不可恢复。</span></p> : <p>{previewDelete.isError ? errorMessage(previewDelete.error) : '正在核对待删除内容…'}</p>}</Dialog> : null}
    {dialog === 'upload' ? <Dialog kicker="MULTI-FILE / FOLDER UPLOAD" title="上传文件与目录" className="repository-upload-dialog" closeLabel="关闭上传窗口" footerClassName="repository-upload-footer" onClose={() => {setDialog(null); void cancelUploadSession()}} footer={<><span>{uploadSummary}</span><span><button className="repository-button" type="button" onClick={() => {setDialog(null); void cancelUploadSession()}}>取消</button><button className="repository-button repository-button-primary" type="button" disabled={!uploadCanProceed} onClick={() => upload.mutate()}>{uploadButtonLabel[uploadPhase]}</button></span></>}><p className="repository-dialog-destination">上传位置 <strong>repository / {actionEntry && String(actionEntry.kind) === 'directory' ? String(actionEntry.relative_path || actionEntry.name) : ''}</strong></p><label className={`repository-upload-dropzone${uploadDrag ? ' is-dragover' : ''}${uploadItems.length ? ' has-files' : ''}`} onDragEnter={(event) => {event.preventDefault(); setUploadDrag(true)}} onDragOver={(event) => {event.preventDefault(); event.dataTransfer.dropEffect = 'copy'}} onDragLeave={(event) => {event.preventDefault(); if (event.currentTarget === event.target) setUploadDrag(false)}} onDrop={(event) => {event.preventDefault(); setUploadDrag(false); void extractDropDescriptors(event.dataTransfer).then((items) => addUploadDescriptors(items, true)).catch((error) => setUploadError(errorMessage(error)))}}><span className="repository-upload-mark"><Icon name="upload" /></span><strong>拖拽多个文件或文件夹到这里</strong><span>文件夹会保留层级并自动创建为子目录</span><small>TEXT AUTO-DETECT　/　2 MIB NORMALIZED EACH　/　32 MIB REPOSITORY</small></label><input ref={uploadFilesRef} type="file" multiple hidden onChange={(event) => {if (event.target.files) void addUploadDescriptors(descriptorsFromFiles(event.target.files), true); event.target.value = ''}} /><input ref={uploadFolderRef} type="file" multiple hidden {...({webkitdirectory: '', directory: ''} as React.InputHTMLAttributes<HTMLInputElement>)} onChange={(event) => {if (event.target.files) void addUploadDescriptors(descriptorsFromFiles(event.target.files, true), true); event.target.value = ''}} /><div className="repository-upload-choices"><button className="repository-button" type="button" onClick={() => uploadFilesRef.current?.click()}>选择多个文件</button><button className="repository-button" type="button" onClick={() => uploadFolderRef.current?.click()}>选择文件夹</button></div><p className="repository-upload-picker-note">拖拽文件夹可识别其中的空目录；浏览器的“选择文件夹”通常不会暴露空目录。</p><section className="repository-upload-queue" hidden={!uploadItems.length} aria-live="polite"><div className="repository-upload-queue-head"><strong>已选择 {uploadFileCount} 个文件{uploadDirectoryCount ? ` · ${uploadDirectoryCount} 个目录` : ''}</strong><button type="button" onClick={() => void cancelUploadSession()}>清空列表</button></div><div className="repository-upload-file-list">{uploadItems.map((item) => <div className={`repository-upload-file${item.error ? ' is-invalid' : ''}${['conflict', 'blocking_conflict'].includes(item.serverStatus) ? ' is-conflict' : ''}`} key={item.key}><span className="repository-upload-file-icon">{item.kind === 'directory' ? 'DIR' : (item.relativePath.split('.').pop() || 'FILE').slice(0, 5).toUpperCase()}</span><span className="repository-upload-file-copy"><strong title={item.relativePath}>{item.relativePath}</strong><small>{item.kind === 'directory' ? '目录清单' : `${formatBytes(item.file.size)} · ${item.encoding}`}</small></span><span className="repository-upload-file-state">{uploadState(item)}</span><button className={`repository-upload-file-remove${item.error || item.serverStatus === 'blocking_conflict' || item.encodingHasDisallowedControl ? ' is-exclude' : ''}`} type="button" aria-label={`排除 ${item.relativePath}`} onClick={() => void removeUploadItem(item.key)}>{item.error || item.serverStatus === 'blocking_conflict' || item.encodingHasDisallowedControl ? '排除' : '×'}</button>{item.encodingPreview || item.encodingHasDisallowedControl ? <div className="repository-encoding-preview"><strong>候选解码预览{item.encodingPreviewTruncated ? '（已截断）' : ''}</strong><pre aria-label="候选解码预览">{item.encodingPreview}</pre>{item.encodingHasDisallowedControl ? <span role="alert">检测到不允许的控制字符，无法按该编码上传；请排除此文件。</span> : null}</div> : null}</div>)}</div></section></Dialog> : null}
    {saveConflict ? <Dialog kicker="SAVE CONFLICT" title="文件已在其他位置发生变化" className="repository-save-conflict-dialog" onClose={() => undefined} footer={<><button className="repository-button" type="button" onClick={() => void backupConflict('copy')}>复制本地内容</button><button className="repository-button" type="button" onClick={() => void backupConflict('download')}>下载本地备份</button><button className="repository-button repository-button-danger" type="button" disabled={!conflictReloadConfirmed} onClick={() => void reloadAfterConflict()}>丢弃本地修改并重新载入</button></>}><p><strong>{saveConflict.snapshot.relativePath}</strong> 的服务端版本已经变化，或文件已被移动/删除。为了避免覆盖他人的修改，本地内容尚未写入。请先复制或下载本地备份，再决定是否重新载入。</p><div className="repository-conflict-backup-actions"><label><input type="checkbox" checked={conflictReloadConfirmed} onChange={(event) => setConflictReloadConfirmed(event.target.checked)} /> 我已备份本地内容，确认丢弃本地修改</label></div><p className="mt-3 text-danger">{saveConflict.message}</p></Dialog> : null}
  </section>
}
