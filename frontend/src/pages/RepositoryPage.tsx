import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {Fragment, useEffect, useMemo, useRef, useState, type FormEvent} from 'react'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {MonacoEditor, type MonacoEditorInstance} from '../components/MonacoEditor'
import {LoadingState} from '../components/PageState'

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
interface FileResponse extends ApiEnvelope {id?: number; entry_id?: number; filename?: string; relative_path?: string; content?: string; file_version?: number}
interface IndexResponse extends ApiEnvelope {job_id?: number; job?: JsonRecord; has_active?: boolean}
interface SearchResponse extends ApiEnvelope {hits?: JsonRecord[]; embedding_model?: string}
interface DeletePreview extends ApiEnvelope {confirmation_token?: string; path?: string; kind?: string; entry_count?: number; file_count?: number; directory_count?: number; total_size?: number}
interface UploadPreview extends ApiEnvelope {session_id?: string; structure_version?: number; base_structure_version?: number; ready?: boolean; files?: JsonRecord[]}
type Entry = JsonRecord & {depth: number}
type DialogName = 'upload' | 'manage' | 'delete' | null
type InlineCreate = {kind: 'file' | 'directory'; parentId: number | null; value: string; error: string; saving: boolean}

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

function Dialog({title, kicker, onClose, children, footer, className = '', closeLabel = '关闭', footerClassName = ''}: {title: string; kicker: string; onClose: () => void; children: React.ReactNode; footer: React.ReactNode; className?: string; closeLabel?: string; footerClassName?: string}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {const element = ref.current; if (element && !element.open) element.showModal(); return () => {if (element?.open) element.close()}}, [])
  return <dialog ref={ref} className={`repository-dialog${className ? ` ${className}` : ''}`} onCancel={(event) => {event.preventDefault(); onClose()}}>
    <header><div><p>{kicker}</p><h2>{title}</h2></div><button className="repository-icon-button" type="button" onClick={onClose} aria-label={closeLabel}><Icon name="close" /></button></header>
    <div className="repository-dialog-body">{children}</div>
    <footer className={footerClassName || undefined}>{footer}</footer>
  </dialog>
}

export default function RepositoryPage() {
  const queryClient = useQueryClient()
  const editorRef = useRef<MonacoEditorInstance | null>(null)
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
  const [uploadFiles, setUploadFiles] = useState<File[]>([])
  const [uploadDrag, setUploadDrag] = useState(false)
  const [externalDragDepth, setExternalDragDepth] = useState(0)
  const [externalDropTarget, setExternalDropTarget] = useState<number | null>(null)
  const uploadFilesRef = useRef<HTMLInputElement>(null)
  const uploadFolderRef = useRef<HTMLInputElement>(null)
  const manageNameRef = useRef<HTMLInputElement>(null)
  const manageDestinationRef = useRef<HTMLSelectElement>(null)
  const [deletePreview, setDeletePreview] = useState<DeletePreview | null>(null)
  const [indexJobId, setIndexJobId] = useState<number | null>(null)
  const [notice, setNotice] = useState<{title: string; message: string; error?: boolean} | null>(null)

  const context = useQuery({queryKey: ['repository', 'context'], queryFn: () => apiFetch<ApiEnvelope>('/api/repository/context')})
  const tree = useQuery({queryKey: ['repository', 'tree'], queryFn: () => apiFetch<TreeResponse>('/api/repository/tree')})
  const file = useQuery({queryKey: ['repository', 'file', selected], queryFn: () => apiFetch<FileResponse>(`/api/repository/file/${selected}`), enabled: selected != null})
  const activeIndex = useQuery({queryKey: ['repository', 'index', 'active'], queryFn: () => apiFetch<IndexResponse>('/api/repository/index/status/active'), enabled: context.isSuccess, refetchInterval: 2500})
  const indexStatus = useQuery({queryKey: ['repository', 'index', indexJobId], queryFn: () => apiFetch<IndexResponse>(`/api/repository/index/status/${indexJobId}`), enabled: indexJobId != null, refetchInterval: indexJobId != null ? 1500 : false})

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

  const refreshTree = async () => {await queryClient.invalidateQueries({queryKey: ['repository']})}
  const save = useMutation({
    mutationFn: () => {if (!file.data) throw new Error('尚未选择文件'); return apiFetch<ApiEnvelope>('/api/repository/file', {method: 'POST', body: JSON.stringify({file_id: file.data.entry_id || file.data.id || selected, content, expected_file_version: file.data.file_version})})},
    onSuccess: async () => {setDraft(null); setNotice({title: '文件已保存', message: relativePath || name}); await refreshTree()},
  })
  const createEntry = useMutation({
    mutationFn: () => {
      if (!inlineCreate) throw new Error('没有正在创建的项目')
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
    mutationFn: () => {
      if (!actionEntry) throw new Error('没有选中项目')
      return apiFetch<ApiEnvelope>(`/api/repository/entry/${Number(actionEntry.id)}/move`, {method: 'POST', body: JSON.stringify({destination_parent_id: destination || null, new_name: entryName, expected_structure_version: tree.data?.structure_version, conflict_policy: mergeDirectories ? 'merge' : 'error'})})
    },
    onSuccess: async () => {setDialog(null); setNotice({title: mergeDirectories ? '目录已合并' : '位置已更新', message: `${entryName} 已移动到 ${destination ? `repository / ${String(entryMap.get(Number(destination))?.relative_path || entryMap.get(Number(destination))?.name || '')}` : 'repository /'}`}); await refreshTree()},
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
    onSuccess: async () => {if (selected === Number(actionEntry?.id) || (String(actionEntry?.kind) === 'directory' && relativePath.startsWith(`${String(actionEntry?.relative_path || actionEntry?.name || '')}/`))) {setSelected(null); setDraft(null)}; setDialog(null); setDeletePreview(null); setNotice({title: '已删除', message: String(actionEntry?.relative_path || actionEntry?.name || '')}); await refreshTree()},
  })
  const upload = useMutation({
    mutationFn: async () => {
      if (!uploadFiles.length) throw new Error('请选择文件')
      const body = new FormData()
      const parentId = actionEntry && String(actionEntry.kind) === 'directory' ? Number(actionEntry.id) : actionEntry?.parent_id || ''
      if (parentId) body.append('parent_id', String(parentId))
      body.append('expected_structure_version', String(tree.data?.structure_version || ''))
      uploadFiles.forEach((item) => {body.append('files', item); body.append('relative_paths', (item as File & {webkitRelativePath?: string}).webkitRelativePath || item.name)})
      const preview = await apiFetch<UploadPreview>('/api/repository/upload/preview', {method: 'POST', body})
      const conflicts = (preview.files || []).filter((item) => String(item.status || '') === 'conflict')
      if (!preview.session_id) throw new Error('上传会话创建失败')
      if (!preview.ready || conflicts.length) {
        await apiFetch<ApiEnvelope>(`/api/repository/upload/session/${encodeURIComponent(preview.session_id)}`, {method: 'DELETE'})
        throw new Error(conflicts.length ? `有 ${conflicts.length} 个同名文件，请先在仓库中重命名或删除冲突项` : '文件编码需要人工确认，请改用 UTF-8 文本后重试')
      }
      return apiFetch<ApiEnvelope>(`/api/repository/upload/session/${encodeURIComponent(preview.session_id)}/commit`, {method: 'POST', body: JSON.stringify({expected_structure_version: preview.structure_version ?? preview.base_structure_version, resolutions: {}})})
    },
    onSuccess: async () => {setDialog(null); setUploadFiles([]); setNotice({title: '上传完成', message: `${uploadFiles.length} 个文件已加入仓库`}); await refreshTree()},
  })
  const buildIndex = useMutation({
    mutationFn: () => apiFetch<IndexResponse>('/api/repository/index/build', {method: 'POST'}),
    onSuccess: async (data) => {if (data.job_id) setIndexJobId(Number(data.job_id)); setNotice({title: '结构化整理已启动', message: data.message || '正在建立代码索引'}); await queryClient.invalidateQueries({queryKey: ['repository', 'index']})},
  })
  const cancelIndex = useMutation({
    mutationFn: () => {const id = Number(currentIndexJob?.id || indexJobId); return apiFetch<ApiEnvelope>(`/api/repository/index/${id}/cancel`, {method: 'POST'})},
    onSuccess: async () => {setNotice({title: '整理已取消', message: '仓库文件没有被修改'}); await queryClient.invalidateQueries({queryKey: ['repository', 'index']})},
  })
  const semanticSearch = useMutation({mutationFn: () => apiFetch<SearchResponse>('/api/repository/index/search', {method: 'POST', body: JSON.stringify({query: semanticQuery})})})

  const actionDirectoryId = () => focusedDirectory || Number(currentEntry?.parent_id || 0) || null
  const externalDirectoryAtTarget = (target: EventTarget | null) => {
    const row = target instanceof Element ? target.closest<HTMLElement>('.repository-tree-row[data-entry-kind="directory"]') : null
    const rowId = Number(row?.dataset.entryId || 0)
    return rowId || actionDirectoryId()
  }
  const isExternalFileDrag = (event: React.DragEvent) => Array.from(event.dataTransfer.types || []).includes('Files') && !Array.from(event.dataTransfer.types || []).includes('application/x-numoj-entry-id')
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
      <aside className={`repository-files-pane${externalDragDepth ? ' is-external-dragover' : ''}`} aria-label="仓库文件" onDragEnter={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); setExternalDragDepth((value) => value + 1); setExternalDropTarget(externalDirectoryAtTarget(event.target))}} onDragOver={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); event.dataTransfer.dropEffect = 'copy'; setExternalDropTarget(externalDirectoryAtTarget(event.target))}} onDragLeave={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); setExternalDragDepth((value) => Math.max(0, value - 1))}} onDrop={(event) => {if (!isExternalFileDrag(event)) return; event.preventDefault(); event.stopPropagation(); const targetId = externalDirectoryAtTarget(event.target); setExternalDragDepth(0); setExternalDropTarget(targetId); setActionEntry(targetId ? entryMap.get(targetId) || null : null); setUploadFiles(Array.from(event.dataTransfer.files || [])); setDialog('upload')}}><div className="repository-pane-head"><span className="repository-pane-copy"><span className="repository-pane-label">FILES</span><span className="repository-pane-count">{files.length} FILES</span></span><span className="repository-file-tools"><button className="repository-file-tool" type="button" aria-label="新建文件" onClick={() => openCreate('file')}><Icon name="file-plus" /></button><button className="repository-file-tool" type="button" aria-label="新建目录" onClick={() => openCreate('directory')}><Icon name="folder-plus" /></button><button className="repository-file-tool" type="button" aria-label="上传文件或文件夹" onClick={() => {setActionEntry(entryMap.get(actionDirectoryId() || 0) || currentEntry); setDialog('upload')}}><Icon name="upload" /></button></span></div><label className="repository-file-search"><Icon name="search" /><input type="search" placeholder="筛选文件与目录" value={filter} onChange={(event) => setFilter(event.target.value)} /></label><div className="repository-tree" role="tree" aria-label="代码仓库目录树">{repositoryError ? <div className="repository-tree-empty">仓库加载失败。<br />{repositoryError.message}</div> : <>{treeRows.map((row, index) => {
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
        return <div className={`repository-tree-row${isExpanded ? ' is-expanded' : ''}${selected === id || focusedDirectory === id ? ' is-active' : ''}${directSearchHit ? ' is-search-hit' : ''}`} style={{'--tree-depth': row.depth, '--tree-indent': `${Math.min(row.depth, 8) * 13}px`} as React.CSSProperties} data-entry-id={id} data-entry-kind={directory ? 'directory' : 'file'} role="treeitem" aria-level={row.depth + 1} aria-expanded={directory ? isExpanded : undefined} title={path} key={`${id}-${index}`}><button className={`repository-tree-toggle${!directory || !hasChildren ? ' is-placeholder' : ''}`} type="button" tabIndex={!directory || !hasChildren ? -1 : 0} aria-label={isExpanded ? '折叠目录' : '展开目录'} onClick={() => setExpanded((items) => items.includes(id) ? items.filter((item) => item !== id) : [...items, id])}><Icon name="chevron" /></button><span className={`repository-tree-glyph${directory ? '' : ' file'}`}><Icon name={directory ? 'folder' : 'file'} /></span><button className="repository-tree-main" type="button" onDoubleClick={() => {if (directory) openCreate('file')}} onClick={() => {if (directory) {setFocusedDirectory(id); setExpanded((items) => items.includes(id) ? items.filter((item) => item !== id) : [...items, id])} else {setSelected(id); setDraft(null); setMobileFiles(false)}}}><span className={`repository-tree-name${directSearchHit ? ' is-path' : ''}`}>{markedName(visibleName, directSearchHit ? query : '')}</span></button><button className="repository-tree-menu" type="button" aria-label={`${String(entry.name || '')} 的操作菜单`} onClick={(event) => {event.stopPropagation(); showContextMenu(entry, event.currentTarget)}}><Icon name="more" /></button></div>
      })}{!treeRows.length ? <div className="repository-tree-empty">{entries.length ? '没有匹配的文件或目录。' : <>仓库还是空的。<br />新建文件、目录，或拖入本地文件夹。</>}</div> : null}</>}</div><footer className="repository-files-foot"><span>PRIVATE WORKSPACE</span><span>{formatBytes(usedBytes)} / {formatBytes(maxRepositoryBytes)} · {formatBytes(maxFileBytes)} EACH</span></footer><div className="repository-file-drop-overlay" aria-hidden={externalDragDepth ? 'false' : 'true'}><span><Icon name="upload" /></span><strong>松开以添加到此目录</strong><small>{externalDropTarget ? `${String(entryMap.get(externalDropTarget)?.relative_path || entryMap.get(externalDropTarget)?.name || 'ROOT').toUpperCase()} · MULTI-FILE / FOLDER` : 'ROOT · MULTI-FILE / FOLDER'}</small></div></aside>
      <main className="repository-editor-pane" aria-label="代码编辑器"><header className="repository-editor-bar"><div className="repository-file-tab"><span className="repository-tab-ext">{ext}</span><strong>{name}</strong>{draft != null ? <span className="repository-modified">● MODIFIED</span> : null}</div><div className="repository-editor-actions"><button className="repository-icon-button" type="button" title="保存（Ctrl/Cmd + S）" aria-label="保存文件" disabled={!selected || save.isPending} onClick={() => save.mutate()}><Icon name="save" /></button><button className="repository-icon-button" type="button" title="移动或重命名" aria-label="移动或重命名当前文件" disabled={!currentEntry} onClick={() => currentEntry && openManage(currentEntry)}><Icon name="move" /></button><button className="repository-icon-button repository-icon-danger" type="button" title="删除文件" aria-label="删除当前文件" disabled={!currentEntry || previewDelete.isPending} onClick={() => currentEntry && openDelete(currentEntry)}><Icon name="trash" /></button></div></header><div className="repository-editor-shell"><div className="repository-breadcrumbs">{!selected ? <><span>repository</span><span>›</span><b>选择一个文件开始编辑</b></> : <><span>repository</span>{relativePath.split('/').filter(Boolean).map((piece, index, pieces) => <Fragment key={`${piece}-${index}`}><span>›</span>{index === pieces.length - 1 ? <b>{piece}</b> : <span>{piece}</span>}</Fragment>)}</>}</div>{!selected ? <div className="repository-empty-editor"><span className="repository-empty-mark"><Icon name="file-plus" /></span><strong>从左侧打开文件</strong><p>也可以新建文件，或将一组文件与文件夹直接拖入文件区。</p></div> : file.isPending ? <div className="repository-editor-loading"><span className="math-curve-loader" data-math-curve-loader data-size="lg"><span className="math-curve-loader__label">代码编辑器正在加载</span></span></div> : <div className="repository-editor-stage"><MonacoEditor language={languageForFilename(name)} problemId={selected || 0} value={content} onChange={(value) => setDraft(value)} idPrefix="repository" ariaLabel="代码仓库编辑器输入区" shellBaseClassName="repository-monaco-shell" hostClassName="repository-monaco-container" fallbackClassName="repository-code-fallback" onReady={({editor}) => {
        editorRef.current = editor
        const cursorEditor = editor as MonacoEditorInstance & {onDidChangeCursorPosition?: (listener: (event: {position?: {lineNumber?: number; column?: number}}) => void) => {dispose: () => void}}
        const subscription = cursorEditor.onDidChangeCursorPosition?.((event) => setCursor({line: Number(event.position?.lineNumber || 1), column: Number(event.position?.column || 1)}))
        return () => {subscription?.dispose(); if (editorRef.current === editor) editorRef.current = null}
      }} /></div>}</div><footer className="repository-editor-status"><span><b>{selected ? languageLabelForFilename(name).toUpperCase() : 'NO FILE'}</b><span>UTF-8</span><span>LF</span></span><span><span>{selected ? `Ln ${cursor.line}, Col ${cursor.column}` : 'Ln —, Col —'}</span><b>{!selected ? 'IDLE' : save.isPending ? 'SAVING' : draft != null ? 'UNSAVED' : 'SAVED'}</b></span></footer></main>
      <aside className="repository-inspector" aria-label="代码结构与语义检索"><div className="repository-inspector-tabs" role="tablist"><button className={inspector === 'outline' ? 'active' : ''} type="button" role="tab" aria-selected={inspector === 'outline'} onClick={() => setInspector('outline')}>OUTLINE</button><button className={inspector === 'semantic' ? 'active' : ''} type="button" role="tab" aria-selected={inspector === 'semantic'} onClick={() => setInspector('semantic')}>SEMANTIC</button></div>{inspector === 'outline' ? <section className="repository-inspector-panel active"><p className="repository-inspector-note">从当前文件提取结构。选择符号可定位到对应代码行。</p><div className="repository-outline-list">{symbols.map((symbol) => <button className="repository-outline-item" type="button" key={`${symbol.line}-${symbol.name}`} onClick={() => jumpToLine(symbol.line)}><span className="repository-symbol">{symbol.type}</span><strong>{symbol.name}</strong><small>L{symbol.line}</small></button>)}{!selected || !symbols.length ? <div className="repository-inspector-empty">{selected ? '当前文件没有识别到结构。' : '打开文件后显示结构。'}</div> : null}</div></section> : <section className="repository-inspector-panel active"><form className="repository-semantic-search" onSubmit={submitSearch}><label><Icon name="search" /><input type="search" placeholder="描述你要找的代码" value={semanticQuery} onChange={(event) => setSemanticQuery(event.target.value)} /></label><button type="submit" disabled={semanticSearch.isPending}>{semanticSearch.isPending ? '…' : '检索'}</button></form><p className="repository-inspector-note">{semanticSearch.data ? `找到 ${(semanticSearch.data.hits || []).length} 个结果 · ${semanticSearch.data.embedding_model || 'SEMANTIC'}` : '先完成结构化整理，再用自然语言检索函数。'}</p><div className="repository-semantic-list">{(semanticSearch.data?.hits || []).map((hit, index) => <button className="repository-semantic-hit" type="button" key={String(hit.chunk_id || index)} onClick={() => {const target = entries.find((entry) => String(entry.relative_path || entry.path) === String(hit.filename)); if (target) {setSelected(Number(target.id)); setDraft(null)}}}><span><strong>{String(hit.qualified_name || hit.filename || '代码片段')}</strong><em>{Math.round(Number(hit.score || 0) * 100)}%</em></span><small>{String(hit.filename || '')} · L{String(hit.start_line || '—')}</small><p>{String(hit.summary || hit.signature || '')}</p></button>)}{semanticSearch.isError ? <div className="repository-inspector-empty">{errorMessage(semanticSearch.error)}</div> : semanticSearch.data && !(semanticSearch.data.hits || []).length ? <div className="repository-inspector-empty">没有找到匹配的代码。</div> : null}</div></section>}</aside>
    </div>
    <div className={`repository-toast${notice || operationError ? ' is-visible' : ''}${notice?.error || operationError ? ' is-error' : ''}`} role="status" aria-live="polite"><span><Icon name={notice?.error || operationError ? 'close' : 'check'} /></span><div><strong>{operationError ? '操作失败' : notice?.title || '操作完成'}</strong><p>{operationError ? errorMessage(operationError) : notice?.message || ''}</p></div></div>

    {contextMenu ? <div className="repository-context-menu" role="menu" style={{left: contextMenu.left, top: contextMenu.top}}><button type="button" onClick={() => {const entry = contextMenu.entry; setContextMenu(null); openManage(entry, 'rename')}}><Icon name="edit" />重命名</button><button type="button" onClick={() => {const entry = contextMenu.entry; setContextMenu(null); openManage(entry, 'move')}}><Icon name="move" />移动到…</button><button className="danger" type="button" onClick={() => {const entry = contextMenu.entry; setContextMenu(null); openDelete(entry)}}><Icon name="trash" />删除</button></div> : null}

    {dialog === 'manage' && actionEntry ? <Dialog kicker="ORGANIZE ENTRY" title={manageMode === 'rename' ? `重命名${String(actionEntry.kind) === 'directory' ? '目录' : '文件'}` : '移动或重命名'} className="repository-move-dialog" onClose={() => setDialog(null)} footer={<><button className="repository-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="repository-button repository-button-primary" type="submit" form="repositoryMoveForm" disabled={!entryName.trim() || moveEntry.isPending}>应用更改</button></>}><form id="repositoryMoveForm" onSubmit={submitMove}><label className="repository-field"><span>名称</span><input ref={manageNameRef} required maxLength={255} autoComplete="off" value={entryName} onChange={(event) => setEntryName(event.target.value)} /></label><label className="repository-field"><span>目标目录</span><select ref={manageDestinationRef} value={destination} onChange={(event) => setDestination(event.target.value)}><option value="">repository /</option>{directories.filter((item) => Number(item.id) !== Number(actionEntry.id) && !String(item.relative_path || '').startsWith(`${String(actionEntry.relative_path || '')}/`)).map((item) => <option value={String(item.id)} key={String(item.id)}>repository / {String(item.relative_path || item.name)}</option>)}</select><small>也可以在文件树中直接把文件或目录拖到目标文件夹。</small></label>{String(actionEntry.kind) === 'directory' ? <label className="repository-move-merge"><input type="checkbox" checked={mergeDirectories} onChange={(event) => setMergeDirectories(event.target.checked)} /><span><strong>同名目录时递归合并</strong><small>只合并目录；任意深层文件重名或类型冲突都会取消整个操作。</small></span></label> : null}</form></Dialog> : null}
    {dialog === 'delete' && actionEntry ? <Dialog kicker="DESTRUCTIVE ACTION" title={`删除${String(actionEntry.kind) === 'directory' ? '目录' : '文件'}`} className="repository-delete-dialog" onClose={() => setDialog(null)} footer={<><button className="repository-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="repository-button repository-button-danger" type="button" disabled={!deletePreview?.confirmation_token || deleteEntry.isPending} onClick={() => deleteEntry.mutate()}>{deleteEntry.isPending ? '正在删除…' : deletePreview ? '确认永久删除' : previewDelete.isError ? '无法删除' : '正在核对…'}</button></>}>{deletePreview ? <p>将永久删除 <strong>{String(deletePreview.path || actionEntry.relative_path || actionEntry.name)}</strong>。<span className="repository-delete-facts"><b>{Number(deletePreview.file_count || 0)}</b> 个文件 · <b>{Number(deletePreview.directory_count || 0)}</b> 个目录 · <b>{formatBytes(Number(deletePreview.total_size || 0))}</b></span>{selected === Number(actionEntry.id) || (String(actionEntry.kind) === 'directory' && relativePath.startsWith(`${String(actionEntry.relative_path || actionEntry.name || '')}/`)) ? <span className="repository-delete-warning">当前编辑器中的 <strong>{relativePath}</strong> 位于删除范围内{draft != null ? '，其中尚有未保存内容' : ''}；确认后编辑器会关闭。</span> : null}<span>此操作不可恢复。</span></p> : <p>{previewDelete.isError ? errorMessage(previewDelete.error) : '正在核对待删除内容…'}</p>}</Dialog> : null}
    {dialog === 'upload' ? <Dialog kicker="MULTI-FILE / FOLDER UPLOAD" title="上传文件与目录" className="repository-upload-dialog" closeLabel="关闭上传窗口" footerClassName="repository-upload-footer" onClose={() => setDialog(null)} footer={<><span>{uploadFiles.length ? `已选择 ${uploadFiles.length} 个文件` : '尚未选择文件'}</span><span><button className="repository-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="repository-button repository-button-primary" type="button" disabled={!uploadFiles.length || upload.isPending} onClick={() => upload.mutate()}>{upload.isPending ? '正在检查…' : '检查文件'}</button></span></>}><p className="repository-dialog-destination">上传位置 <strong>repository / {actionEntry && String(actionEntry.kind) === 'directory' ? String(actionEntry.relative_path || actionEntry.name) : ''}</strong></p><label className={`repository-upload-dropzone${uploadDrag ? ' is-dragover' : ''}${uploadFiles.length ? ' has-files' : ''}`} onDragEnter={(event) => {event.preventDefault(); setUploadDrag(true)}} onDragOver={(event) => {event.preventDefault(); event.dataTransfer.dropEffect = 'copy'}} onDragLeave={(event) => {event.preventDefault(); if (event.currentTarget === event.target) setUploadDrag(false)}} onDrop={(event) => {event.preventDefault(); setUploadDrag(false); setUploadFiles(Array.from(event.dataTransfer.files || []))}}><span className="repository-upload-mark"><Icon name="upload" /></span><strong>拖拽多个文件或文件夹到这里</strong><span>文件夹会保留层级并自动创建为子目录</span><small>TEXT AUTO-DETECT　/　2 MIB NORMALIZED EACH　/　32 MIB REPOSITORY</small></label><input ref={uploadFilesRef} type="file" multiple hidden onChange={(event) => setUploadFiles(Array.from(event.target.files || []))} /><input ref={uploadFolderRef} type="file" multiple hidden {...({webkitdirectory: '', directory: ''} as React.InputHTMLAttributes<HTMLInputElement>)} onChange={(event) => setUploadFiles(Array.from(event.target.files || []))} /><div className="repository-upload-choices"><button className="repository-button" type="button" onClick={() => uploadFilesRef.current?.click()}>选择多个文件</button><button className="repository-button" type="button" onClick={() => uploadFolderRef.current?.click()}>选择文件夹</button></div><p className="repository-upload-picker-note">拖拽文件夹可识别其中的空目录；浏览器的“选择文件夹”通常不会暴露空目录。</p><section className="repository-upload-queue" hidden={!uploadFiles.length} aria-live="polite"><div className="repository-upload-queue-head"><strong>已选择 {uploadFiles.length} 个文件</strong><button type="button" onClick={() => setUploadFiles([])}>清空列表</button></div><div className="repository-upload-file-list">{uploadFiles.map((item, index) => <div className="repository-upload-file" key={`${item.name}-${index}`}><strong>{item.name}</strong><span>{Math.ceil(item.size / 1024)} KB</span></div>)}</div></section></Dialog> : null}
  </section>
}
