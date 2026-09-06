import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useMemo, useRef, useState, type FormEvent} from 'react'
import {useLocation} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {Identicon} from '../components/Identicon'
import {Link} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {useNativeDialog} from '../components/useNativeDialog'
import {useSession} from '../session'
import {VibeHubGpuControl} from '../components/VibeHubGpuControl'

interface Response extends ApiEnvelope {projects: JsonRecord[]; count: number}
interface ProjectResponse extends ApiEnvelope {project: JsonRecord}
type EditorMode = 'create' | 'edit'

export default function VibeHubPage() {
  const {session} = useSession()
  const location = useLocation()
  const queryClient = useQueryClient()
  const initialParams = useMemo(() => new URLSearchParams(location.search), [location.search])
  const result = useQuery({queryKey: ['vibehub'], queryFn: () => apiFetch<Response>('/api/vibehub/projects')})
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState(() => initialParams.get('view') || 'all')
  const [editorOpen, setEditorOpen] = useState(false)
  const [editorMode, setEditorMode] = useState<EditorMode>('create')
  const [editorSlug, setEditorSlug] = useState('')
  const [title, setTitle] = useState('')
  const [originalTitle, setOriginalTitle] = useState('')
  const [gpuMemory, setGpuMemory] = useState(0)
  const [packageFile, setPackageFile] = useState<File | null>(null)
  const [editorStatus, setEditorStatus] = useState('')
  const [editorError, setEditorError] = useState(false)
  const [editorLoading, setEditorLoading] = useState(false)
  const [editorReview, setEditorReview] = useState<{version: string; note: string} | null>(null)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleteText, setDeleteText] = useState('')
  const [deleteStatus, setDeleteStatus] = useState('')
  const [approveProject, setApproveProject] = useState<JsonRecord | null>(null)
  const [approveStatus, setApproveStatus] = useState('')
  const [approveNote, setApproveNote] = useState('')
  const [approvedGpuMemory, setApprovedGpuMemory] = useState(0)
  const [featuredProject, setFeaturedProject] = useState<JsonRecord | null>(null)
  const [featuredStatus, setFeaturedStatus] = useState('')
  const titleRef = useRef<HTMLInputElement>(null)
  const editorCloseRef = useRef<HTMLButtonElement>(null)
  const approveConfirmRef = useRef<HTMLButtonElement>(null)
  const featuredConfirmRef = useRef<HTMLButtonElement>(null)
  const editorRequestRef = useRef<AbortController | null>(null)
  const editorDialogRef = useNativeDialog(editorOpen, () => {
    if (editorMode === 'create') titleRef.current?.focus()
    else editorCloseRef.current?.focus()
  })
  const deleteDialogRef = useNativeDialog(deleteOpen)
  const approveDialogRef = useNativeDialog(Boolean(approveProject), () => approveConfirmRef.current?.focus())
  const featuredDialogRef = useNativeDialog(Boolean(featuredProject), () => featuredConfirmRef.current?.focus())

  const anyModalOpen = editorOpen || deleteOpen || Boolean(approveProject) || Boolean(featuredProject)
  useEffect(() => {
    document.body.classList.toggle('vibe-modal-open', anyModalOpen)
    return () => document.body.classList.remove('vibe-modal-open')
  }, [anyModalOpen])
  useEffect(() => () => editorRequestRef.current?.abort(), [])
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key !== '/' || anyModalOpen || /^(INPUT|TEXTAREA|SELECT)$/.test((event.target as HTMLElement | null)?.tagName || '')) return
      event.preventDefault()
      document.querySelector<HTMLInputElement>('[data-vibe-search]')?.focus()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [anyModalOpen])

  const refresh = async () => {await queryClient.invalidateQueries({queryKey: ['vibehub']})}
  const saveProject = useMutation({
    mutationFn: () => {
      if (editorMode === 'create' && !packageFile) throw new Error('请选择 ZIP 程序包。')
      const body = new FormData()
      body.append('title', title)
      body.append('gpu_memory_mib', String(gpuMemory))
      if (packageFile) body.append('package', packageFile)
      const encoded = encodeURIComponent(editorSlug)
      const url = editorMode === 'create' ? '/api/vibehub/projects' : packageFile ? `/api/vibehub/projects/${encoded}/versions` : `/api/vibehub/projects/${encoded}`
      const method = editorMode === 'create' || packageFile ? 'POST' : 'PATCH'
      return apiFetch<ApiEnvelope>(url, {method, body})
    },
    onMutate: () => {setEditorError(false); setEditorStatus(editorMode === 'edit' ? '正在构建更新并自动送审…' : '正在构建作品并自动送审…')},
    onSuccess: async () => {setEditorStatus('latest 镜像已构建并进入审核队列，正在刷新我的作品…'); await refresh(); setEditorOpen(false); setFilter('mine')},
    onError: (error) => {setEditorError(true); setEditorStatus(errorMessage(error))},
  })
  const deleteProject = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/vibehub/projects/${encodeURIComponent(editorSlug)}`, {method: 'DELETE'}),
    onMutate: () => setDeleteStatus('正在删除作品…'),
    onSuccess: async () => {setDeleteStatus('作品已删除，正在返回原作品页面…'); await refresh(); setDeleteOpen(false); setEditorOpen(false)},
    onError: (error) => setDeleteStatus(errorMessage(error)),
  })
  const approve = useMutation({
    mutationFn: (decision: 'approve' | 'reject') => {
      if (decision === 'reject' && !approveNote.trim()) throw new Error('请填写审核意见。')
      return apiFetch<ApiEnvelope>(`/api/vibehub/admin/reviews/${encodeURIComponent(String(approveProject?.slug || ''))}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({decision, note: approveNote.trim(), gpu_memory_mib: approvedGpuMemory, expected_version: Number(approveProject?.submitted_version)})})
    },
    onSuccess: async () => {setApproveStatus('正在刷新…'); await refresh(); setApproveProject(null)},
    onError: (error) => setApproveStatus(errorMessage(error)),
  })
  const toggleFeatured = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>(`/api/vibehub/admin/featured/${encodeURIComponent(String(featuredProject?.slug || ''))}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({featured: !Boolean(featuredProject?.is_featured)})}),
    onSuccess: async () => {setFeaturedStatus(Boolean(featuredProject?.is_featured) ? '已取消精品，正在刷新…' : '已设为精品，正在刷新…'); await refresh(); setFeaturedProject(null)},
    onError: (error) => setFeaturedStatus(errorMessage(error)),
  })

  const openCreate = () => {
    editorRequestRef.current?.abort(); editorRequestRef.current = null
    setEditorReview(null)
    setGpuMemory(0)
    setEditorMode('create'); setEditorSlug(''); setTitle(''); setOriginalTitle(''); setPackageFile(null); setEditorStatus(''); setEditorError(false); setEditorLoading(false); setEditorOpen(true)
  }
  const openEdit = async (project: JsonRecord) => {
    const slug = String(project.slug || '')
    editorRequestRef.current?.abort()
    const request = new AbortController()
    editorRequestRef.current = request
    setEditorReview(null)
    setGpuMemory(0)
    setEditorMode('edit'); setEditorSlug(slug); setTitle(''); setOriginalTitle(''); setPackageFile(null); setEditorStatus('正在读取作品信息…'); setEditorError(false); setEditorLoading(true); setEditorOpen(true)
    try {
      const response = await apiFetch<ProjectResponse>(`/api/vibehub/projects/${encodeURIComponent(slug)}?view=latest`, {signal: request.signal})
      if (request.signal.aborted || editorRequestRef.current !== request) return
      setTitle(String(response.project.title || ''))
      setOriginalTitle(String(response.project.title || ''))
      setGpuMemory(Number(response.project.gpu_memory_mib || 0))
      const reviewNote = String(response.project.last_review_note || '').trim()
      setEditorReview(reviewNote ? {version: String(response.project.last_reviewed_version || ''), note: reviewNote} : null)
      setEditorStatus('')
      window.requestAnimationFrame(() => titleRef.current?.focus())
    } catch (error) {
      if (request.signal.aborted || editorRequestRef.current !== request) return
      setEditorError(true); setEditorStatus(errorMessage(error))
    } finally {
      if (editorRequestRef.current === request) {
        editorRequestRef.current = null
        setEditorLoading(false)
      }
    }
  }
  useEffect(() => {
    const slug = initialParams.get('edit')
    const target = result.data?.projects.find((item) => String(item.slug) === slug)
    if (slug && target && !editorOpen) void openEdit(target)
  }, [result.data])

  const projects = useMemo(() => (result.data?.projects || []).filter((item) => {
    const needle = query.trim().toLowerCase()
    const matchesQuery = !needle || `${String(item.title || '')} ${String(item.owner_username || '')}`.toLowerCase().includes(needle)
    const matchesFilter = filter === 'all' || filter === 'featured' && Boolean(item.is_featured) || filter === 'pending' && Boolean(item.can_approve) || filter === 'mine' && Boolean(item.is_mine)
    return matchesQuery && matchesFilter
  }), [filter, query, result.data?.projects])
  if (result.isPending) return <LoadingState label="正在读取 VibeHub" />
  if (result.isError) return <ErrorState message={result.error.message} retry={() => void result.refetch()} />
  const deletePhrase = `我确认要删除 ${originalTitle} 这个作品`
  return <div className="vibe-gallery" data-vibehub-app data-vibe-view="gallery">
    <section className="vibe-catalog" aria-label="VibeHub 作品">
      <header className="vibe-catalog-toolbar">
        <label className="vibe-search"><i className="fas fa-magnifying-glass" /><span className="visually-hidden">搜索游戏</span><input data-vibe-search type="search" placeholder="搜索游戏或作者" value={query} onChange={(event) => setQuery(event.target.value)} autoComplete="off" /><kbd>/</kbd></label>
        <div className="vibe-filter-pills" aria-label="筛选作品"><button type="button" className={filter === 'all' ? 'is-active' : ''} aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>全部</button><button type="button" className={filter === 'featured' ? 'is-active' : ''} aria-pressed={filter === 'featured'} onClick={() => setFilter('featured')}><i className="fas fa-gem" />精品</button>{session?.user?.is_admin ? <button type="button" className={filter === 'pending' ? 'is-active' : ''} aria-pressed={filter === 'pending'} onClick={() => setFilter('pending')}><i className="fas fa-clock" />待审核</button> : null}{session?.user ? <button type="button" className={filter === 'mine' ? 'is-active' : ''} aria-pressed={filter === 'mine'} onClick={() => setFilter('mine')}>我的</button> : null}</div>
        <div className="vibe-toolbar-actions"><Link className="vibe-toolbar-link" to="/vibehub/guide"><i className="fas fa-book-open" /><span>开发者手册</span></Link>{session?.user ? <button className="vibe-create-trigger" type="button" onClick={openCreate} aria-label="创建作品"><i className="fas fa-plus" /><span>创建作品</span></button> : <Link className="vibe-create-trigger" to="/login" aria-label="创建作品"><i className="fas fa-plus" /><span>创建作品</span></Link>}</div>
      </header>
      <div className="vibe-gallery-grid">{projects.map((project, index) => {
        const slug = String(project.slug || project.id || index)
        const owner = String(project.owner_username || 'Numerical OJ')
        const pendingLabel = project.has_pending_review || project.review_status === 'pending' ? '待审核' : project.review_status === 'rejected' || project.latest_review_status === 'rejected' ? '审核未通过' : '待处理'
        return <article className={`vibe-card${project.is_featured ? ' vibe-card--featured' : ''}${project.is_pending ? ' vibe-card--pending' : ''}`} key={slug}>
          <Link className="vibe-card-link" aria-disabled={Boolean(project.runtime_blocked_reason)} onClick={(event) => {if (project.runtime_blocked_reason) {event.preventDefault(); if (project.can_edit) void openEdit(project)}}} to={String(project.play_url || `/vibehub/${encodeURIComponent(slug)}/play`)} aria-label={`打开 ${String(project.title || slug)}${project.is_pending ? `，${pendingLabel}` : ''}`}><span className="vibe-card-cover">{project.cover_url ? <img src={String(project.cover_url)} alt={`${String(project.title || slug)} 封面`} loading="lazy" /> : null}</span>{project.is_pending ? <span className="vibe-card-pending"><i className="fas fa-clock" />{pendingLabel}</span> : null}<span className="vibe-card-caption"><strong>{String(project.title || slug)}</strong><span className="vibe-card-author"><Identicon seed={owner} className="vibe-author-avatar" /><span>{owner}</span></span></span></Link>
          {project.can_manage_featured ? <button className={`vibe-featured-mark vibe-featured-mark--control${project.is_featured ? '' : ' vibe-featured-mark--inactive'}`} type="button" onClick={() => {setFeaturedStatus(''); setFeaturedProject(project)}} aria-label={`${project.is_featured ? '取消精品：' : '设为精品：'}${String(project.title || slug)}`} title={project.is_featured ? '取消精品' : '设为精品'}><i className="fas fa-gem" /></button> : project.is_featured ? <span className="vibe-featured-mark" title="精品" aria-label="精品作品"><i className="fas fa-gem" /></span> : null}
          {project.can_edit || project.can_approve ? <span className="vibe-card-actions">{project.can_edit ? <button type="button" onClick={() => void openEdit(project)} aria-label={`编辑 ${String(project.title || slug)}`} title="编辑作品"><i className="fas fa-pen" /></button> : null}{project.can_approve ? <button type="button" data-vibe-approve-project onClick={() => {setApproveStatus(''); setApproveNote(''); setApprovedGpuMemory(Number(project.gpu_memory_mib || 0)); setApproveProject(project)}} aria-label={`审核 ${String(project.title || slug)}`} title="审核"><i className="fas fa-check" /><span>审核</span></button> : null}</span> : null}
        </article>
      })}</div>
      {!projects.length ? <div className="vibe-empty-state"><i className="fas fa-shapes" /><h2>{result.data?.projects?.length ? '没有找到相符的作品' : '还没有作品'}</h2><p>{result.data?.projects?.length ? '换个关键词或筛选条件再试试。' : '审核通过的作品会出现在这里。'}</p></div> : null}
    </section>

    <dialog ref={editorDialogRef} className="vibe-modal" aria-labelledby="vibeProjectModalTitle" onCancel={(event) => {event.preventDefault(); editorRequestRef.current?.abort(); setEditorOpen(false)}} onClose={() => setEditorOpen(false)}><section className="vibe-modal-panel"><header><div><h2 id="vibeProjectModalTitle">{editorMode === 'edit' ? '编辑作品' : '创建作品'}</h2><p>{editorMode === 'edit' ? '保存修改时构建镜像并自动送审；可选上传新程序包。' : '保存时构建镜像并自动送审。'}</p></div><button ref={editorCloseRef} className="vibe-modal-close" type="button" onClick={() => {editorRequestRef.current?.abort(); setEditorOpen(false)}} aria-label="关闭"><i className="fas fa-xmark" /></button></header><form encType="multipart/form-data" onSubmit={(event: FormEvent) => {event.preventDefault(); saveProject.mutate()}}>
      {editorMode === 'edit' && editorReview ? <aside className="vibe-review-note" aria-label="管理员审核意见"><strong>管理员审核意见{editorReview.version ? ` · v${editorReview.version}` : ''}</strong><p>{editorReview.note}</p></aside> : null}
      <label className="vibe-form-field"><span>游戏名称</span><input ref={titleRef} name="title" required maxLength={120} autoComplete="off" placeholder="给作品起个名字" value={title} onChange={(event) => setTitle(event.target.value)} /></label><label className="vibe-package-field"><input type="file" name="package" required={editorMode === 'create'} accept=".zip,application/zip" onChange={(event) => setPackageFile(event.target.files?.[0] || null)} /><i className="fas fa-file-zipper" /><span><strong>{packageFile?.name || (editorMode === 'edit' ? '保留现有程序包' : '选择 ZIP 程序包')}</strong><small>必须包含 Dockerfile 与 vibehub.json</small></span><b>选择文件</b></label>
      <VibeHubGpuControl value={gpuMemory} onChange={setGpuMemory} label="申请显存" disabled={editorLoading || saveProject.isPending} />
      <p className={`vibe-form-status${editorError ? ' is-error' : ''}`} aria-live="polite">{editorStatus}</p><footer>{editorMode === 'edit' ? <button className="vibe-modal-danger" type="button" disabled={editorLoading || !originalTitle} onClick={() => {editorRequestRef.current?.abort(); setEditorOpen(false); setDeleteText(''); setDeleteStatus(''); setDeleteOpen(true)}}>删除作品</button> : <span />}<button className="vibe-modal-primary" type="submit" disabled={saveProject.isPending || editorLoading || (editorMode === 'edit' && !originalTitle)}>{saveProject.isPending ? '构建并送审中…' : editorMode === 'edit' ? '保存更新并自动送审' : '创建并自动送审'}</button></footer></form></section></dialog>
    <dialog ref={deleteDialogRef} className="vibe-modal" aria-labelledby="vibeDeleteConfirmTitle" aria-describedby="vibeDeleteConfirmDescription vibeDeleteConfirmPhrase" onCancel={(event) => {event.preventDefault(); setDeleteOpen(false); setEditorOpen(true)}} onClose={() => setDeleteOpen(false)}><section className="vibe-modal-panel vibe-modal-panel--confirm"><h2 id="vibeDeleteConfirmTitle">确认删除作品</h2><p id="vibeDeleteConfirmDescription">此操作不可恢复。请输入以下文字后才能删除：</p><p className="vibe-delete-confirm-phrase" id="vibeDeleteConfirmPhrase">{deletePhrase}</p><form onSubmit={(event) => {event.preventDefault(); if (deleteText === deletePhrase) deleteProject.mutate()}}><label className="vibe-form-field vibe-delete-confirm-field"><span>确认文字</span><input type="text" autoComplete="off" required value={deleteText} onChange={(event) => setDeleteText(event.target.value)} /></label><p className={`vibe-form-status${deleteProject.isError ? ' is-error' : ''}`} aria-live="polite">{deleteStatus}</p><footer><button className="vibe-modal-secondary" type="button" onClick={() => {setDeleteOpen(false); setEditorOpen(true)}}>返回编辑</button><button className="vibe-modal-danger vibe-modal-danger--confirm" type="submit" disabled={deleteText !== deletePhrase || deleteProject.isPending}>{deleteProject.isPending ? '删除中…' : '删除作品'}</button></footer></form></section></dialog>
    <dialog ref={approveDialogRef} className="vibe-modal" aria-labelledby="vibeApproveTitle" onCancel={(event) => {event.preventDefault(); setApproveProject(null)}} onClose={() => setApproveProject(null)}><section className="vibe-modal-panel vibe-modal-panel--confirm">
      <h2 id="vibeApproveTitle">审核作品</h2>
      <form onSubmit={(event) => {event.preventDefault(); approve.mutate('approve')}}>
        {Number(approveProject?.gpu_memory_mib || 0) > 0 ? <><p className="vibe-gpu-request">申请显存：{Number(approveProject?.gpu_memory_mib) / 1024} GiB</p><VibeHubGpuControl value={approvedGpuMemory} onChange={setApprovedGpuMemory} label="批准显存" max={Number(approveProject?.gpu_memory_mib)} disabled={approve.isPending} /></> : null}
        <label className="vibe-form-field vibe-review-field"><span>审核意见</span><textarea rows={3} maxLength={2000} value={approveNote} onChange={(event) => setApproveNote(event.target.value)} disabled={approve.isPending} /></label>
        <p className={`vibe-form-status${approve.isError ? ' is-error' : ''}`} aria-live="polite">{approveStatus}</p>
        <footer><button className="vibe-modal-secondary" type="button" onClick={() => setApproveProject(null)}>取消</button><button className="vibe-modal-danger" type="button" disabled={approve.isPending} onClick={() => approve.mutate('reject')}>驳回</button><button ref={approveConfirmRef} className="vibe-modal-primary" type="submit" disabled={approve.isPending}>{approve.isPending ? '处理中…' : '通过'}</button></footer>
      </form>
    </section></dialog>
    <dialog ref={featuredDialogRef} className="vibe-modal" aria-labelledby="vibeFeaturedTitle" aria-describedby="vibeFeaturedDescription" onCancel={(event) => {event.preventDefault(); setFeaturedProject(null)}} onClose={() => setFeaturedProject(null)}><section className="vibe-modal-panel vibe-modal-panel--confirm"><span className="vibe-confirm-icon vibe-confirm-icon--featured"><i className="fas fa-gem" /></span><h2 id="vibeFeaturedTitle">{featuredProject?.is_featured ? '取消精品？' : '设为精品？'}</h2><p id="vibeFeaturedDescription">{featuredProject?.is_featured ? `确认取消“${String(featuredProject?.title || featuredProject?.slug || '')}”的精品资格，并恢复普通作品资源规格。` : `确认将“${String(featuredProject?.title || featuredProject?.slug || '')}”设为精品，并启用精品标记与资源规格。`}</p><p className={`vibe-form-status${toggleFeatured.isError ? ' is-error' : ''}`} aria-live="polite">{featuredStatus}</p><footer><button className="vibe-modal-secondary" type="button" onClick={() => setFeaturedProject(null)}>取消</button><button ref={featuredConfirmRef} className="vibe-modal-primary" type="button" disabled={toggleFeatured.isPending} onClick={() => toggleFeatured.mutate()}>{toggleFeatured.isPending ? featuredProject?.is_featured ? '取消中…' : '设置中…' : featuredProject?.is_featured ? '确认取消精品' : '确认设为精品'}</button></footer></section></dialog>
  </div>
}
