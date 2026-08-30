import {useQuery} from '@tanstack/react-query'
import {useMemo, useState} from 'react'

import {apiFetch} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface Response extends ApiEnvelope {projects: JsonRecord[]; count: number}

export default function VibeHubPage() {
  const {session} = useSession()
  const result = useQuery({queryKey: ['vibehub'], queryFn: () => apiFetch<Response>('/api/vibehub/projects')})
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const projects = useMemo(() => (result.data?.projects || []).filter((item) => {
    const needle = query.trim().toLowerCase()
    const matchesQuery = !needle || `${String(item.title || '')} ${String(item.owner_username || '')}`.toLowerCase().includes(needle)
    const matchesFilter = filter === 'all' || filter === 'featured' && Boolean(item.is_featured) || filter === 'pending' && Boolean(item.can_approve) || filter === 'mine' && Boolean(item.is_mine)
    return matchesQuery && matchesFilter
  }), [filter, query, result.data?.projects])
  if (result.isPending) return <LoadingState label="正在读取 VibeHub" />
  if (result.isError) return <ErrorState message={result.error.message} />
  return <div className="vibe-gallery" data-vibehub-app data-vibe-view="gallery">
    <section className="vibe-catalog" aria-label="VibeHub 作品">
      <header className="vibe-catalog-toolbar">
        <label className="vibe-search"><i className="fas fa-magnifying-glass" /><span className="visually-hidden">搜索游戏</span><input type="search" placeholder="搜索游戏或作者" value={query} onChange={(event) => setQuery(event.target.value)} autoComplete="off" /><kbd>/</kbd></label>
        <div className="vibe-filter-pills" aria-label="筛选作品"><button type="button" className={filter === 'all' ? 'is-active' : ''} onClick={() => setFilter('all')}>全部</button><button type="button" className={filter === 'featured' ? 'is-active' : ''} onClick={() => setFilter('featured')}><i className="fas fa-gem" />精品</button>{session?.user?.is_admin ? <button type="button" className={filter === 'pending' ? 'is-active' : ''} onClick={() => setFilter('pending')}><i className="fas fa-clock" />待审核</button> : null}<button type="button" className={filter === 'mine' ? 'is-active' : ''} onClick={() => setFilter('mine')}>我的</button></div>
        <div className="vibe-toolbar-actions"><a className="vibe-toolbar-link" href="/vibehub/guide"><i className="fas fa-book-open" /><span>开发者手册</span></a><a className="vibe-create-trigger" href="/vibehub?create=1" aria-label="创建作品"><i className="fas fa-plus" /><span>创建作品</span></a></div>
      </header>
      <div className="vibe-gallery-grid">{projects.map((project, index) => {
        const slug = String(project.slug || project.id || index)
        const owner = String(project.owner_username || 'Numerical OJ')
        return <article className={`vibe-card${project.is_featured ? ' vibe-card--featured' : ''}${project.is_pending ? ' vibe-card--pending' : ''}`} key={slug}><a className="vibe-card-link" href={String(project.play_url || `/vibehub/${slug}`)} aria-label={`打开 ${String(project.title || slug)}`}><span className="vibe-card-cover">{project.cover_url ? <img src={String(project.cover_url)} alt={`${String(project.title || slug)} 封面`} loading="lazy" /> : null}</span>{project.is_pending ? <span className="vibe-card-pending"><i className="fas fa-clock" />待审核</span> : null}<span className="vibe-card-caption"><strong>{String(project.title || slug)}</strong><span className="vibe-card-author"><span className="numoj-avatar vibe-author-avatar" aria-hidden="true">{owner.slice(0, 2).toUpperCase()}</span><span>{owner}</span></span></span></a>{project.is_featured ? <span className="vibe-featured-mark" title="精品"><i className="fas fa-gem" /></span> : null}</article>
      })}</div>
      {!projects.length ? <div className="vibe-empty-state"><i className="fas fa-shapes" /><h2>{result.data?.projects?.length ? '没有找到相符的作品' : '还没有作品'}</h2><p>{result.data?.projects?.length ? '换个关键词或筛选条件再试试。' : '审核通过的作品会出现在这里。'}</p></div> : null}
    </section>
  </div>
}
