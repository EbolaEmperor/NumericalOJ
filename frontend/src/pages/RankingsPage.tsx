import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {type FormEvent} from 'react'
import {Link, useNavigate} from 'react-router-dom'

import {apiFetch} from '../api/client'
import type {ApiEnvelope, CompetitionSummary} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface Response extends ApiEnvelope {competitions: CompetitionSummary[]; count: number}

export default function RankingsPage() {
  const {session} = useSession()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const result = useQuery({queryKey: ['rankings'], queryFn: () => apiFetch<Response>('/api/ranking/competitions')})
  const create = useMutation({
    mutationFn: (body: FormData) => apiFetch<ApiEnvelope & {competition_id?: number; path?: string}>('/api/ranking/competitions', {method: 'POST', body}),
    onSuccess: async (data) => {await queryClient.invalidateQueries({queryKey: ['rankings']}); navigate(data.path || `/rankings/${data.competition_id}`)},
  })
  const copy = useMutation({
    mutationFn: (competitionId: number) => apiFetch<ApiEnvelope>(`/api/ranking/competitions/${competitionId}/copy`, {method: 'POST'}),
    onSuccess: async () => {await queryClient.invalidateQueries({queryKey: ['rankings']})},
  })
  const submitCreate = (event: FormEvent<HTMLFormElement>) => {event.preventDefault(); create.mutate(new FormData(event.currentTarget))}
  if (result.isPending) return <LoadingState label="正在读取赛场状态" />
  if (result.isError) return <ErrorState message={result.error.message} />
  const competitions = result.data?.competitions || []
  const active = competitions.filter((item) => Number(item.is_active) === 1).length
  return <>
    <header className="ranking-list-heading" aria-labelledby="rankingListTitle"><p>RANKING · LIST</p><div><h1 id="rankingListTitle">打榜赛</h1><span>{competitions.length} COMPETITIONS · {active} ACTIVE</span></div></header>
    {!competitions.length ? <div className="ranking-empty"><i className="fas fa-trophy ranking-empty-icon mb-3" /><h4 className="mb-2">暂无打榜赛</h4></div> : <div className="row g-3 ranking-grid">{competitions.map((competition) => <div className="col-12 col-md-6 col-lg-4" key={competition.id}><div className="ranking-card-wrap"><Link to={`/rankings/${competition.id}`} className={`ranking-card${Number(competition.is_active) === 1 ? '' : ' is-inactive'}`}><div className="ranking-card-body"><div className="d-flex justify-content-between align-items-start mb-2 gap-2"><h5 className="ranking-card-title mb-0">{competition.title}</h5>{Number(competition.is_active) === 1 ? <span className="badge ranking-badge-active flex-shrink-0"><i className="fas fa-circle me-1" />进行中</span> : <span className="badge bg-secondary flex-shrink-0">已下线</span>}</div><div className="ranking-card-desc">{competition.summary || String(competition.description || '').slice(0, 160) || <span className="fst-italic text-muted">暂无摘要</span>}</div><div className="ranking-stats mt-3"><div className="ranking-stat"><div className="ranking-stat-value">{Number(competition.participant_count || 0)}</div><div className="ranking-stat-label"><i className="fas fa-user-friends me-1" />参赛</div></div><div className="ranking-stat"><div className="ranking-stat-value">{Number(competition.submission_count || 0)}</div><div className="ranking-stat-label"><i className="fas fa-paper-plane me-1" />提交</div></div><div className="ranking-stat"><div className="ranking-stat-value">{String(competition.scoring_mode || 'absolute').toLowerCase() === 'elo' ? 'ELO' : Number(competition.max_score || 100)}</div><div className="ranking-stat-label"><i className={`fas ${String(competition.scoring_mode || '').toLowerCase() === 'elo' ? 'fa-chess-knight' : 'fa-star'} me-1`} />{String(competition.scoring_mode || '').toLowerCase() === 'elo' ? '动态评分' : '满分'}</div></div></div></div><div className="ranking-card-footer"><span className="ranking-card-meta"><i className="far fa-clock me-1" />{String(competition.created_at || '')}</span>{competition.created_by ? <span className="ranking-card-meta"><i className="far fa-user me-1" />{String(competition.created_by)}</span> : null}</div></Link>{session?.user?.is_admin ? <form onSubmit={(event) => {event.preventDefault(); copy.mutate(Number(competition.id))}}><button type="submit" className="ranking-card-copy" title="复制为非公开副本" aria-label={`复制 ${competition.title} 为非公开副本`} disabled={copy.isPending}><i className="far fa-copy" aria-hidden="true" /></button></form> : null}</div></div>)}</div>}
    {session?.user?.is_admin ? <>
      <button type="button" className="ranking-create-fab" data-bs-toggle="modal" data-bs-target="#newCompetitionModal" aria-label="创建打榜赛" title="创建打榜赛"><i className="fas fa-plus" aria-hidden="true" /></button>
      <div className="modal fade" id="newCompetitionModal" tabIndex={-1} aria-labelledby="newCompetitionLabel" aria-hidden="true"><div className="modal-dialog modal-lg"><div className="modal-content"><form onSubmit={submitCreate}><div className="modal-header"><h5 className="modal-title" id="newCompetitionLabel"><i className="fas fa-trophy me-2" /> 创建打榜赛</h5><button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="关闭" /></div><div className="modal-body"><div className="mb-3"><label className="form-label">比赛标题</label><input type="text" className="form-control" name="title" required maxLength={255} placeholder="例如：2026 春季数值优化打榜赛" /></div><div className="mb-3"><label className="form-label">摘要</label><textarea className="form-control" name="summary" rows={2} maxLength={500} placeholder="一句话介绍本场打榜赛（展示在列表卡片上，最多 500 字）" /></div><div className="mb-3"><label className="form-label">满分</label><input type="number" className="form-control" name="max_score" defaultValue="100" min="1" max="100000" /></div><div className="mb-3"><label className="form-label">赛事描述（支持 Markdown）</label><textarea className="form-control" name="description" rows={6} placeholder="简介、规则、数据说明……" /></div>{create.isError ? <div className="alert alert-danger">{create.error.message}</div> : null}</div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" data-bs-dismiss="modal">取消</button><button type="submit" className="btn btn-primary" disabled={create.isPending}><i className="fas fa-check me-1" /> {create.isPending ? '正在创建…' : '创建'}</button></div></form></div></div></div>
    </> : null}
  </>
}
