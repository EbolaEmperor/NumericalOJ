import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useState, type ReactNode} from 'react'
import {createPortal} from 'react-dom'

import {apiFetch, errorMessage} from '../../api/client'
import type {ApiEnvelope} from '../../api/types'
import {ChoicePicker} from '../../components/ChoicePicker'
import {DateTimeRangePicker} from '../../components/DateTimeRangePicker'
import {ReactModal} from '../../components/ReactModal'

interface RejudgeOptions extends ApiEnvelope {
  usernames: string[]
  problem_options: {problem_id: number; filter_label: string}[]
  statuses: string[]
}
interface RejudgeResponse extends ApiEnvelope {
  preview?: boolean
  total: number
  confirmation_token?: string
  progress_url?: string
  progress?: number
  done?: number
}
interface RejudgeConditions {
  usernames: string[]
  problem_ids: number[]
  statuses: string[]
  start?: string
  end?: string
}
interface ConfirmedPreview {conditions: RejudgeConditions; response: RejudgeResponse}
const defaultFilters = {usernames: false, problems: false, statuses: true, time: false}

function FilterRow({label, icon, enabled, onToggle, disabled, children}: {label: string; icon: string; enabled: boolean; onToggle: () => void; disabled: boolean; children: ReactNode}) {
  return <div className={`submission-rejudge-filter-row${enabled ? '' : ' is-disabled'}`}><span className="submission-rejudge-filter-icon" title={label}><i className={`fas ${icon}`} aria-hidden="true" /><span className="visually-hidden">{label}</span></span>{children}<button type="button" role="switch" className="submission-rejudge-filter-switch" aria-label={`${label}筛选`} aria-checked={enabled} title={`${label}筛选`} disabled={disabled} onClick={onToggle}><span className="submission-rejudge-switch-track" aria-hidden="true"><span /></span></button></div>
}

export function RejudgeFilters() {
  const queryClient = useQueryClient()
  const [formOpen, setFormOpen] = useState(false)
  const [preview, setPreview] = useState<ConfirmedPreview>()
  const [username, setUsername] = useState('')
  const [problemId, setProblemId] = useState('')
  const [status, setStatus] = useState('Pending')
  const [enabledFilters, setEnabledFilters] = useState(defaultFilters)
  const [start, setStart] = useState('')
  const [end, setEnd] = useState('')
  const [error, setError] = useState('')
  const [progressOpen, setProgressOpen] = useState(false)
  const [progressActive, setProgressActive] = useState(false)
  const [progressTotal, setProgressTotal] = useState(0)
  const [progressUrl, setProgressUrl] = useState('/api/admin/rejudge-ranges/status')
  const progressQueryKey = ['admin', 'rejudge-ranges', 'status', progressUrl] as const
  const options = useQuery({queryKey: ['admin', 'rejudge-ranges', 'options'], queryFn: () => apiFetch<RejudgeOptions>('/api/admin/rejudge-ranges/options'), enabled: formOpen, staleTime: 0})
  const request = useMutation({mutationFn: (body: RejudgeConditions & {confirm_total?: number; confirmation_token?: string}) => apiFetch<RejudgeResponse>('/api/admin/rejudge-ranges', {method: 'POST', body: JSON.stringify(body)})})
  const progress = useQuery({queryKey: progressQueryKey, queryFn: () => apiFetch<RejudgeResponse>(progressUrl), enabled: progressActive, refetchInterval: progressActive ? 1500 : false})
  const percent = Math.min(100, Math.max(0, Number(progress.data?.progress || 0)))
  const done = Number(progress.data?.done || 0)
  const total = Number(progress.data?.total || progressTotal || 0)
  useEffect(() => {
    if (!progressActive) return
    if (percent >= 100) {
      setProgressActive(false)
      void queryClient.invalidateQueries({queryKey: ['submissions']})
      void queryClient.invalidateQueries({queryKey: ['submission-panel']})
    } else if (progress.isError) setProgressActive(false)
  }, [percent, progressActive, progress.isError, queryClient])
  useEffect(() => {if (formOpen && options.isError) setError(`无法读取筛选条件：${errorMessage(options.error)}`)}, [formOpen, options.isError, options.error])

  const closeForm = () => {if (!request.isPending) setFormOpen(false)}
  const openForm = () => {
    setEnabledFilters({...defaultFilters})
    setUsername('')
    setProblemId('')
    setStatus('Pending')
    setStart('')
    setEnd('')
    setPreview(undefined)
    setError('')
    setFormOpen(true)
  }
  const toggleFilter = (filter: keyof typeof defaultFilters) => setEnabledFilters((current) => ({...current, [filter]: !current[filter]}))
  const returnToFilters = () => {if (!request.isPending) {setPreview(undefined); setFormOpen(true); setError('')}}
  const submitFilters = async () => {
    setError('')
    if (options.isError) {await options.refetch(); return}
    if (enabledFilters.usernames && !username) {setError('请选择用户名'); return}
    if (enabledFilters.problems && !problemId) {setError('请选择题目'); return}
    if (enabledFilters.statuses && !status) {setError('请选择状态'); return}
    if (enabledFilters.time && (!start || !end)) {setError('请选择起始时间和结束时间'); return}
    const conditions: RejudgeConditions = {
      usernames: enabledFilters.usernames ? [username] : [],
      problem_ids: enabledFilters.problems ? [Number(problemId)] : [],
      statuses: enabledFilters.statuses ? [status] : [],
      ...(enabledFilters.time ? {start, end} : {}),
    }
    try {
      const response = await request.mutateAsync(conditions)
      if (!response.preview) throw new Error('未收到重测记录预览，请重试')
      setPreview({conditions, response})
      setFormOpen(false)
    } catch (failure) {setError(errorMessage(failure))}
  }
  const confirmRejudge = async () => {
    if (!preview || !preview.response.total || !preview.response.confirmation_token) return
    setError('')
    try {
      const response = await request.mutateAsync({...preview.conditions, confirm_total: preview.response.total, confirmation_token: preview.response.confirmation_token})
      if (response.preview) {setPreview({...preview, response}); return}
      const nextProgressUrl = response.progress_url || '/api/admin/rejudge-ranges/status'
      queryClient.removeQueries({queryKey: ['admin', 'rejudge-ranges', 'status', nextProgressUrl]})
      setProgressUrl(nextProgressUrl)
      void queryClient.invalidateQueries({queryKey: ['submissions']})
      void queryClient.invalidateQueries({queryKey: ['submission-panel']})
      setProgressTotal(response.total)
      setPreview(undefined)
      setProgressActive(true)
      setProgressOpen(true)
    } catch (failure) {setError(errorMessage(failure))}
  }
  const disabled = request.isPending
  const choiceProps = {searchable: true, showIcon: false, disabled}
  const statusChoices = Array.from(new Set(['Pending', ...(options.data?.statuses || [])]))

  return <>
    <button type="button" className="submission-button submission-button--dark" onClick={openForm}><i className="fas fa-rotate-right" aria-hidden="true" /> 重测</button>
    <ReactModal open={formOpen} onClose={closeForm} id="rejudgeFiltersModal" labelledBy="rejudgeFiltersLabel" className="submission-rejudge-modal">
      <div className="modal-content"><div className="modal-header"><h2 className="modal-title submission-rejudge-title" id="rejudgeFiltersLabel">重测</h2><button type="button" className="btn-close" aria-label="关闭" disabled={disabled} onClick={closeForm} /></div>
        <div className="modal-body submission-rejudge-filters">
          <FilterRow label="用户名" icon="fa-user" enabled={enabledFilters.usernames} disabled={disabled} onToggle={() => toggleFilter('usernames')}><ChoicePicker {...choiceProps} key={String(enabledFilters.usernames)} disabled={disabled || !enabledFilters.usernames} placeholder={enabledFilters.usernames ? '未选择' : '全部'} id="rejudgeUsernames" name="usernames" label="用户名" value={enabledFilters.usernames ? username : ''} onChange={setUsername} searchLabel="搜索用户名" searchPlaceholder="搜索用户名…" options={(options.data?.usernames || []).map((username) => ({value: username, label: username, icon: 'fa-user'}))} /></FilterRow>
          <FilterRow label="题目" icon="fa-book-open" enabled={enabledFilters.problems} disabled={disabled} onToggle={() => toggleFilter('problems')}><ChoicePicker {...choiceProps} key={String(enabledFilters.problems)} disabled={disabled || !enabledFilters.problems} placeholder={enabledFilters.problems ? '未选择' : '全部'} id="rejudgeProblems" name="problem_ids" label="题目" value={enabledFilters.problems ? problemId : ''} onChange={setProblemId} searchLabel="搜索题目" searchPlaceholder="按编号或标题搜索题目…" options={(options.data?.problem_options || []).map((problem) => ({value: String(problem.problem_id), label: problem.filter_label, icon: 'fa-book-open'}))} /></FilterRow>
          <FilterRow label="状态" icon="fa-circle" enabled={enabledFilters.statuses} disabled={disabled} onToggle={() => toggleFilter('statuses')}><ChoicePicker {...choiceProps} key={String(enabledFilters.statuses)} disabled={disabled || !enabledFilters.statuses} placeholder={enabledFilters.statuses ? '未选择' : '全部'} id="rejudgeStatuses" name="statuses" label="状态" value={enabledFilters.statuses ? status : ''} onChange={setStatus} searchLabel="搜索状态" searchPlaceholder="搜索状态…" options={statusChoices.map((status) => ({value: status, label: status, icon: 'fa-circle'}))} /></FilterRow>
          <FilterRow label="时间" icon="fa-clock" enabled={enabledFilters.time} disabled={disabled} onToggle={() => toggleFilter('time')}><DateTimeRangePicker key={String(enabledFilters.time)} id="rejudgeTime" label="时间" placeholder={enabledFilters.time ? '未选择' : '全部时间'} start={enabledFilters.time ? start : ''} end={enabledFilters.time ? end : ''} disabled={disabled || !enabledFilters.time} onChange={(nextStart, nextEnd) => {setStart(nextStart); setEnd(nextEnd)}} /></FilterRow>
        </div>
        <div className="modal-footer"><button type="button" className="submission-button submission-button--accent" disabled={disabled || options.isPending} onClick={() => void submitFilters()}>{disabled ? '确认中…' : '确认'}</button></div>
      </div>
    </ReactModal>
    <ReactModal open={Boolean(preview)} onClose={returnToFilters} id="rejudgeConfirmModal" labelledBy="rejudgeConfirmLabel" className="submission-rejudge-modal">
      <div className="modal-content"><div className="modal-header"><h2 className="modal-title submission-rejudge-title" id="rejudgeConfirmLabel">确认重测</h2><button type="button" className="btn-close" aria-label="关闭" disabled={disabled} onClick={returnToFilters} /></div><div className="modal-body submission-rejudge-count" aria-live="polite"><span>符合条件的记录</span><strong>{preview?.response.total || 0}<small> 条</small></strong></div><div className="modal-footer"><button type="button" className="submission-button submission-button--accent" disabled={disabled || !preview?.response.total || !preview.response.confirmation_token} onClick={() => void confirmRejudge()}>{disabled ? '确认中…' : '确认'}</button></div></div>
    </ReactModal>
    <ReactModal open={progressOpen} onClose={() => setProgressOpen(false)} id="rejudgeProgressModal" labelledBy="rejudgeProgressLabel" className="submission-rejudge-modal"><div className="modal-content"><div className="modal-header"><h2 className="modal-title submission-rejudge-title" id="rejudgeProgressLabel">重测进度</h2><button type="button" className="btn-close" aria-label="关闭" onClick={() => setProgressOpen(false)} /></div><div className="modal-body"><div className="progress mb-2"><div className="progress-bar" role="progressbar" style={{width: `${percent}%`}} aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>{percent}%</div></div>{progress.isError ? <div className="alert alert-danger mb-0" role="alert">无法读取重测进度：{progress.error.message}<button type="button" className="btn btn-sm btn-outline-danger ms-2" onClick={() => {setProgressActive(true); void progress.refetch()}}>重试</button></div> : <p className="small text-muted mb-0">已完成 {done} / {total}</p>}</div><div className="modal-footer"><button type="button" className="submission-button submission-button--ghost" onClick={() => setProgressOpen(false)}>关闭</button></div></div></ReactModal>
    {error ? createPortal(<div className="submission-rejudge-error" role="alert"><span>{error}</span><button type="button" aria-label="关闭错误提示" onClick={() => setError('')}><i className="fas fa-xmark" aria-hidden="true" /></button></div>, document.body) : null}
  </>
}
