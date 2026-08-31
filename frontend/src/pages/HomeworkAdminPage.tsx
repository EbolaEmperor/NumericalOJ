import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useMemo, useRef, useState, type FormEvent} from 'react'
import {createPortal} from 'react-dom'
import {useSearchParams} from 'react-router-dom'

import {apiFetch, errorMessage, queryString} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {Link} from '../components/PageNavigation'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'
import {useSession} from '../session'

interface Response extends ApiEnvelope {
  classes: JsonRecord[]
  selected_class?: string
  homework_list: JsonRecord[]
  all_problems: JsonRecord[]
  all_competitions: JsonRecord[]
}

interface ProgressResponse extends ApiEnvelope {progress?: JsonRecord}
interface RecordsResponse extends ApiEnvelope {records: JsonRecord[]; count: number}
type DialogName = 'add' | 'edit-deadline' | 'codes' | 'plagiarism' | 'records' | 'exam' | null

function dateTimeValue(value: unknown) {
  const text = String(value || '')
  const httpDate = text.match(/^[A-Za-z]{3},\s+(\d{2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}:\d{2})/)
  if (httpDate) {
    const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].indexOf(httpDate[2]) + 1
    return `${httpDate[3]}-${String(month).padStart(2, '0')}-${httpDate[1]}T${httpDate[4]}`
  }
  const normalized = text.replace(' ', 'T')
  return normalized.length >= 16 ? normalized.slice(0, 16) : normalized
}

function displayDateTime(value: unknown) {
  const text = dateTimeValue(value)
  return text ? text.replace('T', ' ') : '未设置'
}

function plagiarismTitle(value: unknown) {
  const fallback = '题目'
  let title = String(value || fallback).trim()
  title = title.replace(/^(\s*(?:题目|Problem)\s*)?#?\d+(?:[._/-]\d+)*\s*(?:[:：\-—–]\s*)?(?:「[^」]*」\s*)+/i, (_all, label: string | undefined) => label ? `${label.trimEnd()} ` : '')
  title = title.replace(/^(\s*(?:题目|Problem)\s*)(?:「[^」]*」\s*)+/i, (_all, prefix: string) => `${prefix.trimEnd()} `)
  title = title.replace(/^\s*(?:「[^」]*」\s*)+/, '')
  return title.replace(/\s{2,}/g, ' ').trim() || fallback
}

function PlagiarismRule({value}: {value: unknown}) {
  const rule = String(value || '').trim()
  if (rule === 'byte-identical') return <span className="plagiarism-rule-badge plagiarism-rule-byte"><i className="fas fa-fingerprint" />字节级</span>
  const parsed = Number.parseFloat(rule)
  if (Number.isFinite(parsed)) {
    const percent = parsed <= 1 ? parsed * 100 : parsed
    return <span className="plagiarism-rule-badge plagiarism-rule-threshold"><i className="fas fa-percent" />{percent.toFixed(0)}%</span>
  }
  return <span className="plagiarism-rule-badge plagiarism-rule-threshold"><i className="fas fa-sliders-h" />{rule}</span>
}

function ClassChoice({value, classes, onChange}: {value: string; classes: JsonRecord[]; onChange: (value: string) => void}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = classes.find((item) => String(item.class_en) === value)
  const options = [{class_en: '', class_cn: '请选择'}, ...classes]
  return <div ref={rootRef} className={`rk-choice${open ? ' open' : ''}`}><input className="rk-choice-value" value={value} readOnly tabIndex={-1} aria-hidden="true" /><button id="homeworkClassPickerTrigger" type="button" className="rk-choice-trigger" role="combobox" aria-haspopup="listbox" aria-expanded={open} aria-label="选择班级" onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main"><i className="fas fa-users" /><span>{String(selected?.class_cn || '请选择')}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox">{options.map((item) => {const optionValue = String(item.class_en || ''); return <button type="button" className={`rk-choice-option${optionValue === value ? ' active' : ''}`} role="option" aria-selected={optionValue === value} key={optionValue || 'none'} onClick={() => {onChange(optionValue); setOpen(false)}}><span className="rk-choice-option-main"><i className="fas fa-users" /><span className="rk-choice-option-name">{String(item.class_cn || '请选择')}</span></span><i className="fas fa-check rk-choice-option-check" /></button>})}</div></div>
}

function Modal({title, onClose, children, footer, modalClassName = '', dialogClassName = '', contentClassName = '', headerClassName = '', titleClassName = '', bodyClassName = '', footerClassName = ''}: {title: React.ReactNode; onClose: () => void; children: React.ReactNode; footer?: React.ReactNode; modalClassName?: string; dialogClassName?: string; contentClassName?: string; headerClassName?: string; titleClassName?: string; bodyClassName?: string; footerClassName?: string}) {
  const modalRef = useRef<HTMLDivElement | null>(null)
  useEffect(() => {modalRef.current?.focus({preventScroll: true})}, [])
  return createPortal(<div className="numoj-content" style={{display: 'contents'}}><div ref={modalRef} className={`modal fade show d-block${modalClassName ? ` ${modalClassName}` : ''}`} role="dialog" aria-modal="true" tabIndex={-1}>
    <div className={`modal-dialog${dialogClassName ? ` ${dialogClassName}` : ''}`}>
      <div className={`modal-content${contentClassName ? ` ${contentClassName}` : ''}`}>
        <div className={`modal-header${headerClassName ? ` ${headerClassName}` : ''}`}><h5 className={`modal-title${titleClassName ? ` ${titleClassName}` : ''}`}>{title}</h5><button type="button" className="btn-close" onClick={onClose} aria-label="关闭" /></div>
        <div className={`modal-body${bodyClassName ? ` ${bodyClassName}` : ''}`}>{children}</div>
        {footer ? <div className={`modal-footer${footerClassName ? ` ${footerClassName}` : ''}`}>{footer}</div> : null}
      </div>
    </div>
  </div><div className="modal-backdrop fade show" /></div>, document.body)
}

export default function HomeworkAdminPage() {
  const {session} = useSession()
  const queryClient = useQueryClient()
  const [params, setParams] = useSearchParams()
  const selectedClass = params.get('sclass') || ''
  const [dialog, setDialog] = useState<DialogName>(null)
  const [kind, setKind] = useState<'problem' | 'ranking'>('problem')
  const [target, setTarget] = useState('')
  const [targetSearch, setTargetSearch] = useState('')
  const [targetMenuOpen, setTargetMenuOpen] = useState(false)
  const targetMenuRef = useDismissibleDropdown<HTMLDivElement>(targetMenuOpen, () => setTargetMenuOpen(false))
  const [deadline, setDeadline] = useState('')
  const [editingHomework, setEditingHomework] = useState<JsonRecord | null>(null)
  const [exportTask, setExportTask] = useState('')
  const [plagiarismTask, setPlagiarismTask] = useState('')
  const [plagiarismMode, setPlagiarismMode] = useState<'threshold' | 'byte'>('threshold')
  const [threshold, setThreshold] = useState('90')
  const [plagiarismTargets, setPlagiarismTargets] = useState<string[]>([])
  const [selectedRecords, setSelectedRecords] = useState<number[]>([])
  const [examFile, setExamFile] = useState<File | null>(null)

  const page = useQuery({
    queryKey: ['admin', 'homework', selectedClass],
    queryFn: () => apiFetch<Response>(`/api/admin/homework${queryString({sclass: selectedClass})}`),
    enabled: Boolean(session?.user?.is_admin),
  })
  const refresh = () => queryClient.invalidateQueries({queryKey: ['admin', 'homework']})
  const add = useMutation({
    mutationFn: () => {
      const body = new FormData()
      body.append('class_en', selectedClass)
      body.append('ddl', deadline)
      body.append(kind === 'problem' ? 'problem_id' : 'ranking_competition_id', target)
      return apiFetch<ApiEnvelope>('/api/admin/homework', {method: 'POST', body})
    },
    onSuccess: async () => {setDialog(null); setTarget(''); setDeadline(''); await refresh()},
  })
  const remove = useMutation({
    mutationFn: (homeworkId: number) => apiFetch<ApiEnvelope>('/api/admin/homework', {method: 'DELETE', body: JSON.stringify({class_en: selectedClass, homework_id: homeworkId})}),
    onSuccess: async () => {setDialog(null); setEditingHomework(null); await refresh()},
  })
  const updateDeadline = useMutation({
    mutationFn: ({id, ddl}: {id: number; ddl: string}) => apiFetch<ApiEnvelope>('/api/admin/homework/deadline', {method: 'POST', body: JSON.stringify({class_en: selectedClass, homework_id: id, new_ddl: ddl})}),
    onSuccess: refresh,
  })
  const startExport = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope & {task_id?: string}>('/api/admin/homework/exports/code', {method: 'POST', body: JSON.stringify({sclass: selectedClass})}),
    onSuccess: (data) => {setExportTask(String(data.task_id || '')); setDialog('codes')},
  })
  const exportProgress = useQuery({
    queryKey: ['admin', 'homework', 'export', exportTask],
    queryFn: () => apiFetch<ProgressResponse>(`/api/admin/homework/exports/${encodeURIComponent(exportTask)}`),
    enabled: Boolean(exportTask && dialog === 'codes'),
    refetchInterval: exportTask && dialog === 'codes' ? 1200 : false,
  })
  const startPlagiarism = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope & {task_id?: string}>('/api/admin/homework/plagiarism/start', {
      method: 'POST',
      body: JSON.stringify({class_en: selectedClass, mode: plagiarismMode, threshold: Number(threshold), targets: plagiarismTargets}),
    }),
    onSuccess: (data) => setPlagiarismTask(String(data.task_id || '')),
  })
  const plagiarismProgress = useQuery({
    queryKey: ['admin', 'homework', 'plagiarism-progress', plagiarismTask],
    queryFn: () => apiFetch<ProgressResponse>(`/api/admin/homework/plagiarism/progress/${encodeURIComponent(plagiarismTask)}`),
    enabled: Boolean(plagiarismTask && dialog === 'plagiarism'),
    refetchInterval: plagiarismTask && dialog === 'plagiarism' ? 1200 : false,
  })
  const records = useQuery({
    queryKey: ['admin', 'homework', 'plagiarism-records', selectedClass],
    queryFn: () => apiFetch<RecordsResponse>(`/api/admin/homework/plagiarism/records${queryString({class_en: selectedClass})}`),
    enabled: Boolean(selectedClass && dialog === 'records'),
  })
  const deleteRecords = useMutation({
    mutationFn: () => apiFetch<ApiEnvelope>('/api/admin/homework/plagiarism/delete', {method: 'POST', body: JSON.stringify({class_en: selectedClass, record_ids: selectedRecords})}),
    onSuccess: async () => {setSelectedRecords([]); await queryClient.invalidateQueries({queryKey: ['admin', 'homework', 'plagiarism-records', selectedClass]})},
  })
  const uploadExam = useMutation({
    mutationFn: () => {
      if (!examFile) throw new Error('请选择成绩文件')
      const body = new FormData()
      body.append('class_en', selectedClass)
      body.append('file', examFile)
      return apiFetch<ApiEnvelope>('/api/admin/exam-scores/import', {method: 'POST', body})
    },
    onSuccess: () => setExamFile(null),
  })

  const homeworkTargets = useMemo(() => (page.data?.homework_list || []).map((item) => {
    const ranking = Boolean(item.is_ranking || item.ranking_competition_id)
    const id = Number(ranking ? item.ranking_competition_id : item.problem_id)
    return {value: `${ranking ? 'ranking' : 'problem'}:${id}`, label: `${ranking ? 'R' : 'P'}${id} · ${String(item.problem_title || '')}`, ranking}
  }).filter((item) => item.value && Number.isFinite(Number(item.value.split(':')[1]))), [page.data?.homework_list])
  const availableTargets = kind === 'problem' ? (page.data?.all_problems || []) : (page.data?.all_competitions || [])
  const filteredTargets = availableTargets.filter((item) => {
    const needle = targetSearch.trim().toLowerCase()
    return !needle || String(item.id || '').includes(needle) || String(item.title || '').toLowerCase().includes(needle)
  }).slice(0, 50)

  if (!session?.user?.is_admin) return <ErrorState message="该页面仅管理员可访问" />
  if (page.isPending) return <LoadingState label="正在读取作业管理" />
  if (page.isError) return <ErrorState message={page.error.message} />

  const submitAdd = (event: FormEvent) => {event.preventDefault(); if (target && deadline) add.mutate()}
  const exportStage = exportProgress.data?.progress || {}
  const plagiarismStage = plagiarismProgress.data?.progress || {}
  const operationError = add.error || remove.error || updateDeadline.error || startExport.error

  return <section className="homework-admin-page">
    <h2><i className="fas fa-tasks me-2" /> 作业管理</h2>
    <div className="container">
      <div className="card mb-4"><div className="card-body"><div className="row g-3 align-items-center"><div className="col-auto"><label htmlFor="homeworkClassPickerTrigger" className="form-label">选择班级：</label></div><div className="col-auto" style={{minWidth: 220}}><ClassChoice value={selectedClass} classes={page.data.classes} onChange={(value) => {setParams(value ? {sclass: value} : {}); setDialog(null)}} /></div></div></div></div>
      {selectedClass ? <>
        <div className="mb-3 homework-admin-actions">
          <button className="btn btn-outline-success" type="button" onClick={() => setDialog('add')}><i className="fas fa-plus me-2" />布置新作业</button>
          <a href={`/api/admin/homework/exports/scores?sclass=${encodeURIComponent(selectedClass)}`} download className="btn btn-outline-primary ms-2"><i className="fas fa-download me-2" />导出成绩</a>
          <button className="btn btn-outline-secondary ms-2" type="button" disabled={startExport.isPending} onClick={() => startExport.mutate()}><i className="fas fa-code me-2" />导出学生代码</button>
          <button className="btn btn-outline-danger ms-2" type="button" onClick={() => {setPlagiarismTargets(homeworkTargets.filter((item) => !item.ranking).map((item) => item.value)); setPlagiarismTask(''); setDialog('plagiarism')}}><i className="fas fa-user-slash me-2" />标记抄袭</button>
          <button className="btn btn-outline-dark ms-2" type="button" onClick={() => setDialog('records')}><i className="fas fa-exclamation-triangle me-2" />抄袭记录</button>
          <button className="btn btn-outline-warning ms-2" type="button" onClick={() => setDialog('exam')}><i className="fas fa-file-upload me-2" />上传期末成绩</button>
        </div>
        <div className="card"><div className="card-body"><table className="table table-hover"><thead><tr><th><i className="fas fa-hashtag me-2" /> 题目ID</th><th><i className="fas fa-book me-2" /> 题目名称</th><th><i className="fas fa-clock me-2" /> 截止时间</th><th><i className="fas fa-user me-2" /> 完成人数</th><th><i className="fas fa-cogs me-2" /> 操作</th></tr></thead><tbody>{page.data.homework_list.map((item) => <tr key={String(item.id)}><td>{item.is_ranking ? <span className="text-muted">#{String(item.ranking_competition_id)}</span> : String(item.problem_id || '')}</td><td>{item.is_ranking ? <span className="badge bg-warning text-dark me-1">打榜赛</span> : null}{String(item.problem_title || '')}</td><td>{displayDateTime(item.ddl)}</td><td>{String(item.complete_cnt || 0)}</td><td><button className="btn btn-sm btn-outline-primary" type="button" onClick={() => {setEditingHomework(item); setDeadline(dateTimeValue(item.ddl)); setDialog('edit-deadline')}}><i className="fas fa-edit me-2" />修改DDL</button> <button className="btn btn-sm btn-outline-danger" type="button" disabled={remove.isPending} onClick={() => {if (window.confirm('确定要删除此作业吗？')) remove.mutate(Number(item.id))}}><i className="fas fa-trash-alt me-2" />删除作业</button></td></tr>)}{!page.data.homework_list.length ? <tr><td colSpan={6} className="text-center text-muted">暂无作业</td></tr> : null}</tbody></table></div></div>
      </> : null}
      {operationError ? <div className="alert alert-danger mt-3">{errorMessage(operationError)}</div> : null}
    </div>

    {dialog === 'edit-deadline' && editingHomework ? <Modal title="修改截止时间" onClose={() => {setDialog(null); setEditingHomework(null)}} footer={<><button type="button" className="btn btn-secondary" onClick={() => {setDialog(null); setEditingHomework(null)}}>取消</button><button type="button" className="btn btn-primary" disabled={!deadline || updateDeadline.isPending} onClick={() => updateDeadline.mutate({id: Number(editingHomework.id), ddl: deadline})}>保存修改</button></>}><div className="mb-3"><label className="form-label" htmlFor="editDDLInput">新截止时间</label><input id="editDDLInput" type="datetime-local" className="form-control" value={deadline} onChange={(event) => setDeadline(event.target.value)} required /></div></Modal> : null}

    {dialog === 'add' ? <Modal title="布置新作业" onClose={() => {setDialog(null); setTargetMenuOpen(false)}} footer={<><button type="button" className="btn btn-secondary" onClick={() => setDialog(null)}>取消</button><button type="submit" form="homeworkAddForm" className="btn btn-primary" disabled={!target || add.isPending}>{add.isPending ? '正在保存…' : '确认添加'}</button></>}><form id="homeworkAddForm" onSubmit={submitAdd}><div className="mb-3"><label className="form-label d-block">作业类型</label><div className="btn-group" role="group"><input type="radio" className="btn-check" name="hwtype" id="hwTypeProblemSpa" value="problem" checked={kind === 'problem'} onChange={() => {setKind('problem'); setTarget(''); setTargetSearch(''); setTargetMenuOpen(false)}} /><label className="btn btn-outline-primary btn-sm" htmlFor="hwTypeProblemSpa">题目</label><input type="radio" className="btn-check" name="hwtype" id="hwTypeRankingSpa" value="ranking" checked={kind === 'ranking'} onChange={() => {setKind('ranking'); setTarget(''); setTargetSearch(''); setTargetMenuOpen(false)}} /><label className="btn btn-outline-primary btn-sm" htmlFor="hwTypeRankingSpa">打榜赛</label></div></div><div ref={targetMenuRef} className="mb-3 position-relative"><label className="form-label" htmlFor="hwSearchSpa">选择{kind === 'ranking' ? '打榜赛' : '题目'}</label><input id="hwSearchSpa" type="text" className="form-control" autoComplete="off" placeholder={`按编号或标题搜索${kind === 'ranking' ? '打榜赛' : '题目'}…`} value={targetSearch} onFocus={() => setTargetMenuOpen(true)} onChange={(event) => {setTarget(''); setTargetSearch(event.target.value); setTargetMenuOpen(true)}} />{targetMenuOpen && filteredTargets.length ? <div className="list-group position-absolute w-100 shadow-sm" style={{zIndex: 1080, maxHeight: 240, overflow: 'auto'}}>{filteredTargets.map((item) => <button type="button" className="list-group-item list-group-item-action py-2" key={String(item.id)} onClick={() => {setTarget(String(item.id)); setTargetSearch(`#${String(item.id)} ${String(item.title || '')}`); setTargetMenuOpen(false)}}><span className="text-muted me-2">#{String(item.id)}</span>{String(item.title || '')}</button>)}</div> : null}<div className="form-text">{target ? `已选择：#${target} ${String(availableTargets.find((item) => String(item.id) === target)?.title || '')}` : ''}</div></div><div className="mb-3"><label className="form-label">截止时间</label><input type="datetime-local" className="form-control" value={deadline} onChange={(event) => setDeadline(event.target.value)} required /></div>{add.isError ? <div className="alert alert-danger mb-0">{errorMessage(add.error)}</div> : null}</form></Modal> : null}

    {dialog === 'codes' ? <Modal title={<><i className="fas fa-tasks me-2" />导出学生代码</>} dialogClassName="modal-dialog-centered" onClose={() => setDialog(null)} footer={<><button type="button" className="btn btn-secondary" onClick={() => setDialog(null)}>取消</button>{String(exportStage.stage) === 'completed' ? <a className="btn btn-success" href={`/api/admin/homework/exports/${encodeURIComponent(exportTask)}/download`} download><i className="fas fa-download me-2" />下载文件</a> : null}</>}><p className="mb-2">{String(exportStage.message || '正在启动任务...')}</p><div className="progress" style={{height: 20}} role="progressbar" aria-valuenow={Number(exportStage.percentage || 0)} aria-valuemin={0} aria-valuemax={100}><div className="progress-bar" style={{width: `${Number(exportStage.percentage || 0)}%`}}>{Number(exportStage.percentage || 0)}%</div></div>{exportProgress.isError ? <div className="alert alert-danger mt-3 mb-0">{errorMessage(exportProgress.error)}</div> : null}</Modal> : null}

    {dialog === 'plagiarism' ? <Modal title={<><i className="fas fa-user-slash me-2" />标记抄袭</>} dialogClassName="modal-lg" onClose={() => setDialog(null)} footer={<><button type="button" className="btn btn-secondary" onClick={() => setDialog(null)}>关闭</button><button type="button" className="btn btn-danger" disabled={!plagiarismTargets.length || startPlagiarism.isPending || Boolean(plagiarismTask)} onClick={() => startPlagiarism.mutate()}><i className="fas fa-play me-2" />{startPlagiarism.isPending ? '正在启动…' : '开始'}</button></>}>
      {!plagiarismTask ? <><div className="mb-3"><label className="form-label d-block">查重规则</label><div className="btn-group" role="group"><input type="radio" className="btn-check" id="plagiarismThresholdSpa" checked={plagiarismMode === 'threshold'} onChange={() => {setPlagiarismMode('threshold'); setPlagiarismTargets((items) => items.filter((item) => item.startsWith('problem:')))}} /><label className="btn btn-outline-primary" htmlFor="plagiarismThresholdSpa">查重阈值</label><input type="radio" className="btn-check" id="plagiarismByteSpa" checked={plagiarismMode === 'byte'} onChange={() => setPlagiarismMode('byte')} /><label className="btn btn-outline-primary" htmlFor="plagiarismByteSpa">字节级一致</label></div></div>{plagiarismMode === 'threshold' ? <div className="mb-3"><label className="form-label">阈值（%）</label><input className="form-control" type="number" min="1" max="100" step="1" value={threshold} onChange={(event) => setThreshold(event.target.value)} /></div> : null}<div className="d-flex justify-content-between align-items-center mb-2"><label className="form-label mb-0">作业题</label><div><button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setPlagiarismTargets(homeworkTargets.filter((item) => !(item.ranking && plagiarismMode === 'threshold')).map((item) => item.value))}>全选</button><button type="button" className="btn btn-sm btn-outline-secondary ms-1" onClick={() => setPlagiarismTargets([])}>清空</button></div></div><div className="border rounded p-3" style={{maxHeight: 260, overflow: 'auto'}}>{homeworkTargets.map((item) => <div className="form-check" key={item.value}><input className="form-check-input" id={`plagiarism-${item.value}`} type="checkbox" value={item.value} checked={plagiarismTargets.includes(item.value)} disabled={item.ranking && plagiarismMode === 'threshold'} onChange={(event) => setPlagiarismTargets((items) => event.target.checked ? [...items, item.value] : items.filter((value) => value !== item.value))} /><label className="form-check-label" htmlFor={`plagiarism-${item.value}`}>{item.ranking ? <span className="badge bg-warning text-dark me-1">打榜赛</span> : null}<span className="text-muted">#{item.value.split(':')[1]}</span> {item.label.replace(/^.[0-9]+ · /, '')}</label></div>)}{!homeworkTargets.length ? <div className="text-muted">暂无可查重的作业</div> : null}</div>{startPlagiarism.isError ? <div className="alert alert-danger mt-3 mb-0">{errorMessage(startPlagiarism.error)}</div> : null}</> : <><p className="mb-2">{String(plagiarismStage.message || '查重任务已经启动…')}</p><div className="progress" style={{height: 20}} role="progressbar" aria-valuenow={Number(plagiarismStage.percentage || 0)} aria-valuemin={0} aria-valuemax={100}><div className="progress-bar bg-danger" style={{width: `${Number(plagiarismStage.percentage || 0)}%`}}>{Number(plagiarismStage.percentage || 0)}%</div></div>{plagiarismProgress.isError ? <div className="alert alert-danger mt-3 mb-0">{errorMessage(plagiarismProgress.error)}</div> : null}</>}
    </Modal> : null}

    {dialog === 'records' ? <Modal
      title={<><span className="plagiarism-records-title-icon"><i className="fas fa-exclamation-triangle" /></span>抄袭记录</>}
      onClose={() => setDialog(null)}
      modalClassName="plagiarism-records-modal"
      dialogClassName="modal-xl modal-dialog-scrollable plagiarism-records-dialog"
      contentClassName="plagiarism-records-content"
      headerClassName="plagiarism-records-header"
      titleClassName="plagiarism-records-title"
      bodyClassName="plagiarism-records-body"
      footerClassName="plagiarism-records-footer"
      footer={<button type="button" className="btn btn-sm btn-light plagiarism-records-action" onClick={() => setDialog(null)}>关闭</button>}
    >
      <div className="plagiarism-records-toolbar">
        <div className="plagiarism-records-count"><i className="fas fa-list-ul" /><span>{records.isPending ? '加载中...' : records.isError ? '加载失败' : `共 ${records.data.count} 条记录`}</span></div>
        <div className="plagiarism-records-actions">
          <a className="btn btn-sm btn-light plagiarism-records-action" href={`/api/admin/homework/plagiarism/download?class_en=${encodeURIComponent(selectedClass)}`} download><i className="fas fa-download" />下载</a>
          <button type="button" className="btn btn-sm btn-light plagiarism-records-action plagiarism-records-action-danger" disabled={!selectedRecords.length || deleteRecords.isPending} onClick={() => {if (window.confirm('确定删除选中的抄袭记录吗？')) deleteRecords.mutate()}}><i className="fas fa-trash-alt" />删除</button>
        </div>
      </div>
      <div className="table-responsive plagiarism-records-table-wrap">
        <table className="table table-sm align-middle plagiarism-records-table"><thead><tr><th className="plagiarism-select-col"><input className="form-check-input" type="checkbox" aria-label="全选抄袭记录" checked={Boolean(records.data?.records.length) && selectedRecords.length === records.data?.records.length} onChange={(event) => setSelectedRecords(event.target.checked ? (records.data?.records || []).map((item) => Number(item.id)) : [])} /></th><th>记录ID</th><th>用户</th><th>题目</th><th>提交ID</th><th><i className="fas fa-balance-scale me-1" />比较规则</th><th>相同用户名</th><th>标记时间</th></tr></thead><tbody>
          {records.isPending ? <tr><td colSpan={8}><div className="plagiarism-records-state"><span className="math-curve-loader" data-math-curve-loader data-size="sm"><span className="math-curve-loader__label">加载中…</span></span></div></td></tr> : records.isError ? <tr><td colSpan={8}><div className="plagiarism-records-state text-danger"><i className="fas fa-times-circle" /><span>加载失败</span></div></td></tr> : records.data.records.length ? records.data.records.map((item) => {
            const matched = Array.isArray(item.matched_usernames) ? item.matched_usernames : String(item.matched_usernames_text || '').split(/[、,]/).map((value) => value.trim()).filter(Boolean)
            const submissionHref = item.target_kind === 'ranking' ? `/rankings/${String(item.competition_id || item.problem_id)}?tab=all_submissions${item.username ? `&q=${encodeURIComponent(String(item.username))}` : ''}` : `/submissions/${String(item.submission_id || '')}`
            return <tr key={String(item.id)}><td className="plagiarism-select-col"><input className="form-check-input plagiarism-record-checkbox" type="checkbox" value={String(item.id)} aria-label={`选择记录 ${String(item.id)}`} checked={selectedRecords.includes(Number(item.id))} onChange={(event) => setSelectedRecords((values) => event.target.checked ? [...values, Number(item.id)] : values.filter((value) => value !== Number(item.id)))} /></td><td><span className="plagiarism-record-id">#{String(item.id)}</span></td><td><div className="plagiarism-user-main">{String(item.username || '')}</div></td><td><div className="plagiarism-problem-main">{plagiarismTitle(item.problem_title)}</div></td><td><Link className="plagiarism-submission-link" to={submissionHref}>#{String(item.submission_id || '')}</Link></td><td><PlagiarismRule value={item.comparison_rule} /></td><td><div className="plagiarism-match-list">{matched.map((username) => <span className="plagiarism-match-chip" key={String(username)}>{String(username)}</span>)}</div></td><td><span className="plagiarism-time">{String(item.created_at || '')}</span></td></tr>
          }) : <tr><td colSpan={8}><div className="plagiarism-records-state"><i className="fas fa-inbox" /><span>暂无抄袭记录</span></div></td></tr>}
        </tbody></table>
      </div>
      {deleteRecords.isError ? <div className="alert alert-danger m-3">{errorMessage(deleteRecords.error)}</div> : null}
    </Modal> : null}

    {dialog === 'exam' ? <Modal title="上传期末成绩（Excel）" onClose={() => setDialog(null)} footer={<><button type="button" className="btn btn-secondary" onClick={() => setDialog(null)}>取消</button><button type="button" className="btn btn-primary" disabled={!examFile || uploadExam.isPending} onClick={() => uploadExam.mutate()}>{uploadExam.isPending ? '正在上传…' : '上传'}</button></>}><div className="alert alert-info" role="alert">请选择包含两列（学号、成绩）的 .xlsx / .xls 文件。</div><div className="mb-3"><label className="form-label">选择文件</label><input className="form-control" type="file" accept=".xlsx,.xls" onChange={(event) => setExamFile(event.target.files?.[0] || null)} /></div>{uploadExam.isSuccess ? <div className="alert alert-success mt-3 mb-0">成绩已成功导入。</div> : null}{uploadExam.isError ? <div className="alert alert-danger mt-3 mb-0">{errorMessage(uploadExam.error)}</div> : null}</Modal> : null}
  </section>
}
