import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useMemo, useState, type FormEvent} from 'react'
import {Link, useNavigate, useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {ModelLogo} from '../components/ModelLogo'
import {MonacoEditor} from '../components/MonacoEditor'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface FormResponse extends ApiEnvelope {
  action: string
  defaults?: JsonRecord
  form?: JsonRecord
  problem?: JsonRecord
  options: {
    languages: string[]
    problem_types: Array<{value: string; label: string}>
    programming_grading_modes: Array<{value: number; label: string}>
    default_written_grading_prompt: string
    llm_endpoint_candidates: Record<string, JsonRecord[]>
  }
}

function Choice({value, options, icon, disabled = false, onChange}: {value: string; options: Array<{value: string; label: string; icon?: string; model?: string}>; icon: string; disabled?: boolean; onChange: (value: string) => void}) {
  const [open, setOpen] = useState(false)
  const selected = options.find((option) => option.value === value) || options[0]
  const optionIcon = (option?: {icon?: string; model?: string}) => option?.model ? <ModelLogo model={option.model} /> : <i className={`fas ${option?.icon || icon}`} />
  return <div className={`rk-choice${open ? ' open' : ''}${disabled ? ' is-disabled' : ''}`}><input type="text" className="rk-choice-value" value={value} readOnly tabIndex={-1} aria-hidden="true" /><button type="button" className="rk-choice-trigger" role="combobox" aria-haspopup="listbox" aria-expanded={open} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main">{optionIcon(selected)}<span>{selected?.label || value}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox">{options.map((option) => <button type="button" className={`rk-choice-option${option.value === value ? ' active' : ''}`} role="option" aria-selected={option.value === value} onClick={() => {onChange(option.value); setOpen(false)}} key={option.value}><span className="rk-choice-option-main">{optionIcon(option)}<span><span className="rk-choice-option-name">{option.label}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div>
}

function EndpointChoice({name, label, value, items, help, onChange}: {name: string; label: string; value: string; items: JsonRecord[]; help?: string; onChange: (value: string) => void}) {
  const options = [{value: '', label: '未配置', icon: 'fa-minus-circle'}, ...items.map((item) => ({value: String(item.id || ''), label: String(item.model || item.name || `节点 #${item.id}`), model: String(item.model || item.name || '')}))]
  return <div><label className="form-label" htmlFor={`${name}Picker`}><i className="fas fa-plug me-2" /> {label}</label><Choice value={value} options={options} icon="fa-microchip" onChange={onChange} />{help ? <div className="form-text">{help}</div> : null}</div>
}

function asString(value: unknown, fallback = '') {return value == null ? fallback : String(value)}

export default function ProblemEditorPage() {
  const {problemId} = useParams()
  const editing = Boolean(problemId)
  const numericId = Number(problemId || 0)
  const {session} = useSession()
  const navigate = useNavigate()
  const query = useQuery({queryKey: ['admin', 'problem-form', problemId || 'new'], queryFn: () => apiFetch<FormResponse>(editing ? `/api/admin/problems/${numericId}/edit-form` : '/api/admin/problems/create-form'), enabled: Boolean(session?.user?.is_admin)})
  const seed = query.data?.form || query.data?.defaults
  const [values, setValues] = useState<Record<string, string>>({})
  const [testCodeTouched, setTestCodeTouched] = useState(false)
  const set = (key: string, value: string) => setValues((current) => ({...current, [key]: value}))
  useEffect(() => {
    if (!seed) return
    const next: Record<string, string> = {}
    Object.entries(seed).forEach(([key, value]) => {if (!['object', 'undefined'].includes(typeof value) || value === null) next[key] = asString(value)})
    if (!editing && next.time_limit === '2000') next.time_limit = '10000'
    const promptly = seed.promptly_review_config as JsonRecord | undefined
    next.promptly_brief = asString(promptly?.brief)
    next.promptly_prompt_requirements = asString(promptly?.prompt_requirements)
    next.promptly_example_replies_json = JSON.stringify(promptly?.example_replies || [])
    setTestCodeTouched(false)
    setValues(next)
  }, [editing, seed])
  useEffect(() => {document.title = `${editing ? '编辑题目' : '添加题目'} - Numerical OJ`}, [editing])

  const type = values.type || asString(query.data?.problem?.type, '1')
  const language = values.lang || 'matlab'
  const programmingMode = values.programming_grading_mode || '1'
  const writtenMode = values.written_grading_mode || '1'
  const endpointCandidates = query.data?.options.llm_endpoint_candidates || {}
  const languages = useMemo(() => (query.data?.options.languages || []).map((item) => ({
    value: item,
    label: item === 'cpp' ? 'C++' : item === 'python' || item === 'py' ? 'Python' : item === 'lean4' ? 'Lean 4' : item.toUpperCase(),
  })), [query.data])
  const mutation = useMutation({
    mutationFn: () => {
      const body = new FormData()
      Object.entries(values).forEach(([key, value]) => body.append(key, value))
      body.set('type', type)
      body.set('lang', language)
      body.set('programming_grading_mode', programmingMode)
      body.set('written_grading_mode', writtenMode)
      return apiFetch<ApiEnvelope & {problem_id?: number}>(query.data?.action || (editing ? `/api/admin/problems/${numericId}` : '/api/admin/problems'), {method: 'POST', body})
    },
    onSuccess: (data) => navigate(`/problems/${editing ? numericId : Number(data.problem_id)}`),
  })
  const submit = (event: FormEvent) => {event.preventDefault(); mutation.mutate()}

  if (!session?.user?.is_admin) return <ErrorState message="该页面仅管理员可访问" />
  if (query.isPending || !seed) return <LoadingState label="正在读取题目配置" />
  if (query.isError) return <ErrorState message={query.error.message} />
  const typeOptions = query.data.options.problem_types.map((item) => ({value: String(item.value), label: item.label}))
  const programmingModeOptions = query.data.options.programming_grading_modes.map((item) => ({value: String(item.value), label: item.label}))
  const writtenModeOptions = [{value: '1', label: 'OCR + 文本批改'}, {value: '2', label: '直接批改图片'}, {value: '3', label: 'tex 文本批改'}, {value: '4', label: '纯人工批改'}]
  const examples = (() => {try {const parsed = JSON.parse(values.promptly_example_replies_json || '[]'); return Array.isArray(parsed) ? parsed.map(String) : []} catch {return []}})()
  const setExamples = (items: string[]) => set('promptly_example_replies_json', JSON.stringify(items))

  return <section className="numoj-problem-editor-page">
    <h2><i className="fas fa-pencil-alt me-2" /> {editing ? '编辑题目' : '添加新题目'}</h2>
    {mutation.isError ? <div className="alert alert-danger" role="alert">{errorMessage(mutation.error)}</div> : null}
    <form id={editing ? 'editProblemForm' : 'addProblemForm'} onSubmit={submit}>
      {editing && type === '1' ? <div className="row mb-3">
        <div className="col-md-4"><label htmlFor="titleInput" className="form-label"><i className="fas fa-heading me-2" /> 题目标题</label><input type="text" className="form-control" id="titleInput" name="title" required value={values.title || ''} onChange={(event) => set('title', event.target.value)} /></div>
        <div className="col-md-2"><label className="form-label"><i className="fas fa-language me-2" /> 语言</label><Choice value={language} options={languages} icon="fa-code" onChange={(value) => set('lang', value)} /></div>
        <div className="col-md-3"><label htmlFor="timeLimitInput" className="form-label"><i className="fas fa-stopwatch me-2" /> {language === 'lean4' ? '证明验证时限' : '时限'} (ms)</label><input type="number" className="form-control" id="timeLimitInput" name="time_limit" min={1} required value={values.time_limit || '2000'} onChange={(event) => set('time_limit', event.target.value)} /></div>
        <div className="col-md-3"><label htmlFor="submissionLimitInput" className="form-label"><i className="fas fa-check-circle me-2" /> 提交限制</label><input type="number" className="form-control" id="submissionLimitInput" min={1} required value={values.submission_limit || '10'} onChange={(event) => set('submission_limit', event.target.value)} /></div>
      </div> : editing ? <div className="row mb-3">
        <div className="col-md-3"><label htmlFor="titleInput" className="form-label"><i className="fas fa-heading me-2" /> 题目标题</label><input type="text" className="form-control" id="titleInput" name="title" required value={values.title || ''} onChange={(event) => set('title', event.target.value)} /></div>
        <div className="col-md-3"><label className="form-label"><i className="fas fa-sliders me-2" /> 批改模式</label><Choice value={writtenMode} options={writtenModeOptions} icon="fa-sliders" onChange={(value) => set('written_grading_mode', value)} /></div>
        <div className="col-md-3"><label className="form-label"><i className="fas fa-check-circle me-2" /> 提交限制</label><input type="number" className="form-control" min={1} value={values.submission_limit || '10'} onChange={(event) => set('submission_limit', event.target.value)} /></div>
      </div> : <div className="row mb-3">
        <div className="col-md-6"><label htmlFor="titleInput" className="form-label"><i className="fas fa-heading me-2" /> 题目标题</label><input type="text" className="form-control" id="titleInput" name="title" required value={values.title || ''} onChange={(event) => set('title', event.target.value)} /></div>
        <div className="col-md-3"><label className="form-label"><i className="fas fa-question me-2" /> 题目类型</label><Choice value={type} options={typeOptions} icon="fa-question" onChange={(value) => set('type', value)} /></div>
        {type === '1' ? <div className="col-md-3"><label className="form-label"><i className="fas fa-language me-2" /> 语言</label><Choice value={language} options={languages} icon="fa-code" onChange={(value) => set('lang', value)} /></div> : null}
      </div>}
      {type === '1' ? <>
        {language === 'lean4' && !editing ? <div className="alert alert-info mb-3">Lean 4 题目的源码、只读权限和验证入口由独立 ZIP 题目包管理。先创建题目，再从题目详情页上传包含 <code>numoj-lean.json</code> 的题目包。</div> : null}
        {!editing ? <div className="row mb-3"><div className="col-md-6"><label htmlFor="timeLimitInput" className="form-label"><i className="fas fa-stopwatch me-2" /> {language === 'lean4' ? '证明验证时限' : '测试点时限'} (毫秒 ms)</label><input type="number" className="form-control" id="timeLimitInput" name="time_limit" min={1} required value={values.time_limit || '10000'} onChange={(event) => set('time_limit', event.target.value)} /></div><div className="col-md-6"><label htmlFor="submissionLimitInput" className="form-label"><i className="fas fa-check-circle me-2" /> 提交次数限制</label><input type="number" className="form-control" id="submissionLimitInput" min={1} required value={values.submission_limit || '10'} onChange={(event) => set('submission_limit', event.target.value)} /></div></div> : null}
        {language !== 'lean4' ? <div className="row g-3 mb-3"><div className={editing ? 'col-md-4' : 'col-md-6'}><label className="form-label"><i className="fas fa-sliders me-2" /> 批改模式</label><Choice value={programmingMode} options={programmingModeOptions} icon="fa-sliders" onChange={(value) => set('programming_grading_mode', value)} /></div>{programmingMode === '2' ? <><div className={editing ? 'col-md-4' : 'col-md-6'}><label className="form-label"><i className="fas fa-image me-2" /> 输出图片文件名</label><input className="form-control" value={values.output_image_filename || 'output.png'} onChange={(event) => set('output_image_filename', event.target.value)} /><div className="form-text">仅支持 png、jpg、jpeg、bmp、gif 或 webp 图片。</div></div><div className={editing ? 'col-md-4' : 'col-md-6'}><EndpointChoice name="output_image_grading_endpoint_id" label="输出图片批改端点" value={values.output_image_grading_endpoint_id || ''} items={endpointCandidates.output_image_grading_endpoint_id || []} onChange={(value) => set('output_image_grading_endpoint_id', value)} /></div></> : null}</div> : null}
        {programmingMode === '2' ? <div className="mb-3"><label className="form-label"><i className="fas fa-list-check me-2" /> 评分标准</label><textarea className="form-control" rows={6} value={values.programming_grading_prompt || ''} onChange={(event) => set('programming_grading_prompt', event.target.value)} /></div> : null}
        {programmingMode === '3' ? <><div className="row g-3 mb-3"><div className="col-md-6"><EndpointChoice name="review_endpoint_id" label="Promptly 审查端点" value={values.review_endpoint_id || ''} items={endpointCandidates.review_endpoint_id || []} help="用于审查学生 Prompt。" onChange={(value) => set('review_endpoint_id', value)} /></div><div className="col-md-6"><EndpointChoice name="code_generation_endpoint_id" label="Promptly 代码生成端点" value={values.code_generation_endpoint_id || ''} items={endpointCandidates.code_generation_endpoint_id || []} help="用于根据通过审查的 Prompt 生成代码。" onChange={(value) => set('code_generation_endpoint_id', value)} /></div></div><div className="border rounded p-3 mb-3"><div className="mb-3"><label className="form-label"><i className="fas fa-align-left me-2" /> 简要题意</label><textarea className="form-control" rows={3} value={values.promptly_brief || ''} onChange={(event) => set('promptly_brief', event.target.value)} /></div><div className="mb-3"><label className="form-label"><i className="fas fa-list-check me-2" /> Prompt 要求</label><textarea className="form-control" rows={4} value={values.promptly_prompt_requirements || ''} onChange={(event) => set('promptly_prompt_requirements', event.target.value)} /></div><div className="d-flex align-items-center justify-content-between mb-2"><label className="form-label mb-0"><i className="fas fa-comments me-2" /> 示例回复</label><button type="button" className="btn btn-outline-secondary btn-sm" onClick={() => setExamples([...examples, ''])}><i className="fas fa-plus me-1" /> 添加</button></div><div className="d-grid gap-2">{examples.map((example, index) => <div className="input-group" key={index}><textarea className="form-control" rows={2} value={example} onChange={(event) => setExamples(examples.map((item, itemIndex) => itemIndex === index ? event.target.value : item))} /><button className="btn btn-outline-danger" type="button" onClick={() => setExamples(examples.filter((_, itemIndex) => itemIndex !== index))}><i className="fas fa-trash" /></button></div>)}</div></div></> : null}
      </> : <>{!editing ? <><p>书面作业：学生将通过提交文件来完成作业，老师需要人工批改。</p><div className="row g-3 mb-3"><div className="col-md-4"><label className="form-label"><i className="fas fa-sliders me-2" /> 批改模式</label><Choice value={writtenMode} options={writtenModeOptions} icon="fa-sliders" onChange={(value) => set('written_grading_mode', value)} /></div>{['1'].includes(writtenMode) ? <div className="col-md-4"><EndpointChoice name="ocr_endpoint_id" label="OCR 端点" value={values.ocr_endpoint_id || ''} items={endpointCandidates.ocr_endpoint_id || []} onChange={(value) => set('ocr_endpoint_id', value)} /></div> : null}{['1', '3'].includes(writtenMode) ? <div className="col-md-4"><EndpointChoice name="text_grading_endpoint_id" label="文本 / TeX 批改端点" value={values.text_grading_endpoint_id || ''} items={endpointCandidates.text_grading_endpoint_id || []} onChange={(value) => set('text_grading_endpoint_id', value)} /></div> : null}{writtenMode === '2' ? <div className="col-md-4"><EndpointChoice name="direct_image_grading_endpoint_id" label="图片直接批改端点" value={values.direct_image_grading_endpoint_id || ''} items={endpointCandidates.direct_image_grading_endpoint_id || []} onChange={(value) => set('direct_image_grading_endpoint_id', value)} /></div> : null}</div></> : <div className="row g-3 mb-3">{['1'].includes(writtenMode) ? <div className="col-md-4"><EndpointChoice name="ocr_endpoint_id" label="OCR 端点" value={values.ocr_endpoint_id || ''} items={endpointCandidates.ocr_endpoint_id || []} onChange={(value) => set('ocr_endpoint_id', value)} /></div> : null}{['1', '3'].includes(writtenMode) ? <div className="col-md-4"><EndpointChoice name="text_grading_endpoint_id" label="文本 / TeX 批改端点" value={values.text_grading_endpoint_id || ''} items={endpointCandidates.text_grading_endpoint_id || []} onChange={(value) => set('text_grading_endpoint_id', value)} /></div> : null}{writtenMode === '2' ? <div className="col-md-4"><EndpointChoice name="direct_image_grading_endpoint_id" label="图片直接批改端点" value={values.direct_image_grading_endpoint_id || ''} items={endpointCandidates.direct_image_grading_endpoint_id || []} onChange={(value) => set('direct_image_grading_endpoint_id', value)} /></div> : null}</div>}{writtenMode !== '4' ? <div className="mb-3"><label className="form-label"><i className="fas fa-list-check me-2" /> 评分标准</label><textarea className="form-control" rows={6} placeholder="例如：步骤完整性 2 分、关键结论正确性 2 分、表达规范性 1 分；若缺失边界条件，最多给 4 分。" value={values.written_grading_prompt || (!editing ? query.data.options.default_written_grading_prompt : '') || ''} onChange={(event) => set('written_grading_prompt', event.target.value)} /></div> : null}{!editing ? <div className="mb-3"><label className="form-label"><i className="fas fa-check-circle me-2" /> 提交次数限制</label><input type="number" className="form-control" min={1} value={values.submission_limit || '10'} onChange={(event) => set('submission_limit', event.target.value)} /></div> : null}</>}
      <div className="mb-3"><label htmlFor="contentTextArea" className="form-label"><i className="fab fa-markdown me-2" /> 题面 (Markdown + LaTeX)</label><textarea className="form-control" id="contentTextArea" rows={10} required value={values.content || ''} onChange={(event) => set('content', event.target.value)} /><small className="text-muted">可使用 Markdown + LaTeX 语法；如行内公式可用 $...$ 或 \(...\)。</small></div>
      {editing && type === '1' && language === 'lean4' ? <div className="alert alert-info">Lean 4 文件和验证契约由独立题目包管理。请保存题面与时限后，从题目详情页上传或更新 ZIP 题目包。</div> : null}
      {type === '1' && language !== 'lean4' ? <><div className="row mb-3"><div className="col-md-6"><label className="form-label"><i className="fas fa-code me-2" /> 初始代码 (可选)</label><div className="card numoj-form-code-editor-card"><div className="card-body p-0"><MonacoEditor idPrefix="initial" ariaLabel="初始代码编辑器" language={language} problemId={numericId} value={values.initial_code || ''} onChange={(value) => set('initial_code', value)} /></div></div><small className="text-muted">这段代码会在提交页面的代码编辑框中预先显示。</small></div><div className="col-md-6"><label className="form-label"><i className="fas fa-code me-2" /> 交互库代码 (可选)</label><div className="card numoj-form-code-editor-card"><div className="card-body p-0"><MonacoEditor idPrefix="test" ariaLabel="交互库代码编辑器" language={language} problemId={numericId} value={values.test_code || (editing && !testCodeTouched && query.data.problem?.test_code == null ? 'None' : '')} onChange={(value) => {setTestCodeTouched(true); set('test_code', value)}} /></div></div><small className="text-muted">{editing ? <>这段代码用作交互库/模板。学生代码将粘贴到 <code>%%user_code_here</code>。</> : <>这段代码用作交互库/评测模板。学生代码将会粘贴到 <code>%%user_code_here</code> 所在位置。</>}</small></div></div><div className="mb-3"><label className="form-label"><i className="fas fa-ban me-2" /> 禁用函数 (可选)</label><input type="text" className="form-control" placeholder="例如：system, popen, fork" value={values.forbidden_func || ''} onChange={(event) => set('forbidden_func', event.target.value)} /><small className="text-muted">可以输入多个函数名，用逗号分隔。</small></div></> : null}
      {editing ? <div className="mb-3"><label className="form-label"><i className="fas fa-question-circle me-2" /> 题目类型</label><Choice value={type} options={typeOptions} icon="fa-question" disabled onChange={() => {}} /><small className="text-muted">题目类型一旦创建后无法修改。</small></div> : null}
      <button type="submit" className={`btn ${editing ? 'btn-outline-primary' : 'btn-outline-success'}`} disabled={mutation.isPending}><i className="fas fa-check" /> {mutation.isPending ? '正在保存…' : editing ? '保存修改' : '确认添加'}</button>{editing ? <> <Link to={`/problems/${numericId}`} className="btn btn-outline-secondary"><i className="fas fa-times" /> 放弃修改</Link></> : null}
    </form>
  </section>
}
