import {useMutation, useQuery} from '@tanstack/react-query'
import {useEffect, useMemo, useState, type FormEvent} from 'react'
import {useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord} from '../api/types'
import {MarkdownContent} from '../components/MarkdownContent'
import {ModelLogo} from '../components/ModelLogo'
import {MonacoEditor} from '../components/MonacoEditor'
import {Link, useNavigate} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'
import {useDismissibleDropdown} from '../components/useDismissibleDropdown'
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

interface MarkdownPreviewResponse extends ApiEnvelope {rendered_content?: string}

const editorIconPaths: Record<string, string[]> = {
  title: ['M12 20h9', 'M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z'],
  statement: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z', 'M14 2v6h6M8 13h8M8 17h6'],
  edit: ['M12 20h9', 'M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z'],
  preview: ['M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z', 'M12 14.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z'],
  settings: ['M4 6h10M18 6h2M4 12h2M10 12h10M4 18h7M15 18h5'],
  ocr: ['M8 3H5a2 2 0 0 0-2 2v3M16 3h3a2 2 0 0 1 2 2v3M3 16v3a2 2 0 0 0 2 2h3M21 16v3a2 2 0 0 1-2 2h-3', 'M7 9h10M7 13h10M7 17h6'],
  judges: ['M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2', 'M8.5 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75'],
  rubric: ['M8 6h12M8 12h12M8 18h12', 'm3 6 1.5 1.5L6.5 5M3 12l1.5 1.5L6.5 11M3 18l1.5 1.5L6.5 17'],
  image: ['M3 5h18v14H3Z', 'm3 16 4-4 3 3 4-5 5 6M8 9h.01'],
  code: ['m8 9-3 3 3 3M16 9l3 3-3 3M14 5l-4 14'],
}

function EditorIcon({name}: {name: string}) {
  return <svg className="problem-editor-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{(editorIconPaths[name] || []).map((path, index) => <path d={path} key={index} />)}</svg>
}

function Choice({value, options, icon, disabled = false, onChange}: {value: string; options: Array<{value: string; label: string; icon?: string; model?: string}>; icon: string; disabled?: boolean; onChange: (value: string) => void}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = options.find((option) => option.value === value) || options[0]
  const optionIcon = (option?: {icon?: string; model?: string}) => option?.model ? <ModelLogo model={option.model} /> : <i className={`fas ${option?.icon || icon}`} />
  return <div ref={rootRef} className={`rk-choice${open ? ' open' : ''}${disabled ? ' is-disabled' : ''}`}><input type="text" className="rk-choice-value" value={value} readOnly tabIndex={-1} aria-hidden="true" /><button type="button" className="rk-choice-trigger" role="combobox" aria-haspopup="listbox" aria-expanded={open} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main">{optionIcon(selected)}<span>{selected?.label || value}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox">{options.map((option) => <button type="button" className={`rk-choice-option${option.value === value ? ' active' : ''}`} role="option" aria-selected={option.value === value} onClick={() => {onChange(option.value); setOpen(false)}} key={option.value}><span className="rk-choice-option-main">{optionIcon(option)}<span><span className="rk-choice-option-name">{option.label}</span></span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div>
}

function EndpointChoice({name, label, value, items, onChange}: {name: string; label: string; value: string; items: JsonRecord[]; onChange: (value: string) => void}) {
  const options = [{value: '', label: '未配置', icon: 'fa-minus-circle'}, ...items.map((item) => ({value: String(item.id || ''), label: String(item.model || item.name || `节点 #${item.id}`), model: String(item.model || item.name || '')}))]
  return <div className="problem-editor-field"><span id={`${name}PickerLabel`}>{label}</span><Choice value={value} options={options} icon="fa-microchip" onChange={onChange} /></div>
}

interface WrittenVoteRow {endpoint_id: string; count: number}

function WrittenVoteEditor({rows, items, onChange}: {rows: WrittenVoteRow[]; items: JsonRecord[]; onChange: (rows: WrittenVoteRow[]) => void}) {
  const options = [{value: '', label: '选择评委模型', icon: 'fa-minus-circle'}, ...items.map((item) => ({value: String(item.id || ''), label: `${String(item.model || '未命名模型')} · #${String(item.id || '')}`, model: String(item.model || '')}))]
  const total = rows.reduce((sum, row) => sum + (row.endpoint_id ? row.count : 0), 0)
  const updateCount = (index: number, count: number) => onChange(rows.map((item, rowIndex) => rowIndex === index ? {...item, count: Math.max(1, Math.min(5, count || 1))} : item))
  return <section className="aje written-vote-editor mb-3" aria-label="AI 评委配置"><div className="aje-shell"><div className="aje-head"><div className="aje-title"><EditorIcon name="judges" />AI 评委 Vote</div><div className="aje-head-tools"><div className="aje-meta"><span className="aje-count">{rows.length} 个评委</span><span className={`aje-total${total > 10 ? ' is-invalid' : ''}`}>票数 <b>{total}</b></span></div><button type="button" className="aje-add" title="添加评委模型" aria-label="添加评委模型" disabled={rows.length >= 10} onClick={() => onChange([...rows, {endpoint_id: '', count: 1}])}><i className="fas fa-plus" /></button></div></div><div className="aje-grid">{rows.map((row, index) => <article className="aje-card written-vote-card" key={index}><div className="aje-card-top"><span className="written-vote-card-index">评委 {String(index + 1).padStart(2, '0')}</span><button type="button" className="written-vote-remove" title={`删除评委模型 ${index + 1}`} aria-label={`删除评委模型 ${index + 1}`} disabled={rows.length === 1} onClick={() => onChange(rows.filter((_, rowIndex) => rowIndex !== index))}><i className="fas fa-trash-can" /></button></div><div className="aje-card-main written-vote-card-main"><Choice value={row.endpoint_id} options={options} icon="fa-microchip" onChange={(value) => onChange(rows.map((item, rowIndex) => rowIndex === index ? {...item, endpoint_id: value} : item))} /></div><div className="written-vote-card-footer"><div className="written-vote-stepper" role="group" aria-label={`评委模型 ${index + 1} Vote 次数`}><button type="button" aria-label={`减少评委模型 ${index + 1} Vote 次数`} disabled={row.count <= 1} onClick={() => updateCount(index, row.count - 1)}><i className="fas fa-minus" /></button><input id={`writtenVoteCount${index}`} type="text" inputMode="numeric" pattern="[1-5]" role="spinbutton" aria-label={`评委模型 ${index + 1} Vote 次数`} aria-valuemin={1} aria-valuemax={5} aria-valuenow={row.count} value={row.count} onChange={(event) => updateCount(index, Number(event.target.value))} /><span>票</span><button type="button" aria-label={`增加评委模型 ${index + 1} Vote 次数`} disabled={row.count >= 5} onClick={() => updateCount(index, row.count + 1)}><i className="fas fa-plus" /></button></div></div></article>)}</div></div></section>
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
  const [writtenVoteRows, setWrittenVoteRows] = useState<WrittenVoteRow[]>([{endpoint_id: '', count: 1}])
  const [testCodeTouched, setTestCodeTouched] = useState(false)
  const [previewOpen, setPreviewOpen] = useState(false)
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
    const configuredVotes = Array.isArray(seed.written_vote_config) ? seed.written_vote_config as JsonRecord[] : []
    const seedWrittenMode = asString(seed.written_grading_mode, '1')
    const fallbackEndpoint = asString(seedWrittenMode === '2' ? seed.direct_image_grading_endpoint_id : seed.text_grading_endpoint_id)
    setWrittenVoteRows(configuredVotes.length ? configuredVotes.map((item) => ({endpoint_id: asString(item.endpoint_id), count: Number(item.count || 1)})) : [{endpoint_id: fallbackEndpoint, count: 1}])
    setTestCodeTouched(false)
    setValues(next)
  }, [editing, seed])
  useEffect(() => {document.title = `${editing ? '编辑题目' : '添加题目'} - Numerical OJ`}, [editing])

  const type = values.type || asString(query.data?.problem?.type, '1')
  const language = values.lang || 'matlab'
  const programmingMode = values.programming_grading_mode || '1'
  const writtenMode = values.written_grading_mode || '1'
  const endpointCandidates = query.data?.options.llm_endpoint_candidates || {}
  const writtenVoteCandidates = writtenMode === '2' ? endpointCandidates.direct_image_grading_endpoint_id || [] : endpointCandidates.text_grading_endpoint_id || []
  const changeWrittenMode = (nextMode: string) => {
    if (writtenMode !== '4' && nextMode !== '4' && (writtenMode === '2') !== (nextMode === '2')) {
      setWrittenVoteRows([{endpoint_id: '', count: 1}])
    }
    set('written_grading_mode', nextMode)
  }
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
      body.set('written_vote_config', JSON.stringify(writtenMode === '4' ? [] : writtenVoteRows.filter((row) => row.endpoint_id).map((row) => ({endpoint_id: Number(row.endpoint_id), count: row.count}))))
      return apiFetch<ApiEnvelope & {problem_id?: number}>(query.data?.action || (editing ? `/api/admin/problems/${numericId}` : '/api/admin/problems'), {method: 'POST', body})
    },
    onSuccess: (data) => navigate(`/problems/${editing ? numericId : Number(data.problem_id)}`),
  })
  const submit = (event: FormEvent) => {event.preventDefault(); mutation.mutate()}
  const markdownPreview = useQuery({
    queryKey: ['problem-markdown-preview', values.content || ''],
    queryFn: () => apiFetch<MarkdownPreviewResponse>('/api/forum/preview', {method: 'POST', body: JSON.stringify({content: values.content || ''})}),
    enabled: previewOpen && Boolean((values.content || '').trim()),
    staleTime: 60_000,
  })

  if (!session?.user?.is_admin) return <ErrorState message="该页面仅管理员可访问" />
  if (query.isPending || !seed) return <LoadingState label="正在读取题目配置" />
  if (query.isError) return <ErrorState message={query.error.message} retry={() => void query.refetch()} />
  const typeOptions = query.data.options.problem_types.map((item) => ({value: String(item.value), label: item.label}))
  const programmingModeOptions = query.data.options.programming_grading_modes.map((item) => ({value: String(item.value), label: item.label}))
  const writtenModeOptions = [{value: '1', label: 'OCR + 文本批改'}, {value: '2', label: '直接批改图片'}, {value: '3', label: 'tex 文本批改'}, {value: '4', label: '纯人工批改'}]
  const examples = (() => {try {const parsed = JSON.parse(values.promptly_example_replies_json || '[]'); return Array.isArray(parsed) ? parsed.map(String) : []} catch {return []}})()
  const setExamples = (items: string[]) => set('promptly_example_replies_json', JSON.stringify(items))

  return <section className="numoj-problem-editor-page problem-editor-v2">
    <form id={editing ? 'editProblemForm' : 'addProblemForm'} onSubmit={submit}>
      <header className="problem-editor-header">
        <div className="problem-editor-heading"><span>{editing ? `P${String(numericId).padStart(4, '0')}` : '新题目'} · {type === '1' ? '编程题' : '书面题'}</span><h1>{editing ? '编辑题目' : '添加题目'}</h1></div>
        <div className="problem-editor-actions">{editing ? <Link to={`/problems/${numericId}`} className="problem-editor-cancel">取消</Link> : null}<button type="submit" className="problem-editor-save" disabled={mutation.isPending}><i className={`fas ${mutation.isPending ? 'fa-spinner fa-spin' : 'fa-check'}`} />{mutation.isPending ? '保存中' : '保存'}</button></div>
      </header>
      {mutation.isError ? <div className="problem-editor-error" role="alert">{errorMessage(mutation.error)}</div> : null}
      <div className="problem-editor-layout">
        <div className="problem-editor-main">
          <label className="problem-editor-title-field" htmlFor="titleInput"><span><EditorIcon name="title" />标题</span><input type="text" id="titleInput" name="title" required value={values.title || ''} onChange={(event) => set('title', event.target.value)} /></label>
          <main className="problem-editor-document">
          <header className="problem-editor-document-bar"><h2><EditorIcon name="statement" />题面</h2><div className="problem-editor-tabs" role="tablist" aria-label="题面编辑与预览"><button type="button" role="tab" aria-selected={!previewOpen} className={!previewOpen ? 'is-active' : ''} onClick={() => setPreviewOpen(false)}><EditorIcon name="edit" />编辑</button><button type="button" role="tab" aria-selected={previewOpen} className={previewOpen ? 'is-active' : ''} onClick={() => setPreviewOpen(true)}><EditorIcon name="preview" />预览</button></div></header>
          {previewOpen ? <div className="problem-editor-preview problem-detail-page" role="tabpanel"><div className="problem-col-left">{!(values.content || '').trim() ? <div className="problem-editor-preview-empty">暂无题面</div> : markdownPreview.isPending ? <div className="problem-editor-preview-empty">正在渲染</div> : markdownPreview.isError ? <div className="problem-editor-preview-empty is-error">{errorMessage(markdownPreview.error)}</div> : <MarkdownContent html={String(markdownPreview.data?.rendered_content || '')} className="problem-content numoj-markdown numoj-problem-code-rendering my-3" />}</div></div> : <textarea className="problem-editor-markdown" id="contentTextArea" required value={values.content || ''} onChange={(event) => set('content', event.target.value)} aria-label="题面 Markdown" />}
          </main>
        </div>
        <aside className="problem-editor-settings" aria-label="题目设置">
          <section className="problem-editor-card"><header><h2><EditorIcon name="settings" />基本设置</h2></header><div className="problem-editor-fields">
            <div className="problem-editor-field"><span>类型</span><Choice value={type} options={typeOptions} icon="fa-question" disabled={editing} onChange={(value) => set('type', value)} /></div>
            {type === '1' ? <div className="problem-editor-field"><span>语言</span><Choice value={language} options={languages} icon="fa-code" onChange={(value) => set('lang', value)} /></div> : null}
            {type === '1' ? <label className="problem-editor-field" htmlFor="timeLimitInput"><span>{language === 'lean4' ? '验证时限 / ms' : '时限 / ms'}</span><input type="number" id="timeLimitInput" min={1} required value={values.time_limit || (editing ? '2000' : '10000')} onChange={(event) => set('time_limit', event.target.value)} /></label> : null}
            <label className="problem-editor-field" htmlFor="submissionLimitInput"><span>提交上限</span><input type="number" id="submissionLimitInput" min={1} required value={values.submission_limit || '10'} onChange={(event) => set('submission_limit', event.target.value)} /></label>
            {type === '1' && language !== 'lean4' ? <div className="problem-editor-field"><span>评测模式</span><Choice value={programmingMode} options={programmingModeOptions} icon="fa-sliders" onChange={(value) => set('programming_grading_mode', value)} /></div> : null}
            {type === '2' ? <div className="problem-editor-field"><span>批改模式</span><Choice value={writtenMode} options={writtenModeOptions} icon="fa-sliders" onChange={changeWrittenMode} /></div> : null}
          </div></section>
          {type === '1' && language !== 'lean4' && programmingMode === '2' ? <section className="problem-editor-card"><header><h2><EditorIcon name="image" />图片评测</h2></header><div className="problem-editor-fields">
            <label className="problem-editor-field" htmlFor="outputImageFilename"><span>输出文件</span><input id="outputImageFilename" value={values.output_image_filename || 'output.png'} onChange={(event) => set('output_image_filename', event.target.value)} /></label>
            <EndpointChoice name="output_image_grading_endpoint_id" label="批改端点" value={values.output_image_grading_endpoint_id || ''} items={endpointCandidates.output_image_grading_endpoint_id || []} onChange={(value) => set('output_image_grading_endpoint_id', value)} />
            <label className="problem-editor-field" htmlFor="programmingGradingPrompt"><span>评分标准</span><textarea id="programmingGradingPrompt" rows={6} value={values.programming_grading_prompt || ''} onChange={(event) => set('programming_grading_prompt', event.target.value)} /></label>
          </div></section> : null}
          {type === '1' && language !== 'lean4' && programmingMode === '3' ? <section className="problem-editor-card"><header><h2><EditorIcon name="code" />Promptly</h2></header><div className="problem-editor-fields">
            <EndpointChoice name="review_endpoint_id" label="审查端点" value={values.review_endpoint_id || ''} items={endpointCandidates.review_endpoint_id || []} onChange={(value) => set('review_endpoint_id', value)} />
            <EndpointChoice name="code_generation_endpoint_id" label="生成端点" value={values.code_generation_endpoint_id || ''} items={endpointCandidates.code_generation_endpoint_id || []} onChange={(value) => set('code_generation_endpoint_id', value)} />
            <label className="problem-editor-field" htmlFor="promptlyBrief"><span>题意</span><textarea id="promptlyBrief" rows={3} value={values.promptly_brief || ''} onChange={(event) => set('promptly_brief', event.target.value)} /></label>
            <label className="problem-editor-field" htmlFor="promptlyRequirements"><span>Prompt 要求</span><textarea id="promptlyRequirements" rows={4} value={values.promptly_prompt_requirements || ''} onChange={(event) => set('promptly_prompt_requirements', event.target.value)} /></label>
            <div className="problem-editor-examples"><div className="problem-editor-examples-head"><span>示例回复</span><button type="button" onClick={() => setExamples([...examples, ''])} aria-label="添加示例"><i className="fas fa-plus" /></button></div>{examples.map((example, index) => <div className="problem-editor-example" key={index}><textarea rows={2} value={example} onChange={(event) => setExamples(examples.map((item, itemIndex) => itemIndex === index ? event.target.value : item))} /><button type="button" onClick={() => setExamples(examples.filter((_, itemIndex) => itemIndex !== index))} aria-label={`删除示例 ${index + 1}`}><i className="fas fa-trash-can" /></button></div>)}</div>
          </div></section> : null}
          {type === '2' && writtenMode === '1' ? <section className="problem-editor-card"><header><h2><EditorIcon name="ocr" />OCR</h2></header><div className="problem-editor-fields"><EndpointChoice name="ocr_endpoint_id" label="识别端点" value={values.ocr_endpoint_id || ''} items={endpointCandidates.ocr_endpoint_id || []} onChange={(value) => set('ocr_endpoint_id', value)} /></div></section> : null}
          {type === '2' && writtenMode !== '4' ? <WrittenVoteEditor rows={writtenVoteRows} items={writtenVoteCandidates} onChange={setWrittenVoteRows} /> : null}
          {type === '2' && writtenMode !== '4' ? <section className="problem-editor-card"><header><h2><EditorIcon name="rubric" />评分标准</h2></header><div className="problem-editor-fields"><textarea className="problem-editor-rubric" rows={8} aria-label="评分标准" value={values.written_grading_prompt || (!editing ? query.data.options.default_written_grading_prompt : '') || ''} onChange={(event) => set('written_grading_prompt', event.target.value)} /></div></section> : null}
        </aside>
      </div>
      {type === '1' && language !== 'lean4' ? <section className="problem-editor-code-grid">
        <article className="problem-editor-code-card"><header><h2><EditorIcon name="code" />初始代码</h2></header><MonacoEditor idPrefix="initial" ariaLabel="初始代码编辑器" language={language} problemId={numericId} value={values.initial_code || ''} onChange={(value) => set('initial_code', value)} /></article>
        <article className="problem-editor-code-card"><header><h2><EditorIcon name="code" />交互库</h2></header><MonacoEditor idPrefix="test" ariaLabel="交互库代码编辑器" language={language} problemId={numericId} value={values.test_code || (editing && !testCodeTouched && query.data.problem?.test_code == null ? 'None' : '')} onChange={(value) => {setTestCodeTouched(true); set('test_code', value)}} /></article>
        <label className="problem-editor-code-card problem-editor-code-card--compact" htmlFor="forbiddenFunctions"><span>禁用函数</span><input id="forbiddenFunctions" value={values.forbidden_func || ''} onChange={(event) => set('forbidden_func', event.target.value)} /></label>
      </section> : null}
    </form>
  </section>
}
