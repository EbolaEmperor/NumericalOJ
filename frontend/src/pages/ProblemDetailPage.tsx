import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import {useEffect, useRef, useState, type FormEvent} from 'react'
import {Link, useNavigate, useParams} from 'react-router-dom'

import {apiFetch, errorMessage} from '../api/client'
import type {ApiEnvelope, JsonRecord, ProblemSummary, SubmissionSummary} from '../api/types'
import {ErrorState, LoadingState} from '../components/PageState'
import {useSession} from '../session'

interface DetailResponse extends ApiEnvelope {
  problem: ProblemSummary & {content?: string; time_limit_ms?: number; max_score?: number; submission_limit?: number}
  rendered_content: string
  initial_code?: string
  last_submissions: SubmissionSummary[]
  remaining_submissions?: number
  can_submit: boolean
  submit_block_reason?: string
  submit_warning?: JsonRecord
  submit: {action: string; input_name: string; input_kind: string; accept?: string; help_text?: string; programming_grading_mode?: number}
}

const abbreviations: Record<string, string> = {'Accepted': 'AC', 'Wrong Answer': 'WA', 'Unaccepted': 'UA', 'Compile Error': 'CE', 'Runtime Error': 'RE', 'Time Limit Exceeded': 'TL', 'Memory Limit Exceeded': 'ML', 'Output Limit Exceeded': 'OL', 'Forbidden': 'FB', 'No Output': 'NO', 'Nonzero Exit Status': 'NZ', 'Pending': 'PD', 'Waiting': 'WT', 'Running': 'RN', 'Generating': 'GN', 'Error': 'ER'}

function languageLabel(value?: string) {
  return ({matlab: 'MATLAB', cpp: 'C++', c: 'C', python: 'Python', lean: 'Lean 4', lean4: 'Lean 4'} as Record<string, string>)[String(value || '').toLowerCase()] || value || ''
}

export default function ProblemDetailPage() {
  const {problemId} = useParams()
  const {session} = useSession()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [text, setText] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const detail = useQuery({queryKey: ['problem', problemId], queryFn: () => apiFetch<DetailResponse>(`/api/problems/${problemId}`)})
  useEffect(() => {if (detail.data && !text) setText(detail.data.initial_code || '')}, [detail.data, text])
  const submit = useMutation({
    mutationFn: async () => {
      if (!detail.data) throw new Error('题目上下文尚未加载')
      const form = new FormData()
      if (detail.data.submit.input_kind === 'file') {
        const file = fileRef.current?.files?.[0]
        if (!file) throw new Error('请先选择文件')
        form.append(detail.data.submit.input_name, file)
      } else form.append(detail.data.submit.input_name, text)
      return apiFetch<ApiEnvelope & {submission_id?: number}>(detail.data.submit.action, {method: 'POST', body: form})
    },
    onSuccess: async (payload) => {await queryClient.invalidateQueries({queryKey: ['submissions']}); if (payload.submission_id) navigate(`/app/submissions/${payload.submission_id}`)},
  })
  if (detail.isPending) return <LoadingState label="正在读取题目与提交上下文" />
  if (detail.isError) return <ErrorState message={detail.error.message} />
  const data = detail.data!
  const problem = data.problem
  const programming = Number(problem.type || 1) === 1
  const isPrompt = data.submit.input_kind === 'prompt'
  const isFile = data.submit.input_kind === 'file'
  const lang = languageLabel(problem.lang)
  const submitForm = (event: FormEvent) => {event.preventDefault(); submit.mutate()}

  return <div className="problem-detail-page">
    <nav className="numoj-breadcrumb d-flex" aria-label="面包屑导航"><Link to="/app/problems?view=library">总题库</Link><span aria-hidden="true">›</span><span>P{String(problem.id).padStart(4, '0')}</span><span aria-hidden="true">›</span><strong>{problem.title}</strong></nav>
    <div className="row problem-detail-row">
      <div className="col-md-6 mb-3 problem-col-left" id="problemStatementPane">
        <div className="problem-header mb-3"><div className={`problem-heading-layout${data.last_submissions?.length ? ' has-recent-submissions' : ''}`}><div className="problem-heading-info"><div className="numoj-problem-kickers d-flex"><span>{programming ? '编程题' : '书面题'}</span>{problem.lang ? <span>{lang}</span> : null}</div><div className="problem-title-row"><h2 className="mb-0 problem-title-singleline"><strong className="problem-number">{problem.id}.</strong><span className="problem-title-text">{problem.title}</span></h2></div>{session?.user?.is_admin ? <div className="problem-admin-actions mt-2">{programming ? <a href={`/agent/tasks?problem_id=${problem.id}`} className="btn btn-outline-primary"><i className="fas fa-robot me-1" /> 解题</a> : null}<a href={`/admin/edit_problem/${problem.id}`} className="btn btn-outline-warning me"><i className="fas fa-pencil-alt me-1" /> 编辑</a><button type="button" className="btn btn-outline-warning" data-bs-toggle="modal" data-bs-target="#uploadDataModal"><i className="fas fa-cloud-upload-alt me-1" /> 上传</button></div> : null}</div>{data.last_submissions?.length ? <aside className="recent-submissions-card" aria-label="最近提交"><ul>{data.last_submissions.map((item) => <li key={item.id}><span className={`badge submission-status ${String(item.status || '').toLowerCase().replaceAll(' ', '-')}`} title={item.status}>{abbreviations[String(item.status)] || 'UN'}</span><span className="recent-submission-score">{item.score ?? '—'}/{problem.max_score ?? 100}</span><Link to={`/app/submissions/${item.id}`} className="recent-submission-arrow" aria-label={`查看提交 ${item.id} 详情`}><svg viewBox="0 0 16 16"><path d="M3.5 8h8M8.5 4.5 12 8l-3.5 3.5" /></svg></Link></li>)}</ul></aside> : null}</div></div>
        <div className="problem-content numoj-markdown numoj-problem-code-rendering my-3" data-numoj-markdown dangerouslySetInnerHTML={{__html: data.rendered_content}} />
      </div>
      <div className="problem-detail-splitter" role="separator" tabIndex={0} aria-label="调整题面与作答区宽度" aria-orientation="vertical" aria-controls="problemStatementPane problemSubmissionPane" aria-valuemin={20} aria-valuemax={80} aria-valuenow={50} />
      <div className="col-md-6 problem-col-right" id="problemSubmissionPane">
        <form className={`mb-4 problem-submit-form ${isPrompt ? 'problem-prompt-submit-form' : programming ? 'problem-code-submit-form' : 'problem-written-submit-form'}`} onSubmit={submitForm}>
          <div className="d-flex justify-content-between align-items-end mb-2 problem-editor-toolbar"><label className="form-label mb-0 code-label-wrap"><span className="code-title-line"><i className={`fas ${isPrompt ? 'fa-terminal' : programming ? 'fa-code' : 'fa-file-pdf'} me-2`} />{isPrompt ? 'Prompt' : programming ? '代码' : '书面作业'}</span><span className="code-meta-line">{problem.lang ? <span className="badge bg-secondary"><i className="fas fa-language me-2" />{lang}</span> : null}{programming ? <span className="badge bg-secondary"><i className="fas fa-stopwatch me-2" />{problem.time_limit_ms || '—'} ms</span> : null}</span></label><div className="d-flex flex-column align-items-end">{!session?.user?.is_admin && data.remaining_submissions != null ? <small className={`${data.remaining_submissions <= 3 ? 'text-danger' : 'text-muted'} mb-1`}>剩余提交次数: <strong>{data.remaining_submissions}</strong>/{problem.submission_limit || 10}</small> : null}<div className="problem-editor-actions student-code-actions">{programming && !isPrompt ? <button type="button" className="btn btn-outline-secondary" onClick={() => setText(data.initial_code || '')}><i className="fas fa-copy me-1" /><span className="d-none d-md-inline">复用初始代码</span><span className="d-inline d-md-none">复用</span></button> : null}<button type="submit" className="btn btn-outline-primary" disabled={!data.can_submit || submit.isPending}><i className="fas fa-paper-plane me-2" />{submit.isPending ? '提交中…' : data.can_submit ? isPrompt ? '提交 Prompt' : '提交' : '已达上限'}</button></div></div></div>
          {isFile ? <div className="problem-written-file-picker"><input ref={fileRef} id="file" type="file" accept={data.submit.accept} required /><label className="problem-written-dropzone" htmlFor="file"><span className="problem-written-dropzone-icon"><i className="fas fa-cloud-arrow-up" /></span><span className="problem-written-dropzone-copy"><strong>选择或拖入{data.submit.accept?.toUpperCase()} 文件</strong><small>{data.submit.help_text}</small></span></label></div> : isPrompt ? <textarea id="promptEditor" name="prompt" className="form-control" rows={18} required value={text} onChange={(event) => setText(event.target.value)} placeholder="请描述你的解题思路，包括算法或数据结构、关键步骤、状态更新和边界处理。" /> : <div className="card problem-editor-card"><div className="card-body p-0"><div className="problem-editor-shell" data-editor-state="ready" aria-busy="false"><textarea id="codeEditor" name="code" className="numoj-code-textarea-fallback" spellCheck={false} value={text} onChange={(event) => setText(event.target.value)} /></div></div></div>}
          {submit.isError ? <div className="alert alert-danger mt-3" role="alert">{errorMessage(submit.error)}</div> : !data.can_submit && data.submit_block_reason ? <div className="alert alert-warning mt-3">{data.submit_block_reason}</div> : null}
        </form>
      </div>
    </div>
    {session?.user?.is_admin ? <div className="modal fade" id="uploadDataModal" tabIndex={-1} aria-labelledby="uploadDataModalLabel" aria-hidden="true"><div className="modal-dialog"><form method="POST" action={`/admin/upload_testdata/${problem.id}`} encType="multipart/form-data"><div className="modal-content"><div className="modal-header"><h5 className="modal-title" id="uploadDataModalLabel"><i className="fas fa-cloud-upload-alt me-2" /> 上传测试数据</h5><button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="关闭" /></div><div className="modal-body"><div className="mb-3"><label htmlFor="testDataZip" className="form-label">选择 ZIP 文件</label><input className="form-control" type="file" id="testDataZip" name="testdata_zip" accept=".zip" required /><div className="form-text">上传包含 1.in, 1.out, 2.in, 2.out 等文件的 ZIP 包。</div></div></div><div className="modal-footer"><button type="button" className="btn btn-outline-secondary" data-bs-dismiss="modal"><i className="fas fa-times me-2" /> 取消</button><button type="submit" className="btn btn-outline-primary"><i className="fas fa-cloud-upload-alt me-2" /> 上传</button></div></div></form></div></div> : null}
  </div>
}
