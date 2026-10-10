// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {MemoryRouter, Route, Routes, useLocation} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import {proofDagFixture, proofDagV3Fixture, proofDagVerificationFixture} from '../test/faithSieveProofDag'
import FaithSieveDetailPage from './FaithSieveDetailPage'
import FaithSieveListPage from './FaithSieveListPage'
import {faithSieveDetailQueryKey, type FaithSieveDetailResponse, type FaithSieveListResponse, type FaithSieveExecutionMode, type FaithSieveRun} from './faithsieveTypes'

vi.mock('../components/MathCurveLoader', () => ({MathCurveLoader: ({label, ariaLabel}: {label?: string; ariaLabel?: string}) => <span role="status" aria-label={ariaLabel}>{label || '运行中'}</span>}))
vi.mock('../markdown/mathjaxRuntime', () => ({typesetMath: vi.fn().mockResolvedValue(undefined), clearMath: vi.fn()}))

const firstAttempt = 'a'.repeat(32)
const secondAttempt = 'b'.repeat(32)
const run: FaithSieveRun = {id: 7, attempt_id: firstAttempt, execution_mode: 'workflow', submission_id: 31, problem_id: 12, problem_title: '定积分证明', username: 'alice', student_name: '旧称呼', requested_by: 'teacher_trigger', status: 'running', message: '验证证明', submission_created_at: '2026-10-02 09:00:00', created_at: '2026-10-02 10:00:00', updated_at: '2026-10-02 10:01:00', runtime: {harness: 'pi', model: 'omni-model'}, result: null}
function detail(status = 'running'): FaithSieveDetailResponse {
  return {success: true, run: {...run, status}, submission: {id: 31, problem_id: 12, username: 'alice', status: 'Accepted', created_at: '2026-10-02 09:00:00'}, problem: {id: 12, title: '定积分证明', content_html: '<p>证明 \\(x = y\\)</p>'}, result: status === 'completed' ? {verdict: 'correct', score: 5, comment: '证明成立'} : status === 'inconclusive' ? {verdict: 'inconclusive', score: 0, comment: '无法核对原稿'} : null, workflow: {warnings: [], source: {status: 'ok', report: '原稿逐页核对完成', artifact: 'source.md'}, artifacts: [{path: 'proof.lean', language: 'lean4'}], stages: [
    {key: 'extract-1', sequence: 1, label: '原稿核对', role: 'source-extractor', kind: 'judge', state: 'completed', status: 'ok', report: '第一轮原稿报告', parameters: {edge_id: 'e1', obligation_id: 'o1', branch: 'counterexample'}, session_id: 'fs-readonly', artifacts: [{path: 'source.md', language: 'markdown', stage_key: 'extract-1'}]},
    {key: 'compile-1', sequence: 2, label: 'Lean 编译', role: 'compile-lean', kind: 'code', state: status === 'completed' ? 'completed' : 'pending', status: status === 'completed' ? 'passed' : '', report: '实际编译报告', artifacts: [{path: 'proof.lean', language: 'lean4', stage_key: 'compile-1'}], checks: [{label: '独立符号复验', state: 'completed', status: verificationStatus, report: '精确符号输出', exit_code: 0}]},
  ], edges: [{source: 'extract-1', target: 'compile-1'}]}}
}
function json(payload: object) {return Promise.resolve(new Response(JSON.stringify(payload), {status: 200, headers: {'Content-Type': 'application/json'}}))}
let admin = true
let status = 'running'
let completedScore = 5
let sessionAvailable = true
let deleted = false
let currentPage = 1
let totalPages = 1
let desktop = true
let detailCalls = 0
let listCalls = 0
let executionMode: FaithSieveExecutionMode | undefined = 'workflow'
let artifactVersion = '第一版'
let verificationStatus = 'passed'
let withTree = false
let withDag = false
let dagVersion: 2 | 3 = 2
let dagVerification = proofDagVerificationFixture()
let brokenTree = false
let endpointFailure = false
let detailFailuresRemaining = 0
let detailFailureStatus = 503
let retryEligible: boolean | undefined
let retryCalls = 0
let retryHandler: () => Promise<Response>
let cost: FaithSieveRun['cost']
const proofTree = {schema_version: 1, root_id: 'N0', nodes: [{id: 'N0', label: '初始状态', conditions: ['x = y'], goal: 'x = x', scope: []}, {id: 'N1', label: '结论', conditions: ['x = y'], goal: 'x = x', scope: []}], edges: [{id: 'E1', from: 'N0', to: 'N1', step_id: 'S1', source_location: '第 1 页', source_text: '由等式的自反性得结论', changes: {retained: ['x = y'], added: [], consumed: [], transformed: []}, goal_relation: '目标成立', transition_type: '直接推理', scope: []}], ambiguities: []}
function Location() {const location = useLocation(); return <output aria-label="当前地址">{location.pathname}{location.search}</output>}
function renderPage(path: string) {
  const client = new QueryClient({defaultOptions: {queries: {retry: false, refetchOnWindowFocus: false}, mutations: {retry: false}}})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><SessionProvider><Routes><Route path="/admin/faithsieve" element={<FaithSieveListPage />} /><Route path="/admin/faithsieve/:attemptId" element={<FaithSieveDetailPage />} /><Route path="/agents/:sessionId" element={<div>Agent 会话</div>} /></Routes><Location /></SessionProvider></MemoryRouter></QueryClientProvider>)
  return client
}
beforeEach(() => {
  admin = true; status = 'running'; completedScore = 5; sessionAvailable = true; deleted = false; currentPage = 1; totalPages = 1; desktop = true; detailCalls = 0; listCalls = 0; executionMode = 'workflow'; artifactVersion = '第一版'; verificationStatus = 'passed'; withTree = false; brokenTree = false; endpointFailure = false; detailFailuresRemaining = 0; detailFailureStatus = 503
  withDag = false; dagVersion = 2; dagVerification = proofDagVerificationFixture()
  retryEligible = undefined; retryCalls = 0
  cost = undefined
  retryHandler = () => {status = 'queued'; retryEligible = false; return json({success: true, attempt_id: firstAttempt, status})}
  Object.defineProperty(window, 'matchMedia', {configurable: true, value: vi.fn().mockImplementation((query: string) => ({matches: desktop && query.includes('min-width'), media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()}))})
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return json({success: true, api_version: '1', user: {id: 1, username: 'admin', is_admin: admin ? 1 : 0}, navigation: {items: [], counts: {}, agent_active: false}, capabilities: {spa: true}})
    if (url.startsWith('/api/submissions/31/file') && init?.method === 'HEAD') return Promise.resolve(new Response(null, {status: 200}))
    if (url === `/api/admin/faithsieve/${firstAttempt}/retry` && init?.method === 'POST') {retryCalls += 1; return retryHandler()}
    if (url.includes('/artifacts?')) {
      const params = new URL(url, 'http://localhost').searchParams
      const path = params.get('path')!
      if (path === 'faithsieve-work/tree.json') {
        const graph = withDag ? dagVersion === 3 ? proofDagV3Fixture() : proofDagFixture() : proofTree
        const history = params.get('stage_key') === 'tree-1'
        if (withDag && history) graph.nodes[5] = {...graph.nodes[5], statement: '历史版本的结论'}
        return json({success: true, artifact: {path, language: 'json', content: JSON.stringify(graph), proof_tree: brokenTree ? undefined : graph, proof_tree_format: withDag ? 'dependency_dag' : 'json', schema_version: graph.schema_version, proof_node_verification: withDag && !history ? dagVerification : undefined}})
      }
      return json({success: true, artifact: {path, language: path.endsWith('.md') ? 'markdown' : 'lean4', content: `原文 ${params.get('stage_key') || 'current'} ${artifactVersion}`, content_html: path.endsWith('.md') ? '<h2>第一轮原稿</h2><p>公式 \\(x=y\\)</p>' : undefined}})
    }
    if (url.startsWith(`/api/admin/faithsieve/${firstAttempt}`) || url.startsWith(`/api/admin/faithsieve/${secondAttempt}`)) {
      detailCalls += 1
      if (detailFailuresRemaining > 0) {
        detailFailuresRemaining -= 1
        return Promise.resolve(new Response(JSON.stringify({success: false, message: '暂时不可读取任务'}), {status: detailFailureStatus, headers: {'Content-Type': 'application/json'}}))
      }
      const value = detail(status)
      value.run.cost = cost
      if (endpointFailure) {
        value.workflow.stages[1] = {key: 'endpoint-failure', sequence: 2, label: '独立审计证明状态树', role: 'tree-auditor', kind: 'llm', state: 'endpoint_error', status: 'failed', report: '独立审计证明状态树：模型端点余额不足或需要付费（HTTP 402）'}
        value.workflow.edges = [{source: 'extract-1', target: 'endpoint-failure'}]
      }
      if (withTree || withDag) {
        value.workflow.proof_tree = {path: 'faithsieve-work/tree.json', stage_key: 'tree-2', format: withDag ? 'dependency_dag' : 'json', schema_version: withDag ? dagVersion : 1, node_verification: withDag ? dagVerification : undefined}
        value.workflow.stages.splice(1, 0, {key: 'tree-1', sequence: 2, label: withDag ? '建立证明依赖图' : '建立证明状态树', role: 'tree-builder', kind: 'llm', state: 'completed', status: 'ok', artifacts: [{path: 'faithsieve-work/tree.json', language: 'json', stage_key: 'tree-1', format: withDag ? 'dependency_dag' : 'json', schema_version: withDag ? dagVersion : 1}]})
        value.workflow.stages.splice(2, 0, {key: 'tree-audit-1', sequence: 3, label: withDag ? '独立审计证明依赖图' : '独立审计证明状态树', role: 'tree-auditor', kind: 'llm', state: 'completed', status: 'ok', artifacts: [{path: 'faithsieve-work/review/tree.md', language: 'markdown', stage_key: 'tree-audit-1'}]})
        value.workflow.edges = [{source: 'extract-1', target: 'tree-1'}, {source: 'tree-1', target: 'tree-audit-1'}, {source: 'tree-audit-1', target: 'compile-1'}]
        if (withDag) Object.assign(value.workflow.stages.at(-1)!, {role: 'numeric-validator', label: '数值验证', kind: 'judge', state: 'completed', status: verificationStatus, parameters: {node_id: 'N9', obligation_id: 'N9-O1'}, checks: undefined})
        if (withDag && dagVersion === 3) {
          value.workflow.source = {}
          value.workflow.stages = [
            {key: 'image-render', sequence: 1, role: 'image-render', label: '渲染原稿图片', kind: 'code', state: 'completed', status: 'ok', report: '7 页 PNG'},
            {key: 'tree-2', sequence: 2, role: 'tree-builder', label: '生成证明依赖图', kind: 'llm', state: 'completed', status: 'ok', artifacts: [{path: 'faithsieve-work/tree.json', format: 'dependency_dag', schema_version: 3, language: 'json', stage_key: 'tree-2'}]},
            {key: 'tree-audit-2', sequence: 3, role: 'tree-auditor', label: '审核证明依赖图', kind: 'llm', state: 'completed', status: 'ok', report: 'DAG 与原稿图像一致'},
            {key: 'local-N9', sequence: 4, role: 'local-verifier', label: '验证局部命题', kind: 'judge', state: 'completed', status: verificationStatus, parameters: {node_id: 'N9'}, report: '局部推理验证记录', session_id: 'fs-node-N9'},
          ]
          value.workflow.edges = [{source: 'image-render', target: 'tree-2'}, {source: 'tree-2', target: 'tree-audit-2'}, {source: 'tree-audit-2', target: 'local-N9'}]
          if (status === 'inconclusive') value.result = {verdict: 'inconclusive', score: 0, comment: '部分依赖结论尚未成立'}
        }
      }
      value.run.execution_mode = executionMode
      value.run.session_id = executionMode !== 'workflow' && sessionAvailable ? 'fs-skill-session' : null
      value.run.retry_eligible = retryEligible
      if (executionMode !== 'workflow') {
        value.workflow.stages = [{key: 'skill-session', sequence: 1, label: 'FaithSieve Skill', role: 'task-judge', kind: 'judge', state: status === 'running' || status === 'queued' ? 'pending' : 'completed', session_id: sessionAvailable ? 'fs-skill-session' : undefined, task_id: 'ft-skill-task', judge_status: status, report: 'Skill Judge 原始报告', artifacts: [{path: 'proof.lean', language: 'lean4', stage_key: 'skill-session'}]}]
        value.workflow.edges = []
        value.workflow.source = {}
      }
      if (url.includes(secondAttempt)) {value.run = {...value.run, id: 8, attempt_id: secondAttempt}; value.problem!.title = '第二条任务'}
      if (deleted) {value.submission = null; value.problem = null}
      return json(value)
    }
    if (url.startsWith('/api/admin/faithsieve?')) {
      listCalls += 1
      return json({success: true, runs: [{...run, status, execution_mode: executionMode, session_id: executionMode !== 'workflow' && sessionAvailable ? 'fs-skill-session' : null, result: status === 'completed' ? {verdict: completedScore === 0 ? 'incorrect' : 'correct', score: completedScore} : status === 'inconclusive' ? {verdict: 'inconclusive', score: 0} : null}, {...run, id: 8, attempt_id: secondAttempt, execution_mode: executionMode, problem_title: '第二条任务', status: 'completed', result: {verdict: 'correct', score: 5}}], page: currentPage, per_page: 20, total: 2, total_pages: totalPages, page_numbers: Array.from({length: totalPages}, (_, i) => i + 1)})
    }
    throw new Error(`unexpected fetch: ${url}`)
  }))
})
afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers()})

describe('Faith Sieve 列表', () => {
  it('侧边预览顶部展示金额，在说明中保留汇总状态，刷新时更新金额', async () => {
    cost = {cost_rmb: '0.000125', currency: 'CNY', complete: false, estimated: false, missing_usage: true, request_count: 1}
    const client = renderPage('/admin/faithsieve')
    const preview = await screen.findByLabelText('Faith Sieve 预览')
    const charge = await within(preview).findByLabelText('本次费用：人民币0.000125元，费用仍在汇总')
    expect(charge.closest('.faithsieve-preview-heading')).toBeTruthy()
    expect(charge.textContent).toBe('0.00')
    expect(within(preview).queryByText('已记录')).toBeNull()
    expect(charge.querySelector('svg.faithsieve-cost-logo[aria-hidden="true"]')).toBeTruthy()
    expect(charge.querySelector('svg circle, svg rect, svg text')).toBeNull()
    expect(charge.getAttribute('title')).toBe('人民币0.000125元，费用仍在汇总')
    cost = {...cost, cost_rmb: '1.2', complete: true, missing_usage: false, request_count: 2}
    await act(async () => {await client.refetchQueries({queryKey: faithSieveDetailQueryKey(firstAttempt)})})
    const updated = await within(preview).findByLabelText('本次费用：人民币1.2元')
    expect(updated.textContent).toBe('1.20')
    expect(within(preview).queryByText('已记录')).toBeNull()
    client.clear()
  })
  it('依赖节点数值验证被反驳时预览明确为局部推理结果', async () => {
    withDag = true; verificationStatus = 'refuted'
    const client = renderPage('/admin/faithsieve')
    const preview = await screen.findByLabelText('Faith Sieve 预览')
    const summary = await within(preview).findByLabelText('阶段摘要')
    expect(within(summary).getByText('数值验证')).toBeTruthy()
    expect(within(summary).getByText('推理被反驳')).toBeTruthy()
    expect(within(summary).queryByText('反驳成立')).toBeNull()
    expect(within(preview).queryByText('证明存在问题')).toBeNull()
    client.clear()
  })
  it('显示提交归属者，时间仅在侧边栏展示，不使用触发者或更新时间', async () => {
    renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText('Faith Sieve #7，运行中')
    expect(row.querySelector('.submission-col-user')?.textContent).toBe('alice')
    expect(row.textContent).not.toContain('teacher_trigger')
    expect(row.textContent).not.toContain('旧称呼')
    const panel = screen.getByLabelText('Faith Sieve 预览')
    expect(await within(panel).findByRole('link', {name: 'alice · 提交 #31'})).toBeTruthy()
    const table = screen.getByRole('table', {name: 'Faith Sieve 任务'})
    expect(table.querySelector('time, .submission-col-time')).toBeNull()
    expect(within(table).queryByRole('columnheader', {name: '更新时间'})).toBeNull()
    const times = within(panel).getByLabelText('提交与评测时间')
    expect(within(times).getByText('提交时间').nextElementSibling?.textContent).toBe('2026-10-02 09:00:00')
    expect(within(times).getByText('评测触发时间').nextElementSibling?.textContent).toBe('2026-10-02 10:00:00')
    expect(times.textContent).not.toContain('2026-10-02 10:01:00')
    const runtime = row.querySelector('.submission-col-tests')!
    const harnessLogo = runtime.querySelector('[data-harness-logo]')!
    const modelLogo = runtime.querySelector('[data-model-family-logo]')!
    expect(harnessLogo.compareDocumentPosition(modelLogo) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(runtime.textContent).toBe(run.runtime?.model)
    expect(within(runtime as HTMLElement).getByRole('img', {name: 'Pi'}).hasAttribute('title')).toBe(false)
    expect(row.querySelector('.submission-col-language')).toBeNull()
  })
  it('预览原提交缺失时从记录的提交时间字段展示时间', async () => {
    deleted = true
    renderPage('/admin/faithsieve')
    const panel = await screen.findByLabelText('Faith Sieve 预览')
    await within(panel).findByText('原提交已删除')
    expect(within(panel).getByLabelText('提交与评测时间').textContent).toContain('2026-10-02 09:00:00')
  })
  it('保留既有表格主从布局、隐藏表头、键盘选中与详情链接', async () => {
    renderPage('/admin/faithsieve')
    const first = await screen.findByLabelText('Faith Sieve #7，运行中')
    const second = screen.getByLabelText('Faith Sieve #8，已完成')
    expect(screen.getByRole('table', {name: 'Faith Sieve 任务'}).querySelector('thead')?.classList.contains('visually-hidden')).toBe(true)
    expect(first.querySelector('.submission-col-id')).toBeNull()
    expect(within(first).queryByText('#7')).toBeNull()
    expect(first.querySelector('svg[data-execution-mode-logo="workflow"]')).toBeTruthy()
    expect(within(second).getByLabelText('得分 5 / 5')).toBeTruthy()
    expect(within(first).getByRole('link', {name: '打开 Faith Sieve #7 的完整详情'}).getAttribute('href')).toBe(`/admin/faithsieve/${firstAttempt}`)
    expect(first.getAttribute('aria-selected')).toBe('true')
    const panel = screen.getByLabelText('Faith Sieve 预览')
    expect(await within(panel).findByRole('heading', {name: '定积分证明'})).toBeTruthy()
    fireEvent.keyDown(second, {key: ' '})
    expect(await within(panel).findByRole('heading', {name: '第二条任务'})).toBeTruthy()
    expect(second.getAttribute('aria-selected')).toBe('true')
    expect(within(panel).getByRole('link', {name: /查看完整详情/}).getAttribute('href')).toBe(`/admin/faithsieve/${secondAttempt}`)
    expect(first.querySelector('.submission-problem-id')?.textContent).toBe('P0012')
    expect(first.querySelector('[data-model-family-logo]')).toBeTruthy()
    expect(first.querySelector('[data-harness-logo]')?.classList.contains('harness-logo--pi')).toBe(true)
    expect(panel.querySelector('[data-model-family-logo]')).toBeTruthy()
    expect(panel.querySelector('[data-harness-logo]')).toBeTruthy()
    expect(panel.querySelector('.faithsieve-graph')).toBeNull()
    expect(within(panel).getByLabelText('阶段摘要').textContent).toBe('Lean 编译运行中')
    expect(within(panel).queryByText('实际编译报告')).toBeNull()
    expect(panel.querySelector('.submission-detail-meta')).toBeNull()
    expect(within(panel).getAllByRole('link', {name: /查看完整详情/})).toHaveLength(1)
  })
  it('筛选与状态保留URL，使用后端clamp后的页码', async () => {
    currentPage = 2; totalPages = 2
    renderPage('/admin/faithsieve?page=99&username=alice&problem_id=12&submission_id=31&status=running')
    await screen.findByRole('table', {name: 'Faith Sieve 任务'})
    expect(screen.getByRole('link', {name: '2'}).getAttribute('aria-current')).toBe('page')
    expect(screen.queryByRole('link', {name: '下一页'})).toBeNull()
    const previous = screen.getByRole('link', {name: '上一页'}).getAttribute('href')!
    expect(previous).toContain('page=1')
    expect(previous).toContain('username=alice')
    expect(previous).toContain('submission_id=31')
    expect(screen.getByLabelText('学生').getAttribute('maxlength')).toBe('50')
    fireEvent.change(screen.getByLabelText('学生'), {target: {value: 'bob'}})
    fireEvent.click(screen.getByRole('button', {name: '应用筛选'}))
    await waitFor(() => expect(screen.getByLabelText('当前地址').textContent).toContain('username=bob'))
    expect(screen.getByLabelText('当前地址').textContent).not.toContain('page=99')
  })
  it('手机整行进入详情且不建立隐藏预览请求', async () => {
    desktop = false
    renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText('Faith Sieve #7，运行中')
    expect(detailCalls).toBe(0)
    fireEvent.click(row)
    expect(await screen.findByRole('heading', {name: 'Faith Sieve #7'})).toBeTruthy()
    expect(screen.getByLabelText('当前地址').textContent).toBe(`/admin/faithsieve/${firstAttempt}`)
  })
  it('列表活动任务轮询并在全部终态后停止', async () => {
    renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText('Faith Sieve #7，运行中')
    expect(within(row).getByRole('status', {name: '运行中'})).toBeTruthy()
    status = 'completed'
    await screen.findByLabelText('Faith Sieve #7，已完成', {}, {timeout: 4_000})
    expect(within(row).getByLabelText('得分 5 / 5')).toBeTruthy()
    expect(within(row).queryByRole('status')).toBeNull()
    const finishedCalls = listCalls
    await act(async () => {await new Promise((resolve) => setTimeout(resolve, 2_700))})
    expect(listCalls).toBe(finishedCalls)
  }, 10_000)
  it('Skill列表和预览显示方式logo及Judge入口，不显示DAG', async () => {
    executionMode = 'skill'
    renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText('Faith Sieve #7，运行中')
    expect(row.querySelector('svg[data-execution-mode-logo="skill"]')).toBeTruthy()
    const panel = screen.getByLabelText('Faith Sieve 预览')
    expect(await within(panel).findByLabelText('阶段摘要')).toBeTruthy()
    expect(within(panel).getByLabelText('阶段摘要').textContent).toBe('FaithSieve Skill运行中')
    expect(within(panel).getByRole('link', {name: /Judge 会话/}).getAttribute('href')).toBe('/agents/fs-skill-session')
    expect(within(panel).getByRole('link', {name: /查看 Agent 会话/}).getAttribute('href')).toBe('/agents/fs-skill-session')
    expect(panel.querySelector('.faithsieve-graph')).toBeNull()
    fireEvent.click(within(row).getByRole('link', {name: '打开 Faith Sieve #7 的完整详情'}))
    expect(await screen.findByText('Agent 会话')).toBeTruthy()
    expect(screen.getByLabelText('当前地址').textContent).toBe('/agents/fs-skill-session')
  })
  it.each([['queued', '排队中'], ['running', '运行中']])('%s只显示加载动画，尚不显示分数', async (value, label) => {
    status = value
    renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText(`Faith Sieve #7，${label}`)
    expect(within(row).getByRole('status', {name: label})).toBeTruthy()
    expect(row.querySelector('.submission-score')).toBeNull()
  })
  it.each([0, 5])('已完成时保留实际分数%s', async (score) => {
    status = 'completed'; completedScore = score
    renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText('Faith Sieve #7，已完成')
    expect(within(row).getByLabelText(`得分 ${score} / 5`)).toBeTruthy()
    expect(within(row).queryByRole('status')).toBeNull()
  })
  it.each([['failed', '失败'], ['inconclusive', '无结论']])('%s只显示终态图标，不继续加载或误显示0分', async (value, label) => {
    status = value
    renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText(`Faith Sieve #7，${label}`)
    expect(within(row).getByRole('img', {name: label}).getAttribute('title')).toBeNull()
    expect(within(row).queryByText(label)).toBeNull()
    expect(row.querySelector('.submission-col-result')?.textContent).toBe('')
    expect(within(row).queryByRole('status')).toBeNull()
    expect(row.querySelector('.submission-score')).toBeNull()
  })
  it('手机Skill整行直接打开会话，不请求FaithSieve详情', async () => {
    executionMode = 'skill'; desktop = false
    renderPage('/admin/faithsieve')
    fireEvent.click(await screen.findByLabelText('Faith Sieve #7，运行中'))
    expect(await screen.findByText('Agent 会话')).toBeTruthy()
    expect(screen.getByLabelText('当前地址').textContent).toBe('/agents/fs-skill-session')
    expect(detailCalls).toBe(0)
  })
  it('排队Skill在会话创建前禁用详情入口，拿到会话编号后启用', async () => {
    executionMode = 'skill'; status = 'queued'; sessionAvailable = false
    const client = renderPage('/admin/faithsieve')
    const row = await screen.findByLabelText('Faith Sieve #7，排队中')
    expect((within(row).getByRole('button', {name: 'Faith Sieve #7 的会话尚未创建'}) as HTMLButtonElement).disabled).toBe(true)
    expect(within(row).queryByRole('link', {name: '打开 Faith Sieve #7 的完整详情'})).toBeNull()
    await act(async () => {client.setQueriesData<FaithSieveListResponse>({queryKey: ['faithsieve-list']}, (data) => data ? {...data, runs: data.runs.map((item) => ({...item, session_id: 'new-skill-session'}))} : data)})
    expect(within(row).getByRole('link', {name: '打开 Faith Sieve #7 的完整详情'}).getAttribute('href')).toBe('/agents/new-skill-session')
  })
})

describe('Faith Sieve 详情', () => {
  it('右上角展示本次费用，随详情刷新更新，缺失历史用量显示未知', async () => {
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    const header = await screen.findByLabelText('Faith Sieve 摘要')
    const unknown = within(header).getByLabelText('本次费用：费用尚未记录')
    expect(unknown.textContent).toBe('—')
    expect(unknown.querySelector('svg.faithsieve-cost-logo[aria-hidden="true"]')).toBeTruthy()
    expect(unknown.closest('.faithsieve-execution')).toBeTruthy()
    cost = {cost_rmb: '0.002104', currency: 'CNY', complete: false, estimated: false, missing_usage: true, request_count: 2}
    await act(async () => {await client.refetchQueries({queryKey: faithSieveDetailQueryKey(firstAttempt)})})
    const partial = await within(header).findByLabelText('本次费用：人民币0.002104元，费用仍在汇总')
    expect(partial.textContent).toBe('0.00')
    expect(within(header).queryByText('已记录')).toBeNull()
    expect(partial.getAttribute('title')).toBe('人民币0.002104元，费用仍在汇总')
    cost = {cost_rmb: '0.002104', currency: 'CNY', complete: true, estimated: true, missing_usage: false, request_count: 3}
    await act(async () => {await client.refetchQueries({queryKey: faithSieveDetailQueryKey(firstAttempt)})})
    const updated = await within(header).findByLabelText('本次费用：人民币0.002104元，包含估算费用')
    expect(updated.textContent).toBe('≈0.00')
    expect(updated.getAttribute('title')).toBe('人民币0.002104元，包含估算费用')
    expect(header.querySelector('[data-harness-name="pi"]')).toBeTruthy()
    client.clear()
  })
  it.each([
    ['failed', 'workflow', undefined], ['failed', 'workflow', false],
    ['running', 'workflow', true], ['queued', 'workflow', true],
    ['completed', 'workflow', true], ['inconclusive', 'workflow', true],
  ] as const)('仅明确可恢复的workflow失败提供继续入口（%s/%s/%s）', async (value, mode, eligible) => {
    status = value; executionMode = mode; retryEligible = eligible
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    await screen.findByRole('heading', {name: 'Faith Sieve #7'})
    expect(screen.queryByRole('button', {name: '继续评测'})).toBeNull()
    expect(retryCalls).toBe(0)
  })
  it('继续评测只提交一次空请求，保留runtime与历史阶段，刷新失败后恢复轮询到最终结果', async () => {
    vi.useFakeTimers()
    status = 'failed'; retryEligible = true; endpointFailure = true
    let finishRetry!: (response: Response) => void
    retryHandler = () => new Promise((resolve) => {finishRetry = resolve})
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    client.setQueryData(['faithsieve-list', ''], {success: true, runs: []})
    await act(async () => {await vi.advanceTimersByTimeAsync(0)})
    fireEvent.click(screen.getByRole('button', {name: /原稿核对，Judge/}))
    const button = screen.getByRole('button', {name: '继续评测'})
    expect(button.classList.contains('submission-button--ghost')).toBe(true)
    fireEvent.click(button)
    fireEvent.click(button)
    await act(async () => {await vi.advanceTimersByTimeAsync(0)})
    expect((screen.getByRole('button', {name: '提交中…'}) as HTMLButtonElement).disabled).toBe(true)
    expect(retryCalls).toBe(1)
    const request = vi.mocked(fetch).mock.calls.find(([input]) => String(input).endsWith('/retry'))![1]!
    expect(request.method).toBe('POST')
    expect(request.body).toBeUndefined()
    expect(request.credentials).toBe('same-origin')
    expect(screen.queryByRole('dialog')).toBeNull()
    status = 'queued'; retryEligible = false; detailFailuresRemaining = 1
    await act(async () => {
      finishRetry(new Response(JSON.stringify({success: true, attempt_id: firstAttempt, status: 'queued'}), {status: 200, headers: {'Content-Type': 'application/json'}}))
      await vi.advanceTimersByTimeAsync(0)
    })
    const cached = client.getQueryData<FaithSieveDetailResponse>(faithSieveDetailQueryKey(firstAttempt))!
    expect(cached.run.status).toBe('queued')
    expect(cached.run.runtime).toEqual(run.runtime)
    expect(cached.run.retry_eligible).toBe(false)
    expect(client.getQueryState(['faithsieve-list', ''])?.isInvalidated).toBe(true)
    expect(screen.queryByRole('button', {name: '继续评测'})).toBeNull()
    expect(screen.getByLabelText('所选阶段详情').textContent).toContain('第一轮原稿报告')
    expect(screen.queryByText('暂时不可读取任务')).toBeNull()
    status = 'running'; endpointFailure = false
    await act(async () => {await vi.advanceTimersByTimeAsync(5_001)})
    expect(client.getQueryData<FaithSieveDetailResponse>(faithSieveDetailQueryKey(firstAttempt))!.run.status).toBe('running')
    status = 'completed'
    await act(async () => {await vi.advanceTimersByTimeAsync(2_501)})
    fireEvent.click(screen.getByRole('button', {name: /评测结果，结果/}))
    expect(screen.getByLabelText('所选阶段详情').querySelector('.faithsieve-final-score')?.textContent).toBe('5/5')
    const terminalCalls = detailCalls
    await act(async () => {await vi.advanceTimersByTimeAsync(10_000)})
    expect(detailCalls).toBe(terminalCalls)
    expect(retryCalls).toBe(1)
  })
  it('恢复接口已返回running时按实际状态刷新，不重复提交', async () => {
    status = 'failed'; retryEligible = true
    retryHandler = () => {status = 'running'; retryEligible = false; return json({success: true, attempt_id: firstAttempt, status})}
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    fireEvent.click(await screen.findByRole('button', {name: '继续评测'}))
    await waitFor(() => expect(client.getQueryData<FaithSieveDetailResponse>(faithSieveDetailQueryKey(firstAttempt))!.run.status).toBe('running'))
    expect(screen.queryByRole('button', {name: '继续评测'})).toBeNull()
    expect(retryCalls).toBe(1)
  })
  it.each([400, 403, 409, 503])('继续评测%s失败显示后台说明并重新查询资格，不自动重发', async (httpStatus) => {
    status = 'failed'; retryEligible = true
    retryHandler = () => {
      retryEligible = false
      return Promise.resolve(new Response(JSON.stringify({success: false, message: '当前任务不可继续'}), {status: httpStatus, headers: {'Content-Type': 'application/json'}}))
    }
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    fireEvent.click(await screen.findByRole('button', {name: '继续评测'}))
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', '当前任务不可继续')
    await waitFor(() => expect(client.getQueryData<FaithSieveDetailResponse>(faithSieveDetailQueryKey(firstAttempt))!.run.retry_eligible).toBe(false))
    expect(screen.queryByRole('button', {name: '继续评测'})).toBeNull()
    expect(detailCalls).toBe(2)
    expect(retryCalls).toBe(1)
  })
  it('模型端点错误显示失败节点和安全错误说明，不显示已完成', async () => {
    status = 'failed'; endpointFailure = true
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    await screen.findByRole('heading', {name: 'Faith Sieve #7'})
    const node = screen.getByRole('button', {name: '独立审计证明状态树，LLM，失败'})
    expect(node.classList.contains('is-failed')).toBe(true)
    expect(node.classList.contains('is-completed')).toBe(false)
    fireEvent.click(node)
    const selected = screen.getByLabelText('所选阶段详情')
    expect(within(selected).getByText('失败').classList.contains('is-issue')).toBe(true)
    expect(within(selected).getByText('独立审计证明状态树：模型端点余额不足或需要付费（HTTP 402）')).toBeTruthy()
    expect(within(selected).queryByText('已完成')).toBeNull()
  })
  it.each([['refuted', '反驳成立'], ['inconclusive', '无结论']])('工具进程成功时仍显示数学结果%s', async (value, label) => {
    verificationStatus = value
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    await screen.findByRole('heading', {name: 'Faith Sieve #7'})
    const stage = screen.getByLabelText('所选阶段详情')
    fireEvent.click(within(stage).getByText('运行记录'))
    const check = within(stage).getByRole('heading', {name: '独立符号复验'}).closest('section')!
    expect(within(check).getByText(label)).toBeTruthy()
    expect(within(check).queryByText('通过')).toBeNull()
  })
  it.each(['queued', 'running', 'completed', 'failed', 'inconclusive'])('显示%s任务的原稿PDF、真实阶段与状态', async (value) => {
    status = value
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    expect(await screen.findByRole('heading', {name: 'Faith Sieve #7'})).toBeTruthy()
    const primary = screen.getByLabelText('学生解答 PDF')
    expect(await within(primary).findByTitle('submission-pdf')).toBeTruthy()
    expect(primary.classList.contains('submission-detail-primary')).toBe(true)
    expect(screen.getByLabelText('Faith Sieve 摘要').classList.contains('submission-detail-summary-card')).toBe(true)
    expect(screen.getByLabelText('Faith Sieve 摘要').querySelector('[data-model-family-logo]')).toBeTruthy()
    expect(screen.getByLabelText('Faith Sieve 摘要').querySelector('[data-harness-logo]')?.classList.contains('harness-logo--pi')).toBe(true)
    const workflow = screen.getByLabelText('Faith Sieve Workflow')
    expect(workflow.classList.contains('submission-detail-results')).toBe(true)
    expect(within(workflow).getByRole('button', {name: /Lean 编译，代码/})).toBeTruthy()
    if (value === 'failed' || value === 'inconclusive') expect(within(workflow).getByRole('button', {name: /Lean 编译，代码，未完成/})).toBeTruthy()
    if (value === 'inconclusive') expect(screen.queryByText('0')).toBeNull()
  })
  it('按需读取所选阶段历史工件、更新全文，并保持Judge只读链接', async () => {
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    await screen.findByRole('heading', {name: 'Faith Sieve #7'})
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes('/artifacts?'))).toBe(false)
    fireEvent.click(screen.getByRole('button', {name: /原稿核对，Judge/}))
    expect(screen.getByRole('link', {name: /Judge 会话/}).getAttribute('href')).toBe('/agents/fs-readonly')
    fireEvent.click(within(screen.getByLabelText('阶段工件')).getByRole('button', {name: /source.md/}))
    expect(await screen.findByRole('heading', {name: '第一轮原稿'})).toBeTruthy()
    const calls = vi.mocked(fetch).mock.calls.map(([input]) => String(input))
    expect(calls.some((url) => url.includes('stage_key=extract-1'))).toBe(true)
    fireEvent.click(screen.getByRole('button', {name: /Lean 编译，代码/}))
    fireEvent.click(within(screen.getByLabelText('阶段工件')).getByRole('button', {name: /proof.lean/}))
    expect(await screen.findByText('原文 compile-1 第一版')).toBeTruthy()
    expect(screen.queryByRole('heading', {name: '第一轮原稿'})).toBeNull()
    expect(client.getQueryData(faithSieveDetailQueryKey(firstAttempt))).toBeTruthy()
  })
  it('原提交或题目删除后仍能查看workflow', async () => {
    deleted = true
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    expect(await screen.findByText('原提交已删除')).toBeTruthy()
    expect(screen.getByRole('button', {name: /Lean 编译，代码/})).toBeTruthy()
    expect(screen.queryByTitle('submission-pdf')).toBeNull()
  })
  it.each(['skill', undefined] as const)('Skill及历史缺失mode（%s）详情地址直接转到Agent会话', async (mode) => {
    executionMode = mode
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    expect(await screen.findByText('Agent 会话')).toBeTruthy()
    expect(screen.getByLabelText('当前地址').textContent).toBe('/agents/fs-skill-session')
    expect(screen.queryByLabelText('Faith Sieve 摘要')).toBeNull()
    expect(screen.queryByTitle('submission-pdf')).toBeNull()
  })
  it.each([['queued', '等待 Agent 会话创建…'], ['failed', '该任务尚未创建 Agent 会话']])('Skill详情缺少会话时按%s状态提示', async (value, label) => {
    executionMode = 'skill'; status = value; sessionAvailable = false
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    expect(await screen.findByText(label)).toBeTruthy()
    expect(screen.queryByLabelText('Faith Sieve 摘要')).toBeNull()
  })
  it('Workflow阶段工件在运行时间更新后仍保留该阶段版本', async () => {
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    await screen.findByRole('heading', {name: 'Faith Sieve #7'})
    fireEvent.click(within(screen.getByLabelText('阶段工件')).getByRole('button', {name: /proof.lean/}))
    expect(await screen.findByText('原文 compile-1 第一版')).toBeTruthy()
    const artifactCalls = () => vi.mocked(fetch).mock.calls.filter(([input]) => String(input).includes('/artifacts?')).length
    expect(artifactCalls()).toBe(1)
    artifactVersion = '第二版'
    await act(async () => {client.setQueryData<FaithSieveDetailResponse>(faithSieveDetailQueryKey(firstAttempt), (current) => current ? {...current, run: {...current.run, updated_at: '2026-10-02 10:02:00'}} : current)})
    expect(screen.getByText('原文 compile-1 第一版')).toBeTruthy()
    expect(screen.queryByText('原文 compile-1 第二版')).toBeNull()
    expect(artifactCalls()).toBe(1)
  })
  it('活动任务轮询，取得终态后停止', async () => {
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    await screen.findByRole('heading', {name: 'Faith Sieve #7'})
    status = 'completed'
    const resultNode = await screen.findByRole('button', {name: /评测结果，结果/}, {timeout: 4_000})
    expect(screen.queryByText('证明成立')).toBeNull()
    fireEvent.click(resultNode)
    expect(screen.getByLabelText('所选阶段详情').querySelector('.faithsieve-report')?.textContent).toBe('证明成立')
    const finishedCalls = detailCalls
    await act(async () => {await new Promise((resolve) => setTimeout(resolve, 2_700))})
    expect(detailCalls).toBe(finishedCalls)
  }, 10_000)
  it.each(['initial', 'background'])('详情%s请求暂时失败后自动恢复并展示最终结果', async (phase) => {
    vi.useFakeTimers()
    if (phase === 'initial') detailFailuresRemaining = 1
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    await act(async () => {await vi.advanceTimersByTimeAsync(0)})
    if (phase === 'background') {
      expect(screen.getByRole('heading', {name: 'Faith Sieve #7'})).toBeTruthy()
      const node = screen.getByRole('button', {name: /原稿核对，Judge/})
      fireEvent.click(node)
      expect(screen.getByLabelText('所选阶段详情').textContent).toContain('第一轮原稿报告')
      detailFailuresRemaining = 1
      await act(async () => {await vi.advanceTimersByTimeAsync(2_500)})
      expect(screen.getByRole('heading', {name: 'Faith Sieve #7'})).toBeTruthy()
      expect(screen.getByLabelText('所选阶段详情').textContent).toContain('第一轮原稿报告')
      expect(screen.queryByText('暂时不可读取任务')).toBeNull()
    } else {
      expect(screen.getByText('暂时不可读取任务')).toBeTruthy()
      expect(screen.queryByRole('heading', {name: 'Faith Sieve #7'})).toBeNull()
    }
    expect(client.getQueryState(faithSieveDetailQueryKey(firstAttempt))?.status).toBe('error')
    status = 'completed'
    await act(async () => {await vi.advanceTimersByTimeAsync(5_001)})
    const resultNode = screen.getByRole('button', {name: /评测结果，结果/})
    fireEvent.click(resultNode)
    expect(screen.getByLabelText('所选阶段详情').querySelector('.faithsieve-report')?.textContent).toBe('证明成立')
    expect(screen.getByLabelText('所选阶段详情').querySelector('.faithsieve-final-score')?.textContent).toBe('5/5')
    expect(detailCalls).toBe(phase === 'initial' ? 2 : 3)
    const completedCalls = detailCalls
    await act(async () => {await vi.advanceTimersByTimeAsync(10_000)})
    expect(detailCalls).toBe(completedCalls)
  })
  it.each([401, 403, 404])('后台返回%s后隐藏旧详情并停止自动刷新', async (httpStatus) => {
    vi.useFakeTimers()
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    await act(async () => {await vi.advanceTimersByTimeAsync(0)})
    expect(screen.getByRole('heading', {name: 'Faith Sieve #7'})).toBeTruthy()
    detailFailuresRemaining = 1; detailFailureStatus = httpStatus
    await act(async () => {await vi.advanceTimersByTimeAsync(2_500)})
    expect(client.getQueryState(faithSieveDetailQueryKey(firstAttempt))?.status).toBe('error')
    expect(screen.getByText('暂时不可读取任务')).toBeTruthy()
    expect(screen.queryByRole('heading', {name: 'Faith Sieve #7'})).toBeNull()
    const deniedCalls = detailCalls
    await act(async () => {await vi.advanceTimersByTimeAsync(10_000)})
    expect(detailCalls).toBe(deniedCalls)
  })
  it('结论仅作为Workflow末节点，点击后展开', async () => {
    status = 'inconclusive'
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    const node = await screen.findByRole('button', {name: /评测结果，结果，无结论/})
    expect(screen.queryByText('无法核对原稿')).toBeNull()
    expect(screen.queryByLabelText('所选阶段详情')).toBeNull()
    expect(document.querySelector('.faithsieve-result')).toBeNull()
    fireEvent.click(node)
    expect(within(screen.getByLabelText('所选阶段详情')).getByText('无法核对原稿')).toBeTruthy()
  })
  it('证明状态树按需读取最新JSON，历史阶段保持自己的版本', async () => {
    withTree = true
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    const treeTab = await screen.findByRole('tab', {name: '证明状态树（历史）'})
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes('/artifacts?'))).toBe(false)
    fireEvent.click(treeTab)
    await waitFor(() => expect(screen.getByLabelText('证明状态树内容').querySelectorAll('[data-proof-node]')).toHaveLength(2))
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes('stage_key=tree-2'))).toBe(true)
    fireEvent.click(screen.getByRole('tab', {name: 'Workflow'}))
    fireEvent.click(screen.getByRole('button', {name: /建立证明状态树，LLM/}))
    fireEvent.click(screen.getByRole('button', {name: /查看证明状态树/}))
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes('stage_key=tree-1'))).toBe(true))
    expect(screen.getByText('所选阶段版本')).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', {name: '证明状态树（历史）'}))
    expect(screen.queryByText('所选阶段版本')).toBeNull()
    fireEvent.click(screen.getByRole('tab', {name: 'Workflow'}))
    fireEvent.click(screen.getByRole('button', {name: /独立审计证明状态树，LLM/}))
    fireEvent.click(screen.getByRole('button', {name: /查看证明状态树/}))
    expect(screen.getByText('所选阶段版本')).toBeTruthy()
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes('path=faithsieve-work%2Ftree.json') && String(input).includes('stage_key=tree-audit-1'))).toBe(false)
  })
  it('依赖图多父结论详情随宿主摘要刷新，阶段工件缓存不遮住验证进度', async () => {
    withDag = true
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    const tab = await screen.findByRole('tab', {name: '证明依赖图（历史）'})
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input).includes('/artifacts?'))).toBe(false)
    fireEvent.click(tab)
    const graph = await screen.findByLabelText('证明依赖图内容')
    await within(graph).findByText('前提待验证')
    await waitFor(() => expect(graph.querySelectorAll('[data-proof-node]')).toHaveLength(7), {timeout: 8_000})
    expect(graph.querySelectorAll('.faithsieve-proof-edge-line')).toHaveLength(6)
    expect(within(graph).getByText('\\((a+b)^2>0\\)')).toBeTruthy()
    expect(within(graph).getByText('\\((a+b)^3>0\\)')).toBeTruthy()
    expect(within(graph).queryByRole('button', {name: /证明步骤 E/})).toBeNull()
    const artifactCalls = () => vi.mocked(fetch).mock.calls.filter(([input]) => String(input).includes('/artifacts?')).length
    const before = artifactCalls()
    const canvas = graph.querySelector<HTMLElement>('.faithsieve-proof-canvas')!
    fireEvent.click(within(graph).getByRole('button', {name: '放大证明依赖图'}))
    const zoomed = canvas.style.transform
    expect(zoomed).not.toBe('scale(1)')
    dagVerification = Object.fromEntries(Object.entries(dagVerification).map(([id, item]) => [id, {...item, local_status: item.local_status === 'given' ? 'given' : 'passed', established: true, status: 'established', blocking_premise_ids: []}]))
    await act(async () => {await client.refetchQueries({queryKey: faithSieveDetailQueryKey(firstAttempt)})})
    expect(await within(graph).findByText('已成立')).toBeTruthy()
    expect(within(graph).queryByText('前提待验证')).toBeNull()
    expect(artifactCalls()).toBe(before)
    expect(graph.querySelector('.faithsieve-proof-canvas')).toBe(canvas)
    expect(canvas.style.transform).toBe(zoomed)
    expect(graph.querySelector('[data-proof-node="N9"]')?.classList.contains('is-established')).toBe(true)
    client.clear()
  })
  it('旧阶段依赖图不套用当前图的同名节点结果，返回当前图恢复摘要', async () => {
    withDag = true
    dagVerification = Object.fromEntries(Object.entries(dagVerification).map(([id, item]) => [id, {...item, local_status: item.local_status === 'given' ? 'given' : 'passed', established: true, status: 'established', blocking_premise_ids: []}]))
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    fireEvent.click(await screen.findByRole('tab', {name: '证明依赖图（历史）'}))
    expect(await screen.findByText('已成立')).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', {name: 'Workflow'}))
    fireEvent.click(screen.getByRole('button', {name: /建立证明依赖图，LLM/}))
    fireEvent.click(screen.getByRole('button', {name: /查看证明依赖图/}))
    expect(await screen.findByText('历史版本的结论')).toBeTruthy()
    const history = screen.getByLabelText('证明依赖图内容')
    expect(within(history).getByText('未验证')).toBeTruthy()
    expect(within(history).queryByText('已成立')).toBeNull()
    expect(screen.getByText('所选阶段版本')).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', {name: '证明依赖图（历史）'}))
    expect(await screen.findByText('已成立')).toBeTruthy()
    expect(screen.queryByText('历史版本的结论')).toBeNull()
    client.clear()
  })
  it('v2数值Agent显示节点定位和局部反驳，未返回代码检查不生成检查记录', async () => {
    withDag = true; verificationStatus = 'refuted'; status = 'completed'
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    fireEvent.click(await screen.findByRole('button', {name: /数值验证，Judge，推理被反驳.*结论 N9/}))
    const stage = screen.getByLabelText('所选阶段详情')
    expect(within(stage).getByText('推理被反驳')).toBeTruthy()
    expect(within(stage).queryByText('独立符号复验')).toBeNull()
    fireEvent.click(within(stage).getByText('运行记录'))
    expect(within(stage).getByText('证明结论')).toBeTruthy()
    expect(within(stage).getByText('N9')).toBeTruthy()
    client.clear()
  })
  it('v3直接图像流程显示真实代码与Judge阶段，依赖图没有来源转录且结果由末节点展开', async () => {
    withDag = true; dagVersion = 3; status = 'inconclusive'
    const client = renderPage(`/admin/faithsieve/${firstAttempt}`)
    const graphTab = await screen.findByRole('tab', {name: '证明依赖图'})
    expect(screen.queryByRole('tab', {name: '证明依赖图（历史）'})).toBeNull()
    expect(screen.queryByRole('button', {name: /原稿核对，Judge/})).toBeNull()
    expect(screen.queryByRole('button', {name: /拆分/})).toBeNull()
    const rendered = screen.getByRole('button', {name: /渲染原稿图片，代码/})
    expect(screen.getByRole('button', {name: /验证局部命题，Judge，已完成，结论 N9/})).toBeTruthy()
    expect(document.querySelectorAll('[data-stage-key]')).toHaveLength(5)
    expect(document.querySelectorAll('.faithsieve-graph-edge')).toHaveLength(4)
    fireEvent.click(rendered)
    expect(within(screen.getByLabelText('所选阶段详情')).getByText('7 页 PNG')).toBeTruthy()
    expect(screen.queryByText('核对记录')).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: /验证局部命题，Judge/}))
    expect(within(screen.getByLabelText('所选阶段详情')).getByRole('link', {name: /Judge 会话/}).getAttribute('href')).toBe('/agents/fs-node-N9')
    fireEvent.click(screen.getByRole('button', {name: /生成证明依赖图，LLM/}))
    fireEvent.click(screen.getByRole('button', {name: /查看证明依赖图/}))
    const graph = await screen.findByLabelText('证明依赖图内容')
    expect(await within(graph).findByText('前提待验证')).toBeTruthy()
    await waitFor(() => expect(graph.querySelectorAll('[data-proof-node]')).toHaveLength(7), {timeout: 8_000})
    expect(within(graph).getByText('\\((a+b)^2>0\\)')).toBeTruthy()
    expect(within(graph).getByText('\\((a+b)^3>0\\)')).toBeTruthy()
    expect(within(graph).queryByText('原文')).toBeNull()
    expect(graph.querySelector('.faithsieve-proof-source')).toBeNull()
    expect(within(graph).queryByText('S4、S12')).toBeNull()
    expect(graphTab.getAttribute('aria-selected')).toBe('true')
    expect(document.querySelector('[data-harness-logo]')).toBeTruthy()
    expect(document.querySelector('[data-model-family-logo]')).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', {name: 'Workflow'}))
    expect(screen.queryByText('部分依赖结论尚未成立')).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: /评测结果，结果，无结论/}))
    expect(within(screen.getByLabelText('所选阶段详情')).getByText('部分依赖结论尚未成立')).toBeTruthy()
    client.clear()
  })
  it('后端未确认的JSON即使可解析也不能重新放行绘图', async () => {
    withTree = true; brokenTree = true
    renderPage(`/admin/faithsieve/${firstAttempt}`)
    fireEvent.click(await screen.findByRole('tab', {name: '证明状态树（历史）'}))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText('证明状态树未通过结构校验')).toBeTruthy()
    expect(screen.getByLabelText('证明状态树内容').querySelector('svg')).toBeNull()
  })
})

describe('Faith Sieve 权限', () => {
  it.each(['/admin/faithsieve', `/admin/faithsieve/${firstAttempt}`])('非管理员不能访问%s或请求其API', async (path) => {
    admin = false; status = 'failed'; retryEligible = true
    renderPage(path)
    expect(await screen.findByText('该页面仅管理员可访问')).toBeTruthy()
    expect(detailCalls).toBe(0)
    expect(listCalls).toBe(0)
    expect(retryCalls).toBe(0)
    expect(screen.queryByRole('button', {name: '继续评测'})).toBeNull()
  })
})
