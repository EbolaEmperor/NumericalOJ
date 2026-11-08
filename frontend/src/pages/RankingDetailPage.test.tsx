// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {act, cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {MemoryRouter, Route, Routes} from 'react-router-dom'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {SessionProvider} from '../session'
import RankingDetailPage from './RankingDetailPage'

function response(payload: object) {
  return Promise.resolve(new Response(JSON.stringify({success: true, ...payload}), {status: 200, headers: {'Content-Type': 'application/json'}}))
}

async function showSubmit(scoringMode = 'reverse_judge', endpoints = [{id: 11, harness: 'pi', model: 'first-model'}, {id: 22, harness: 'claude_code', model: 'selected-model'}]) {
  const posts = vi.fn((_body: FormData) => response({submission_id: 73}))
  vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({user: {id: 1, username: 'student', is_admin: 0}, navigation: {counts: {}}})
    if (url === '/ranking/7/navigation-state') return response({navigation: {scoring_mode: scoringMode, is_active: true}})
    if (url === '/api/ranking/competitions/7?tab=submit') return response({competition: {id: 7, title: '测试评测', scoring_mode: scoringMode, is_active: 1}, tab: 'submit', answer_endpoints: endpoints, user_submissions: []})
    if (url === '/api/ranking/competitions/7/submissions' && init?.method === 'POST') return posts(init.body as FormData)
    throw new Error(`unexpected fetch: ${url}`)
  }))
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/rankings/7?tab=submit']}><SessionProvider><Routes><Route path="/rankings/:competitionId" element={<RankingDetailPage />} /></Routes></SessionProvider></MemoryRouter></QueryClientProvider>)
  await screen.findByRole('heading', {name: '测试评测'})
  if (scoringMode === 'reverse_judge') {
    fireEvent.click(screen.getByRole('button', {name: '提交方式'}))
    fireEvent.click(screen.getByRole('option', {name: 'ZIP 压缩包'}))
  }
  return posts
}

async function showJudgeSettings(orchestration?: string, scoringMode = 'agent_judge', files: Record<string, unknown>[] = [], gate: {timeout?: number; enabled?: boolean; prompt?: string; endpoints?: Record<string, unknown>[]} = {}) {
  const competition = {id: 7, title: '测试编排设置', scoring_mode: scoringMode, is_active: 1, agent_judge_orchestration_mode: orchestration, reverse_quality_gate_timeout_seconds: gate.timeout, reverse_quality_gate_enabled: gate.enabled, reverse_quality_gate_prompt: gate.prompt}
  let qualityGateEndpoints = gate.endpoints || []
  const posts = vi.fn((body: {orchestration_mode?: string}) => {
    if (body.orchestration_mode) competition.agent_judge_orchestration_mode = body.orchestration_mode
    return response({endpoints: [], orchestration_mode: competition.agent_judge_orchestration_mode})
  })
  const gatePosts = vi.fn((body: {enabled: boolean; prompt: string; timeout_seconds: number; endpoints: Record<string, unknown>[]}) => {
    competition.reverse_quality_gate_enabled = body.enabled
    competition.reverse_quality_gate_prompt = body.prompt
    competition.reverse_quality_gate_timeout_seconds = body.timeout_seconds
    qualityGateEndpoints = body.endpoints
    return response({...body})
  })
  vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/session') return response({user: {id: 1, username: 'admin', is_admin: 1}, navigation: {counts: {}}})
    if (url === '/ranking/7/navigation-state') return response({navigation: {scoring_mode: scoringMode, is_active: true}})
    if (url === '/api/ranking/competitions/7?tab=edit') return response({competition, tab: 'edit', is_admin: true, files, aj_endpoints: [], quality_gate_endpoints: qualityGateEndpoints, judge_rules: []})
    if (url === '/api/ranking/competitions/7/agent-judge/endpoints' && init?.method === 'POST') return posts(JSON.parse(String(init.body)))
    if (url === '/api/ranking/competitions/7/reverse-judge/quality-gate' && init?.method === 'POST') return gatePosts(JSON.parse(String(init.body)))
    throw new Error(`unexpected fetch: ${url}`)
  }))
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/rankings/7?tab=edit']}><SessionProvider><Routes><Route path="/rankings/:competitionId" element={<RankingDetailPage />} /></Routes></SessionProvider></MemoryRouter></QueryClientProvider>)
  await screen.findByRole('heading', {name: '测试编排设置'})
  return {posts, gatePosts, client, competition}
}

function applyAuditTime(seconds: string) {
  fireEvent.click(screen.getByRole('button', {name: '设置审核时间'}))
  const dialog = screen.getByRole('dialog', {name: '设置审核时间'})
  fireEvent.change(within(dialog).getByRole('textbox', {name: '审核时间上限'}), {target: {value: seconds}})
  fireEvent.click(within(dialog).getByRole('button', {name: '应用修改'}))
}

function saveQualityGate() {
  fireEvent.click(within(document.querySelector('.qge-shell')! as HTMLElement).getByRole('button', {name: '保存'}))
}

function fileInput(kind: string) {
  return document.querySelector<HTMLInputElement>(`input[name="${kind}_file"]`)!
}

beforeEach(() => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn()})))
})
afterEach(() => {cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks()})

describe('打榜赛提交文件', () => {
  it.each(['拖入', '点选'])('反向 ZIP %s文件后点击提交会发送文件与选中节点', async (method) => {
    const posts = await showSubmit()
    expect(screen.getByText('Harbor 任务包')).toBeTruthy()
    const guide = screen.getByRole('link', {name: 'Harbor 格式说明'})
    expect(guide.getAttribute('href')).toBe('/rankings/harbor-guide')
    expect(guide.closest('.ranking-competition-title-line')).toBeTruthy()
    expect(document.querySelector('[data-reverse-harbor-guide]')).toBeNull()
    expect(screen.queryByText('从你的仓库拉取最新内容并评测')).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: /^AI 节点：/}))
    fireEvent.click(screen.getByRole('option', {name: /selected-model/}))
    const archive = new File(['ZIP CONTENT'], 'problem.zip', {type: 'application/zip'})
    const input = fileInput('code')
    if (method === '拖入') fireEvent.drop(input.closest('label')!, {dataTransfer: {files: [archive]}})
    else fireEvent.change(input, {target: {files: [archive]}})
    expect(screen.getByText('problem.zip')).toBeTruthy()
    const submit = screen.getByRole('button', {name: '提交评测'}) as HTMLButtonElement
    expect(submit.disabled).toBe(false)
    if (method === '拖入') {
      expect(input.files?.length).toBe(0)
      const required = input.required
      input.required = true // 重演旧页面：React 已有文件，隐藏的原生控件仍被判断为空。
      expect(input.validity.valueMissing).toBe(true)
      fireEvent.click(submit)
      expect(posts).not.toHaveBeenCalled()
      input.required = required
    }
    // 点击真实 submit 按钮，保留浏览器原生表单校验，不能 fireEvent.submit 绕过它。
    fireEvent.click(submit)
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    const body = posts.mock.calls[0][0]
    expect(body).toBeInstanceOf(FormData)
    expect((body.get('code_file') as File).name).toBe('problem.zip')
    expect((body.get('code_file') as File).size).toBe(archive.size)
    expect(body.get('agent_endpoint_id')).toBe('22')
    expect(body.has('base_model')).toBe(false)
  })

  it('普通评测仍要求答案、代码和非空基座模型', async () => {
    const posts = await showSubmit('absolute')
    expect(document.querySelector('[data-reverse-harbor-guide]')).toBeNull()
    expect(screen.queryByRole('link', {name: 'Harbor 格式说明'})).toBeNull()
    const submit = screen.getByRole('button', {name: '提交评测'}) as HTMLButtonElement
    const archive = new File(['CODE'], 'code.zip')
    const answer = new File(['{}'], 'answer.json')
    expect(submit.disabled).toBe(true)
    fireEvent.drop(fileInput('code').closest('label')!, {dataTransfer: {files: [archive]}})
    expect(submit.disabled).toBe(true)
    fireEvent.drop(fileInput('answer').closest('label')!, {dataTransfer: {files: [answer]}})
    expect(submit.disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', {name: /基座模型/}), {target: {value: '   '}})
    expect(submit.disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', {name: /基座模型/}), {target: {value: ' model-name '}})
    expect(submit.disabled).toBe(false)
    fireEvent.click(submit)
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    const body = posts.mock.calls[0][0]
    expect(body.get('base_model')).toBe('model-name')
    expect((body.get('answer_file') as File).name).toBe('answer.json')
    expect((body.get('code_file') as File).name).toBe('code.zip')
    expect(body.has('agent_endpoint_id')).toBe(false)
  })

  it('反向评测未选文件或没有可用节点时仍不能提交', async () => {
    const posts = await showSubmit('reverse_judge', [])
    const submit = screen.getByRole('button', {name: '提交评测'}) as HTMLButtonElement
    expect(submit.disabled).toBe(true)
    fireEvent.drop(fileInput('code').closest('label')!, {dataTransfer: {files: [new File(['ZIP'], 'problem.zip')]}})
    expect(submit.disabled).toBe(true)
    fireEvent.click(submit)
    expect(posts).not.toHaveBeenCalled()
  })
})

describe('Agent Judge 编排设置', () => {
  it.each([undefined, 'single', 'topological'])('读取 %s 模式、切换保存，并同步服务端更新', async (initial) => {
    const {posts, client, competition} = await showJudgeSettings(initial)
    const currentLabel = initial === 'topological' ? '拓扑序编排' : '一次性评测'
    const nextMode = initial === 'topological' ? 'single' : 'topological'
    const nextLabel = nextMode === 'single' ? '一次性评测' : '拓扑序编排'
    const choice = screen.getByRole('combobox', {name: '评测编排'})
    expect(choice.textContent).toContain(currentLabel)
    fireEvent.click(choice)
    fireEvent.click(screen.getByRole('option', {name: nextLabel}))
    fireEvent.click(screen.getByRole('button', {name: '保存'}))
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    expect(posts.mock.calls[0][0].orchestration_mode).toBe(nextMode)
    expect(posts.mock.calls[0][0]).toHaveProperty('reverse_judge_finalize_timeout_seconds', 180)
    await screen.findByText('已保存')
    expect(choice.textContent).toContain(nextLabel)
    competition.agent_judge_orchestration_mode = initial || 'single'
    await act(() => client.invalidateQueries({queryKey: ['ranking', '7']}))
    await waitFor(() => expect(choice.textContent).toContain(currentLabel))
  })

  it('反向评测保留作答与审核时间，不展示或提交收尾超时和编排配置', async () => {
    const {posts, competition} = await showJudgeSettings('topological', 'reverse_judge')
    expect(screen.queryByRole('combobox', {name: '评测编排'})).toBeNull()
    expect(screen.queryByRole('textbox', {name: '收尾超时'})).toBeNull()
    expect(screen.getByRole('textbox', {name: 'AI 作答超时'})).toBeTruthy()
    expect(screen.getByRole('button', {name: '设置审核时间'}).textContent).toContain('30 分钟')
    fireEvent.click(screen.getAllByRole('button', {name: '保存'})[0])
    await waitFor(() => expect(posts).toHaveBeenCalledTimes(1))
    expect(posts.mock.calls[0][0]).not.toHaveProperty('orchestration_mode')
    expect(posts.mock.calls[0][0]).not.toHaveProperty('reverse_judge_finalize_timeout_seconds')
    expect(competition.agent_judge_orchestration_mode).toBe('topological')
  })

  it('默认 Harbor 模板显示为附件并保留下载入口，不提供删除按钮', async () => {
    const url = '/api/ranking/competitions/7/attachments/harbor-template/download'
    await showJudgeSettings(undefined, 'reverse_judge', [{id: 'harbor-template', builtin: true, filename: 'harbor-template.zip', download_url: url, file_size: 2048}])
    expect(screen.getByRole('link', {name: /harbor-template.zip/}).getAttribute('href')).toBe(url)
    const row = screen.getByText('默认模板').closest('.list-group-item')!
    expect(row.querySelector('a')?.getAttribute('href')).toBe(url)
    expect(row.querySelector('button')).toBeNull()
  })
})

describe('反向评测审核时间', () => {
  it('默认30分钟，取消弹窗不改草稿，统一保存时发送1800秒', async () => {
    const {gatePosts} = await showJudgeSettings(undefined, 'reverse_judge')
    const trigger = screen.getByRole('button', {name: '设置审核时间'})
    expect(trigger.textContent).toContain('30 分钟')
    expect(trigger.closest('.qge-config-title-tools')?.textContent).toContain('审核标准')
    fireEvent.click(trigger)
    const dialog = screen.getByRole('dialog', {name: '设置审核时间'})
    const input = within(dialog).getByRole('textbox', {name: '审核时间上限'}) as HTMLInputElement
    expect(input.type).toBe('text')
    expect(input.value).toBe('1800')
    fireEvent.change(input, {target: {value: '2400'}})
    fireEvent.click(within(dialog).getByRole('button', {name: '取消'}))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(trigger.textContent).toContain('30 分钟')
    expect(screen.queryByText('未保存')).toBeNull()
    expect(gatePosts).not.toHaveBeenCalled()
    saveQualityGate()
    await waitFor(() => expect(gatePosts).toHaveBeenCalledTimes(1))
    expect(gatePosts.mock.calls[0][0].timeout_seconds).toBe(1800)
  })

  it('应用时间仅更新草稿，保存时一起保留审核标准、启用状态和端点', async () => {
    const endpoints = [{id: 8, harness: 'pi', model: '审核模型', concurrency_limit: 2, status: 'enabled', has_key: true}]
    const {gatePosts, posts} = await showJudgeSettings(undefined, 'reverse_judge', [], {timeout: 600, enabled: true, prompt: '原有标准', endpoints})
    fireEvent.change(screen.getByRole('textbox', {name: '质量门禁审核标准'}), {target: {value: '更新后的审核标准'}})
    fireEvent.click(screen.getByRole('checkbox', {name: '启用'}))
    applyAuditTime('90')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('button', {name: '设置审核时间'}).textContent).toContain('1 分 30 秒')
    expect(screen.getByText('未保存')).toBeTruthy()
    expect(gatePosts).not.toHaveBeenCalled()
    saveQualityGate()
    await waitFor(() => expect(gatePosts).toHaveBeenCalledTimes(1))
    expect(gatePosts.mock.calls[0][0]).toEqual({timeout_seconds: 90, prompt: '更新后的审核标准', enabled: false, endpoints})
    expect(posts).not.toHaveBeenCalled()
    await waitFor(() => expect(screen.queryByText('未保存')).toBeNull())
  })

  it.each(['59', '7201', '60.5'])('拒绝非法审核时间%s，且不提前保存', async (seconds) => {
    const {gatePosts} = await showJudgeSettings(undefined, 'reverse_judge')
    applyAuditTime(seconds)
    expect(screen.getByRole('alert').textContent).toContain('60–7200 秒的整数')
    expect(screen.getByRole('dialog', {name: '设置审核时间'})).toBeTruthy()
    expect(screen.getByRole('button', {name: '设置审核时间'}).textContent).toContain('30 分钟')
    expect(gatePosts).not.toHaveBeenCalled()
  })

  it('自定义步进按钮遵守上下界，允许60秒和7200秒', async () => {
    await showJudgeSettings(undefined, 'reverse_judge')
    fireEvent.click(screen.getByRole('button', {name: '设置审核时间'}))
    const dialog = screen.getByRole('dialog', {name: '设置审核时间'})
    const input = within(dialog).getByRole('textbox', {name: '审核时间上限'}) as HTMLInputElement
    fireEvent.change(input, {target: {value: '60'}})
    fireEvent.click(within(dialog).getByRole('button', {name: '减少审核时间上限'}))
    expect(input.value).toBe('60')
    fireEvent.click(within(dialog).getByRole('button', {name: '应用修改'}))
    expect(screen.getByRole('button', {name: '设置审核时间'}).textContent).toContain('1 分钟')
    fireEvent.click(screen.getByRole('button', {name: '设置审核时间'}))
    const nextDialog = screen.getByRole('dialog', {name: '设置审核时间'})
    const nextInput = within(nextDialog).getByRole('textbox', {name: '审核时间上限'}) as HTMLInputElement
    fireEvent.change(nextInput, {target: {value: '7200'}})
    fireEvent.click(within(nextDialog).getByRole('button', {name: '增加审核时间上限'}))
    expect(nextInput.value).toBe('7200')
    fireEvent.click(within(nextDialog).getByRole('button', {name: '应用修改'}))
    expect(screen.getByRole('button', {name: '设置审核时间'}).textContent).toContain('120 分钟')
  })

  it('干净状态跟随服务端时间更新，未保存的时间不会被刷新覆盖', async () => {
    const {client, competition, gatePosts} = await showJudgeSettings(undefined, 'reverse_judge', [], {timeout: 600})
    const trigger = screen.getByRole('button', {name: '设置审核时间'})
    expect(trigger.textContent).toContain('10 分钟')
    competition.reverse_quality_gate_timeout_seconds = 1200
    await act(() => client.invalidateQueries({queryKey: ['ranking', '7']}))
    await waitFor(() => expect(trigger.textContent).toContain('20 分钟'))
    applyAuditTime('900')
    competition.reverse_quality_gate_timeout_seconds = 1800
    await act(() => client.invalidateQueries({queryKey: ['ranking', '7']}))
    expect(trigger.textContent).toContain('15 分钟')
    expect(screen.getByText('未保存')).toBeTruthy()
    expect(gatePosts).not.toHaveBeenCalled()
  })

  it('保存期间再次修改时间仍保留未保存提示', async () => {
    const {gatePosts, competition} = await showJudgeSettings(undefined, 'reverse_judge')
    let finishSave: (() => void) | undefined
    gatePosts.mockImplementationOnce((body) => new Promise<Response>((resolve) => {
      finishSave = () => {
        competition.reverse_quality_gate_timeout_seconds = body.timeout_seconds
        void response({endpoints: body.endpoints}).then(resolve)
      }
    }))
    applyAuditTime('2400')
    saveQualityGate()
    await waitFor(() => expect(gatePosts).toHaveBeenCalledTimes(1))
    applyAuditTime('3600')
    await act(async () => {finishSave?.()})
    await waitFor(() => expect(screen.getByRole('button', {name: '设置审核时间'}).textContent).toContain('60 分钟'))
    expect(gatePosts.mock.calls[0][0].timeout_seconds).toBe(2400)
    expect(screen.getByText('未保存')).toBeTruthy()
  })
})
