// @vitest-environment jsdom

import {QueryClient, QueryClientProvider} from '@tanstack/react-query'
import {cleanup, fireEvent, render, screen, waitFor, within} from '@testing-library/react'
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

import {RejudgeFilters} from './RejudgeFilters'

interface FilterBody {
  usernames: string[]
  problem_ids: number[]
  statuses: string[]
  start?: string
  end?: string
  confirm_total?: number
  confirmation_token?: string
}

interface Reply {
  payload: Record<string, unknown>
  status?: number
}

const options = {
  usernames: ['alice', 'bob'],
  problem_options: [{problem_id: 11, filter_label: 'P0011 · 第一题'}, {problem_id: 12, filter_label: 'P0012 · 第二题'}],
  statuses: ['Pending', 'Accepted', 'Wrong Answer'],
}

let requests: FilterBody[]
let replies: Reply[]
let optionsError: boolean
let statusRequests: number
let statusUrls: string[]
let statusOptions: string[]
let clients: QueryClient[]

function response(payload: Record<string, unknown>, status = 200) {
  return Promise.resolve(new Response(JSON.stringify({success: status < 400, ...payload}), {status, headers: {'Content-Type': 'application/json'}}))
}

function renderFilters() {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}, mutations: {retry: false}}})
  clients.push(client)
  return render(<QueryClientProvider client={client}><RejudgeFilters /></QueryClientProvider>)
}

async function openFilters() {
  renderFilters()
  fireEvent.click(screen.getByRole('button', {name: '重测'}))
  const dialog = await screen.findByRole('dialog', {name: '重测'})
  await within(dialog).findByRole('combobox', {name: '用户名'})
  await waitFor(() => expect((within(dialog).getByRole('button', {name: '确认'}) as HTMLButtonElement).disabled).toBe(false))
  return dialog
}

function setFilterEnabled(dialog: HTMLElement, label: string, enabled: boolean) {
  const toggle = within(dialog).getByRole('switch', {name: `${label}筛选`})
  if (toggle.getAttribute('aria-checked') !== String(enabled)) fireEvent.click(toggle)
}

function expectChoiceClosed(dialog: HTMLElement, label: string, picker: HTMLElement) {
  expect(picker.getAttribute('aria-expanded')).toBe('false')
  expect(within(dialog).queryByRole('listbox', {name: label})).toBeNull()
  expect(screen.getByRole('dialog', {name: '重测'})).toBe(dialog)
  expect(document.activeElement).toBe(picker)
}

function selectOption(dialog: HTMLElement, label: string, search: string, option: string) {
  setFilterEnabled(dialog, label, true)
  const picker = within(dialog).getByRole('combobox', {name: label})
  if (picker.getAttribute('aria-expanded') !== 'true') fireEvent.click(picker)
  expect(within(dialog).getByRole('listbox', {name: label}).getAttribute('aria-multiselectable')).not.toBe('true')
  fireEvent.change(within(dialog).getByRole('textbox', {name: `搜索${label}`}), {target: {value: search}})
  fireEvent.click(within(dialog).getByRole('option', {name: option}))
  expectChoiceClosed(dialog, label, picker)
}

function selectTime(dialog: HTMLElement, start: string, end: string) {
  setFilterEnabled(dialog, '时间', true)
  const picker = within(dialog).getByRole('combobox', {name: '时间'})
  fireEvent.click(picker)
  fireEvent.change(within(dialog).getByRole('textbox', {name: '起始时间'}), {target: {value: start}})
  fireEvent.change(within(dialog).getByRole('textbox', {name: '结束时间'}), {target: {value: end}})
  if (picker.getAttribute('aria-expanded') === 'true') fireEvent.click(picker)
}

async function preview(dialog: HTMLElement) {
  fireEvent.click(within(dialog).getByRole('button', {name: '确认'}))
  return screen.findByRole('dialog', {name: '确认重测'})
}

beforeEach(() => {
  requests = []
  replies = []
  optionsError = false
  statusRequests = 0
  statusUrls = []
  statusOptions = [...options.statuses]
  clients = []
  Object.defineProperty(window, 'matchMedia', {configurable: true, value: vi.fn().mockImplementation((query: string) => ({matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn()}))})
  vi.stubGlobal('fetch', vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/admin/rejudge-ranges/options') return optionsError ? response({message: '筛选项读取失败'}, 503) : response({...options, statuses: statusOptions})
    if (url === '/api/admin/rejudge-ranges' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as FilterBody
      requests.push(body)
      const reply = replies.shift()
      if (reply) return response(reply.payload, reply.status)
      return response(body.confirm_total === undefined ? {preview: true, total: 2, confirmation_token: 'preview-token'} : {preview: false, total: 2, progress_url: '/api/admin/rejudge-ranges/status?batch_id=batch-a'})
    }
    if (url.startsWith('/api/admin/rejudge-ranges/status')) {
      statusRequests += 1
      statusUrls.push(url)
      const total = url.includes('batch_id=batch-b') ? 3 : 2
      return response({progress: 100, done: total, total})
    }
    throw new Error(`unexpected fetch: ${url}`)
  }))
})

afterEach(() => {
  cleanup()
  clients.forEach((client) => client.clear())
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('提交列表条件重测', () => {
  it('默认只启用 Pending 状态筛选，其余三行灰色禁用，弹窗只包含四行和确认操作', async () => {
    const dialog = await openFilters()
    const body = dialog.querySelector('.modal-body')!
    const rows = Array.from(body.children)
    expect(rows).toHaveLength(4)
    expect(rows.map((row) => row.querySelector('.submission-rejudge-filter-icon i')?.className)).toEqual(['fas fa-user', 'fas fa-book-open', 'fas fa-circle', 'fas fa-clock'])
    expect(within(dialog).getAllByRole('combobox').map((item) => item.getAttribute('aria-label'))).toEqual(['用户名', '题目', '状态', '时间'])
    expect(within(dialog).getAllByRole('switch').map((item) => item.getAttribute('aria-checked'))).toEqual(['false', 'false', 'true', 'false'])
    for (const label of ['用户名', '题目', '时间']) {
      const picker = within(dialog).getByRole('combobox', {name: label}) as HTMLButtonElement
      expect(picker.disabled).toBe(true)
      expect(picker.textContent).toContain(label === '时间' ? '全部时间' : '全部')
      expect(picker.closest('.submission-rejudge-filter-row')?.classList.contains('is-disabled')).toBe(true)
    }
    const statusPicker = within(dialog).getByRole('combobox', {name: '状态'}) as HTMLButtonElement
    expect(statusPicker.disabled).toBe(false)
    expect(statusPicker.textContent).toContain('Pending')
    expect(statusPicker.closest('.submission-rejudge-filter-row')?.classList.contains('is-disabled')).toBe(false)
    expect(body.querySelector('p, small, .alert')).toBeNull()
    expect(dialog.querySelector('select, datalist, input[type="datetime-local"], input[type="date"], input[type="time"], input[list]')).toBeNull()
    const footer = dialog.querySelector('.modal-footer') as HTMLElement
    expect(within(footer).getAllByRole('button')).toHaveLength(1)
    expect(within(footer).getByRole('button', {name: '确认'})).toBeTruthy()
    await preview(dialog)
    expect(requests).toEqual([{usernames: [], problem_ids: [], statuses: ['Pending']}])
  })

  it('搜索菜单和时间面板中的 Escape 只关闭当前菜单，重测弹窗保持打开', async () => {
    const dialog = await openFilters()
    setFilterEnabled(dialog, '用户名', true)
    const usernamePicker = within(dialog).getByRole('combobox', {name: '用户名'})
    fireEvent.click(usernamePicker)
    fireEvent.keyDown(within(dialog).getByRole('textbox', {name: '搜索用户名'}), {key: 'Escape'})
    expect(usernamePicker.getAttribute('aria-expanded')).toBe('false')
    expect(screen.getByRole('dialog', {name: '重测'})).toBe(dialog)
    expect(document.activeElement).toBe(usernamePicker)

    setFilterEnabled(dialog, '时间', true)
    const timePicker = within(dialog).getByRole('combobox', {name: '时间'})
    fireEvent.click(timePicker)
    fireEvent.keyDown(within(dialog).getByRole('textbox', {name: '起始时间'}), {key: 'Escape'})
    expect(screen.queryByRole('dialog', {name: '时间范围'})).toBeNull()
    expect(timePicker.getAttribute('aria-expanded')).toBe('false')
    expect(screen.getByRole('dialog', {name: '重测'})).toBe(dialog)
    expect(document.activeElement).toBe(timePicker)
    expect(requests).toHaveLength(0)
  })

  it('开启开关仅启用对应控件，仍保留重测弹窗且不自动展开选择菜单', async () => {
    const dialog = await openFilters()
    for (const label of ['用户名', '题目', '时间']) {
      setFilterEnabled(dialog, label, true)
      const picker = within(dialog).getByRole('combobox', {name: label}) as HTMLButtonElement
      expect(picker.disabled).toBe(false)
      expect(picker.getAttribute('aria-expanded')).toBe('false')
      expect(picker.closest('.submission-rejudge-filter-row')?.classList.contains('is-disabled')).toBe(false)
      expect(screen.getByRole('dialog', {name: '重测'})).toBe(dialog)
      expect(within(dialog).queryByRole('listbox')).toBeNull()
      expect(screen.queryByRole('dialog', {name: '时间范围'})).toBeNull()
    }
    expect(requests).toHaveLength(0)
  })

  it('默认状态开关关闭后表示全选，发送空数组且不包含任何时间限制', async () => {
    const dialog = await openFilters()
    setFilterEnabled(dialog, '状态', false)
    const picker = within(dialog).getByRole('combobox', {name: '状态'}) as HTMLButtonElement
    expect(picker.disabled).toBe(true)
    expect(picker.textContent).toContain('全部')
    await preview(dialog)
    expect(requests).toEqual([{usernames: [], problem_ids: [], statuses: []}])
  })

  it('从条数确认返回筛选保留开关与草稿，重新开启后恢复各项原选择', async () => {
    const dialog = await openFilters()
    selectOption(dialog, '用户名', 'alice', 'alice')
    selectOption(dialog, '题目', '第一', 'P0011 · 第一题')
    selectOption(dialog, '状态', 'accepted', 'Accepted')
    selectTime(dialog, '2026-10-01 08:00', '2026-10-14 18:00')
    for (const label of ['用户名', '题目', '状态', '时间']) setFilterEnabled(dialog, label, false)
    const confirmation = await preview(dialog)
    expect(requests).toEqual([{usernames: [], problem_ids: [], statuses: []}])

    fireEvent.click(within(confirmation).getByRole('button', {name: '关闭'}))
    const returned = await screen.findByRole('dialog', {name: '重测'})
    expect(within(returned).getAllByRole('switch').map((item) => item.getAttribute('aria-checked'))).toEqual(['false', 'false', 'false', 'false'])
    for (const label of ['用户名', '题目', '状态', '时间']) setFilterEnabled(returned, label, true)
    expect(within(returned).getByRole('combobox', {name: '用户名'}).textContent).toContain('alice')
    expect(within(returned).getByRole('combobox', {name: '题目'}).textContent).toContain('P0011 · 第一题')
    expect(within(returned).getByRole('combobox', {name: '状态'}).textContent).toContain('Accepted')
    expect(within(returned).getByRole('combobox', {name: '时间'}).textContent).toContain('2026-10-01 08:00')
    expect(within(returned).getByRole('combobox', {name: '时间'}).textContent).toContain('2026-10-14 18:00')
    await waitFor(() => expect((within(returned).getByRole('button', {name: '确认'}) as HTMLButtonElement).disabled).toBe(false))
    await preview(returned)
    expect(requests[1]).toEqual({usernames: ['alice'], problem_ids: [11], statuses: ['Accepted'], start: '2026-10-01T08:00', end: '2026-10-14T18:00'})
  })

  it('通过主按钮重新打开弹窗恢复默认开关和 Pending，不沿用上次条件', async () => {
    const dialog = await openFilters()
    selectOption(dialog, '用户名', 'alice', 'alice')
    selectOption(dialog, '题目', '第一', 'P0011 · 第一题')
    selectOption(dialog, '状态', 'accepted', 'Accepted')
    selectTime(dialog, '2026-10-01 08:00', '2026-10-14 18:00')
    fireEvent.click(within(dialog).getByRole('button', {name: '关闭'}))

    fireEvent.click(screen.getByRole('button', {name: '重测'}))
    const reopened = await screen.findByRole('dialog', {name: '重测'})
    expect(within(reopened).getAllByRole('switch').map((item) => item.getAttribute('aria-checked'))).toEqual(['false', 'false', 'true', 'false'])
    expect(within(reopened).getByRole('combobox', {name: '用户名'}).textContent).toContain('全部')
    expect(within(reopened).getByRole('combobox', {name: '题目'}).textContent).toContain('全部')
    expect(within(reopened).getByRole('combobox', {name: '状态'}).textContent).toContain('Pending')
    expect(within(reopened).getByRole('combobox', {name: '状态'}).textContent).not.toContain('Accepted')
    expect(within(reopened).getByRole('combobox', {name: '时间'}).textContent).toContain('全部时间')
    await waitFor(() => expect((within(reopened).getByRole('button', {name: '确认'}) as HTMLButtonElement).disabled).toBe(false))
    await preview(reopened)
    expect(requests).toEqual([{usernames: [], problem_ids: [], statuses: ['Pending']}])
  })

  it.each(['用户名', '题目', '时间'])('启用%s但未选条件时显示错误，不把空值作为全选发送预览', async (label) => {
    const dialog = await openFilters()
    setFilterEnabled(dialog, label, true)
    fireEvent.click(within(dialog).getByRole('button', {name: '确认'}))
    await screen.findByText(label === '时间' ? /请选择起始时间和结束时间/ : new RegExp(`请选择.*${label}`))
    expect(requests).toHaveLength(0)
    expect(screen.getByRole('dialog', {name: '重测'})).toBe(dialog)
    expect(screen.queryByRole('dialog', {name: '确认重测'})).toBeNull()
  })

  it('服务端候选未包含 Pending 时仍保留默认 Pending 选项和筛选条件', async () => {
    statusOptions = ['Accepted', 'Wrong Answer']
    const dialog = await openFilters()
    const picker = within(dialog).getByRole('combobox', {name: '状态'})
    expect(picker.textContent).toContain('Pending')
    fireEvent.click(picker)
    expect(within(dialog).getByRole('option', {name: 'Pending'}).getAttribute('aria-selected')).toBe('true')
    fireEvent.click(picker)
    await preview(dialog)
    expect(requests).toEqual([{usernames: [], problem_ids: [], statuses: ['Pending']}])
  })

  it('用户名、题目和状态共同筛选，先预览条数，再用原条件和令牌确认执行', async () => {
    const dialog = await openFilters()
    expect(dialog.querySelector('select, datalist, input[type="datetime-local"], input[list]')).toBeNull()
    selectOption(dialog, '用户名', 'ali', 'alice')
    selectOption(dialog, '题目', '第一题', 'P0011 · 第一题')
    selectOption(dialog, '状态', 'wrong', 'Wrong Answer')

    const confirmation = await preview(dialog)
    const snapshot = {usernames: ['alice'], problem_ids: [11], statuses: ['Wrong Answer']}
    expect(requests).toEqual([snapshot])
    expect(confirmation.textContent).toContain('符合条件的记录')
    expect(confirmation.textContent).toContain('2')
    expect(screen.queryByRole('dialog', {name: '重测进度'})).toBeNull()
    expect(statusRequests).toBe(0)

    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    await screen.findByRole('dialog', {name: '重测进度'})
    expect(requests).toEqual([snapshot, {...snapshot, confirm_total: 2, confirmation_token: 'preview-token'}])
    await waitFor(() => expect(statusRequests).toBe(1))
    expect(statusUrls).toEqual(['/api/admin/rejudge-ranges/status?batch_id=batch-a'])
    expect(statusUrls).not.toContain('/api/admin/rejudge-ranges/status')
  })

  it('三个条件均为可搜索单选，新选择替换旧选择，各请求数组只发送最后一个值', async () => {
    const dialog = await openFilters()
    selectOption(dialog, '用户名', 'alice', 'alice')
    selectOption(dialog, '用户名', 'bob', 'bob')
    selectOption(dialog, '题目', 'p0011', 'P0011 · 第一题')
    selectOption(dialog, '题目', '第二', 'P0012 · 第二题')
    selectOption(dialog, '状态', 'accepted', 'Accepted')
    selectOption(dialog, '状态', 'wrong', 'Wrong Answer')

    expect(within(dialog).getAllByRole('listbox', {hidden: true}).some((item) => item.getAttribute('aria-multiselectable') === 'true')).toBe(false)
    await preview(dialog)
    expect(requests).toHaveLength(1)
    expect(requests[0].usernames).toEqual(['bob'])
    expect(requests[0].problem_ids).toEqual([12])
    expect(requests[0].statuses).toEqual(['Wrong Answer'])
    expect(requests[0]).not.toHaveProperty('confirm_total')
    expect(requests[0]).not.toHaveProperty('start')
    expect(requests[0]).not.toHaveProperty('end')
  })

  it('单选菜单重开只保留一个选中项，点击同项不清空并立即收起归还焦点', async () => {
    const dialog = await openFilters()
    selectOption(dialog, '用户名', 'alice', 'alice')
    const picker = within(dialog).getByRole('combobox', {name: '用户名'})
    fireEvent.click(picker)
    expect(within(dialog).getByRole('listbox', {name: '用户名'}).getAttribute('aria-multiselectable')).not.toBe('true')
    expect(within(dialog).getByRole('option', {name: 'alice'}).getAttribute('aria-selected')).toBe('true')
    expect(within(dialog).getAllByRole('option').filter((item) => item.getAttribute('aria-selected') === 'true')).toHaveLength(1)
    fireEvent.click(within(dialog).getByRole('option', {name: 'bob'}))
    expectChoiceClosed(dialog, '用户名', picker)

    fireEvent.click(picker)
    expect(within(dialog).getByRole('option', {name: 'alice'}).getAttribute('aria-selected')).toBe('false')
    expect(within(dialog).getByRole('option', {name: 'bob'}).getAttribute('aria-selected')).toBe('true')
    expect(within(dialog).getAllByRole('option').filter((item) => item.getAttribute('aria-selected') === 'true')).toHaveLength(1)
    fireEvent.click(within(dialog).getByRole('option', {name: 'bob'}))
    expectChoiceClosed(dialog, '用户名', picker)
    expect(picker.textContent).toContain('bob')
    expect(picker.textContent).not.toContain('alice')
    await preview(dialog)
    expect(requests).toEqual([{usernames: ['bob'], problem_ids: [], statuses: ['Pending']}])
  })

  it('搜索后 Enter 选择唯一候选也立即收起菜单，不提前发送重测预览', async () => {
    const dialog = await openFilters()
    setFilterEnabled(dialog, '用户名', true)
    const picker = within(dialog).getByRole('combobox', {name: '用户名'})
    fireEvent.click(picker)
    const search = within(dialog).getByRole('textbox', {name: '搜索用户名'})
    fireEvent.change(search, {target: {value: 'bob'}})
    expect(within(dialog).getAllByRole('option')).toHaveLength(1)
    fireEvent.keyDown(search, {key: 'Enter'})
    expectChoiceClosed(dialog, '用户名', picker)
    expect(requests).toHaveLength(0)
    await preview(dialog)
    expect(requests).toEqual([{usernames: ['bob'], problem_ids: [], statuses: ['Pending']}])
  })

  it('连续创建两个批次分别读取服务器返回的进度地址，不复用上一批的进度', async () => {
    replies = [
      {payload: {preview: true, total: 2, confirmation_token: 'preview-a'}},
      {payload: {preview: false, total: 2, progress_url: '/api/admin/rejudge-ranges/status?batch_id=batch-a'}},
      {payload: {preview: true, total: 3, confirmation_token: 'preview-b'}},
      {payload: {preview: false, total: 3, progress_url: '/api/admin/rejudge-ranges/status?batch_id=batch-b'}},
    ]
    let confirmation = await preview(await openFilters())
    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    const firstProgress = await screen.findByRole('dialog', {name: '重测进度'})
    await within(firstProgress).findByText('已完成 2 / 2')
    fireEvent.click(within(firstProgress).getAllByRole('button', {name: '关闭'})[0])

    fireEvent.click(screen.getByRole('button', {name: '重测'}))
    const dialog = await screen.findByRole('dialog', {name: '重测'})
    await waitFor(() => expect((within(dialog).getByRole('button', {name: '确认'}) as HTMLButtonElement).disabled).toBe(false))
    confirmation = await preview(dialog)
    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    const secondProgress = await screen.findByRole('dialog', {name: '重测进度'})
    await within(secondProgress).findByText('已完成 3 / 3')
    expect(statusUrls).toEqual(['/api/admin/rejudge-ranges/status?batch_id=batch-a', '/api/admin/rejudge-ranges/status?batch_id=batch-b'])
    expect(statusUrls).not.toContain('/api/admin/rejudge-ranges/status')
  })

  it('关闭各项开关解除筛选限制，禁用行中的旧选择不进入接口请求', async () => {
    const dialog = await openFilters()
    selectOption(dialog, '用户名', 'alice', 'alice')
    selectOption(dialog, '题目', '第一', 'P0011 · 第一题')
    selectOption(dialog, '状态', 'accepted', 'Accepted')
    selectTime(dialog, '2026-10-01 08:00', '2026-10-14 18:00')
    for (const label of ['用户名', '题目', '状态', '时间']) {
      setFilterEnabled(dialog, label, false)
      const picker = within(dialog).getByRole('combobox', {name: label}) as HTMLButtonElement
      expect(picker.disabled).toBe(true)
      expect(picker.textContent).toContain(label === '时间' ? '全部时间' : '全部')
      expect(picker.closest('.submission-rejudge-filter-row')?.classList.contains('is-disabled')).toBe(true)
    }

    await preview(dialog)
    expect(requests).toEqual([{usernames: [], problem_ids: [], statuses: []}])
  })

  it('仅按时间筛选也可预览，二次确认保留相同的时间范围', async () => {
    const dialog = await openFilters()
    setFilterEnabled(dialog, '状态', false)
    selectTime(dialog, '2026-10-01 08:00', '2026-10-14 18:00')
    const confirmation = await preview(dialog)
    const snapshot = {usernames: [], problem_ids: [], statuses: [], start: '2026-10-01T08:00', end: '2026-10-14T18:00'}
    expect(requests).toEqual([snapshot])
    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    await screen.findByRole('dialog', {name: '重测进度'})
    expect(requests[1]).toEqual({...snapshot, confirm_total: 2, confirmation_token: 'preview-token'})
  })

  it('确认时条数发生变化会重新展示条数，不提前打开进度，再次确认使用新令牌', async () => {
    replies = [{payload: {preview: true, total: 2, confirmation_token: 'preview-token'}}, {payload: {preview: true, total: 3, confirmation_token: 'changed-token'}}, {payload: {preview: false, total: 3, progress_url: '/api/admin/rejudge-ranges/status?batch_id=batch-b'}}]
    const dialog = await openFilters()
    selectOption(dialog, '用户名', 'alice', 'alice')
    const confirmation = await preview(dialog)
    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    await waitFor(() => expect(confirmation.textContent).toContain('3'))
    expect(requests).toHaveLength(2)
    expect(screen.queryByRole('dialog', {name: '重测进度'})).toBeNull()
    expect(statusRequests).toBe(0)

    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    await screen.findByRole('dialog', {name: '重测进度'})
    expect(requests[2]).toEqual({usernames: ['alice'], problem_ids: [], statuses: ['Pending'], confirm_total: 3, confirmation_token: 'changed-token'})
  })

  it('没有符合条件的记录时禁用二次确认，不发起执行请求', async () => {
    replies = [{payload: {preview: true, total: 0, confirmation_token: 'empty-token'}}]
    const confirmation = await preview(await openFilters())
    const confirm = within(confirmation).getByRole('button', {name: '确认'}) as HTMLButtonElement
    expect(confirmation.textContent).toContain('0')
    expect(confirm.disabled).toBe(true)
    fireEvent.click(confirm)
    expect(requests).toHaveLength(1)
    expect(statusRequests).toBe(0)
    expect(screen.queryByRole('dialog', {name: '重测进度'})).toBeNull()
  })

  it('预览失败保留所选条件，再次确认可以重试', async () => {
    replies = [{payload: {message: '预览读取失败'}, status: 503}]
    const dialog = await openFilters()
    selectOption(dialog, '题目', '第一', 'P0011 · 第一题')
    fireEvent.click(within(dialog).getByRole('button', {name: '确认'}))
    await screen.findByText(/预览读取失败/)
    expect(screen.queryByRole('dialog', {name: '确认重测'})).toBeNull()
    expect(screen.queryByRole('dialog', {name: '重测进度'})).toBeNull()
    expect(statusRequests).toBe(0)

    await preview(dialog)
    expect(requests).toEqual([{usernames: [], problem_ids: [11], statuses: ['Pending']}, {usernames: [], problem_ids: [11], statuses: ['Pending']}])
  })

  it('执行请求失败保留确认弹窗和令牌，重试成功才打开进度', async () => {
    replies = [{payload: {preview: true, total: 2, confirmation_token: 'preview-token'}}, {payload: {message: '重测队列暂不可用'}, status: 503}]
    const confirmation = await preview(await openFilters())
    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    await screen.findByText(/重测队列暂不可用/)
    expect(screen.getByRole('dialog', {name: '确认重测'})).toBeTruthy()
    expect(screen.queryByRole('dialog', {name: '重测进度'})).toBeNull()
    expect(statusRequests).toBe(0)

    fireEvent.click(within(confirmation).getByRole('button', {name: '确认'}))
    await screen.findByRole('dialog', {name: '重测进度'})
    expect(requests).toHaveLength(3)
    expect(requests[2]).toEqual(requests[1])
    expect(requests[2].confirmation_token).toBe('preview-token')
  })

  it('候选读取失败呈现错误，确认按钮重试读取成功后可选择且不会提前预览', async () => {
    optionsError = true
    renderFilters()
    fireEvent.click(screen.getByRole('button', {name: '重测'}))
    await screen.findByText(/筛选项读取失败/)
    expect(requests).toHaveLength(0)
    optionsError = false
    const dialog = screen.getByRole('dialog', {name: '重测'})
    fireEvent.click(within(dialog).getByRole('button', {name: '确认'}))
    setFilterEnabled(dialog, '用户名', true)
    fireEvent.click(within(dialog).getByRole('combobox', {name: '用户名'}))
    await within(dialog).findByRole('option', {name: 'alice'})
    expect(requests).toHaveLength(0)
    selectOption(dialog, '用户名', 'alice', 'alice')
    await preview(dialog)
    expect(requests).toEqual([{usernames: ['alice'], problem_ids: [], statuses: ['Pending']}])
  })
})
