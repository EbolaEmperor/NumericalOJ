// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import {useState} from 'react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {DateTimeRangePicker} from './DateTimeRangePicker'

afterEach(cleanup)

function Example({initialStart = '', initialEnd = ''}: {initialStart?: string; initialEnd?: string}) {
  const [range, setRange] = useState([initialStart, initialEnd])
  return <><DateTimeRangePicker id="dateRange" label="筛选时间" start={range[0]} end={range[1]} onChange={(start, end) => setRange([start, end])} /><output aria-label="时间值">{JSON.stringify(range)}</output><button type="button" onClick={() => setRange(['', ''])}>全选</button></>
}

describe('共享可控日期时间范围', () => {
  it('日历选取闰日保留起始时分，接着选结束日期并自动收起', () => {
    const {container} = render(<Example initialStart="2024-02-28T15:30" />)
    fireEvent.click(screen.getByRole('combobox', {name: '筛选时间'}))
    expect(container.querySelector('input[type="date"], input[type="time"], input[type="datetime-local"], select')).toBeNull()
    expect(screen.getByRole('textbox', {name: '起始时间'}).getAttribute('type')).toBe('text')
    fireEvent.click(screen.getByRole('gridcell', {name: '2024-02-29'}))
    expect(screen.getByLabelText('时间值').textContent).toBe('["2024-02-29T15:30",""]')
    expect(document.activeElement).toBe(screen.getByRole('textbox', {name: '结束时间'}))
    fireEvent.click(screen.getByRole('gridcell', {name: '2024-03-01'}))
    expect(screen.getByLabelText('时间值').textContent).toBe('["2024-02-29T15:30","2024-03-01T23:59"]')
    expect(screen.queryByRole('dialog', {name: '时间范围'})).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('combobox', {name: '筛选时间'}))
  })

  it('键盘跨月按实际月份天数移动，Escape只关闭选择面板并归还焦点', async () => {
    render(<Example initialStart="2024-01-31T00:00" />)
    fireEvent.click(screen.getByRole('combobox', {name: '筛选时间'}))
    fireEvent.keyDown(screen.getByRole('textbox', {name: '起始时间'}), {key: 'Tab'})
    expect(screen.getByRole('dialog', {name: '时间范围'})).not.toBeNull()
    fireEvent.keyDown(screen.getByRole('gridcell', {name: '2024-01-31'}), {key: 'PageDown'})
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('gridcell', {name: '2024-02-29'})))
    fireEvent.keyDown(document.activeElement!, {key: 'ArrowRight'})
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('gridcell', {name: '2024-03-01'})))
    const onDocumentEscape = vi.fn()
    document.addEventListener('keydown', onDocumentEscape)
    fireEvent.keyDown(document.activeElement!, {key: 'Escape'})
    document.removeEventListener('keydown', onDocumentEscape)
    expect(onDocumentEscape).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog', {name: '时间范围'})).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('combobox', {name: '筛选时间'}))
  })

  it('手动编辑与全选受外部状态控制，外点关闭面板', () => {
    render(<Example />)
    expect(screen.getByRole('combobox', {name: '筛选时间'}).textContent).toContain('全部时间')
    fireEvent.click(screen.getByRole('combobox', {name: '筛选时间'}))
    fireEvent.change(screen.getByRole('textbox', {name: '起始时间'}), {target: {value: '2026-10-14 12:35'}})
    fireEvent.change(screen.getByRole('textbox', {name: '结束时间'}), {target: {value: '2026-10-15 19:45'}})
    expect(screen.getByLabelText('时间值').textContent).toBe('["2026-10-14T12:35","2026-10-15T19:45"]')
    fireEvent.pointerDown(screen.getByRole('button', {name: '全选'}))
    expect(screen.queryByRole('dialog', {name: '时间范围'})).toBeNull()
    fireEvent.click(screen.getByRole('button', {name: '全选'}))
    expect(screen.getByRole('combobox', {name: '筛选时间'}).textContent).toContain('全部时间')
  })
})
