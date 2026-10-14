// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {useState} from 'react'
import {afterEach, describe, expect, it} from 'vitest'

import SearchableTargetPicker, {type SearchableTarget} from './SearchableTargetPicker'

afterEach(cleanup)

const items = [{id: 12, title: 'Matrix Practice'}, {id: 29, title: '函数积分'}]

function Example({targets = items}: {targets?: SearchableTarget[]}) {
  const [value, setValue] = useState('')
  return <><SearchableTargetPicker items={targets} value={value} onChange={setValue} id="problemSearch" label="选择题目" placeholder="按编号或标题搜索题目…" /><output aria-label="选中编号">{value}</output><button type="button" onClick={() => setValue('')}>清空选择</button></>
}

describe('共享题目搜索选择', () => {
  it('按编号或标题匹配，选中回填，改搜索文字清除选择', () => {
    render(<Example />)
    const input = screen.getByRole('combobox', {name: '选择题目'}) as HTMLInputElement
    fireEvent.focus(input)
    fireEvent.change(input, {target: {value: ' mAtRiX '}})
    expect(screen.getAllByRole('option')).toHaveLength(1)
    fireEvent.click(screen.getByRole('option', {name: '#12 Matrix Practice'}))
    expect(input.value).toBe('#12 Matrix Practice')
    expect(screen.getByLabelText('选中编号').textContent).toBe('12')
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(screen.getByText('已选择：#12 Matrix Practice')).not.toBeNull()

    fireEvent.change(input, {target: {value: '29'}})
    expect(screen.getByLabelText('选中编号').textContent).toBe('')
    expect(screen.getByRole('option', {name: '#29 函数积分'})).not.toBeNull()
  })

  it('最多展示 50 个候选，外部点击关闭菜单并保留搜索', () => {
    render(<Example targets={Array.from({length: 60}, (_, index) => ({id: index + 1, title: `题目 ${index + 1}`}))} />)
    const input = screen.getByRole('combobox', {name: '选择题目'}) as HTMLInputElement
    fireEvent.focus(input)
    expect(screen.getAllByRole('option')).toHaveLength(50)
    fireEvent.change(input, {target: {value: '题目'}})
    fireEvent.pointerDown(screen.getByRole('button', {name: '清空选择'}))
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(input.value).toBe('题目')
  })

  it('外部清空选中值时同步清除选中回填', () => {
    render(<Example />)
    const input = screen.getByRole('combobox', {name: '选择题目'}) as HTMLInputElement
    fireEvent.focus(input)
    fireEvent.click(screen.getByRole('option', {name: '#12 Matrix Practice'}))
    fireEvent.click(screen.getByRole('button', {name: '清空选择'}))
    expect(input.value).toBe('')
    expect(screen.queryByText('已选择：#12 Matrix Practice')).toBeNull()
  })
})
