// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {useState} from 'react'
import {afterEach, describe, expect, it} from 'vitest'

import {useDismissibleDropdown} from './useDismissibleDropdown'

afterEach(cleanup)

function ExampleDropdown() {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  return <div>
    <div ref={rootRef}>
      <button type="button" aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen((current) => !current)}>节点选择</button>
      {open ? <div role="listbox"><button type="button" role="option" aria-selected="true">菜单内操作</button><button type="button" role="option" aria-selected="false">第二节点</button></div> : null}
    </div>
    <button type="button">菜单外操作</button>
  </div>
}

describe('useDismissibleDropdown', () => {
  it('点击菜单内部时保持展开，点击外部时关闭', () => {
    render(<ExampleDropdown />)
    fireEvent.click(screen.getByRole('button', {name: '节点选择'}))
    fireEvent.pointerDown(screen.getByRole('option', {name: '菜单内操作'}))
    expect(screen.getByRole('listbox')).not.toBeNull()

    fireEvent.pointerDown(screen.getByRole('button', {name: '菜单外操作'}))
    expect(screen.queryByRole('listbox')).toBeNull()
  })

  it('按 Escape 时关闭', () => {
    render(<ExampleDropdown />)
    fireEvent.click(screen.getByRole('button', {name: '节点选择'}))
    fireEvent.keyDown(document, {key: 'Escape'})
    expect(screen.queryByRole('listbox')).toBeNull()
  })

  it('在选项间恢复方向键、首尾键和字母检索', () => {
    render(<ExampleDropdown />)
    fireEvent.click(screen.getByRole('button', {name: '节点选择'}))
    const first = screen.getByRole('option', {name: '菜单内操作'})
    const second = screen.getByRole('option', {name: '第二节点'})
    first.focus()

    fireEvent.keyDown(first, {key: 'ArrowDown'})
    expect(document.activeElement).toBe(second)
    fireEvent.keyDown(second, {key: 'Home'})
    expect(document.activeElement).toBe(first)
    fireEvent.keyDown(first, {key: '第'})
    expect(document.activeElement).toBe(second)
  })
})
