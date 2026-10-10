// @vitest-environment jsdom

import {cleanup, render} from '@testing-library/react'
import {afterEach, describe, expect, it} from 'vitest'

import {ListUsername} from './ListUsername'

afterEach(() => cleanup())

describe('列表用户名', () => {
  it.each([
    ['alice', 'alice'],
    ['1234567890', '1234567890'],
    ['123456789012345', '1234567890…'],
    ['学生归属用户名长长长后续', '学生归属用户名长长长…'],
    ['学生😀abcdefghi', '学生😀abcdefg…'],
    [undefined, '—'],
  ])('用户名%s最多展示十个字符并保留完整提示', (username, label) => {
    const {container} = render(<ListUsername username={username} />)
    expect(container.textContent).toBe(label)
    expect(container.querySelector('span')?.getAttribute('title')).toBe(username || null)
  })
})
