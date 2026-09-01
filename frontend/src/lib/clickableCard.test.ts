// @vitest-environment jsdom

import {describe, expect, it} from 'vitest'

import {shouldNavigateFromCardClick} from './clickableCard'

function clickEvent(target: EventTarget, overrides: Partial<MouseEvent> = {}) {
  return {
    target,
    button: 0,
    defaultPrevented: false,
    metaKey: false,
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    ...overrides,
  }
}

describe('shouldNavigateFromCardClick', () => {
  it('allows a primary click on a non-interactive card area', () => {
    expect(shouldNavigateFromCardClick(clickEvent(document.createElement('div')))).toBe(true)
  })

  it('leaves nested links and buttons to handle their own clicks', () => {
    const link = document.createElement('a')
    const button = document.createElement('button')
    const buttonIcon = document.createElement('i')
    button.append(buttonIcon)

    expect(shouldNavigateFromCardClick(clickEvent(link))).toBe(false)
    expect(shouldNavigateFromCardClick(clickEvent(buttonIcon))).toBe(false)
  })

  it('ignores modified or prevented clicks', () => {
    const target = document.createElement('div')
    expect(shouldNavigateFromCardClick(clickEvent(target, {ctrlKey: true}))).toBe(false)
    expect(shouldNavigateFromCardClick(clickEvent(target, {defaultPrevented: true}))).toBe(false)
  })
})
