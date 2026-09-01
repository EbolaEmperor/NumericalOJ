// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {useState} from 'react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import {ReactModal} from './ReactModal'
import {useDismissibleDropdown} from './useDismissibleDropdown'

afterEach(() => {
  cleanup()
  document.body.classList.remove('modal-open')
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function ModalWithDropdown({onClose}: {onClose: () => void}) {
  const [dropdownOpen, setDropdownOpen] = useState(true)
  const dropdownRef = useDismissibleDropdown<HTMLDivElement>(dropdownOpen, () => setDropdownOpen(false))
  return <ReactModal open onClose={onClose} id="testModal" labelledBy="testModalTitle">
    <div className="modal-content">
      <h2 id="testModalTitle">测试弹窗</h2>
      <div ref={dropdownRef}>{dropdownOpen ? <div role="listbox">下拉内容</div> : null}</div>
      <div data-testid="modal-blank">弹窗空白区域</div>
    </div>
  </ReactModal>
}

describe('ReactModal backdrop dismissal', () => {
  it('下拉框收起后的兼容 mousedown 不会误关弹窗', () => {
    vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => {
      callback(0)
      return 1
    })
    vi.stubGlobal('cancelAnimationFrame', vi.fn())
    const onClose = vi.fn()
    render(<ModalWithDropdown onClose={onClose} />)

    fireEvent.pointerDown(screen.getByTestId('modal-blank'))
    expect(screen.queryByRole('listbox')).toBeNull()
    expect(onClose).not.toHaveBeenCalled()

    const backdrop = document.getElementById('testModal')
    expect(backdrop).not.toBeNull()
    fireEvent.mouseDown(backdrop!)
    expect(onClose).not.toHaveBeenCalled()

    fireEvent.pointerDown(backdrop!)
    expect(onClose).toHaveBeenCalledOnce()
  })
})
