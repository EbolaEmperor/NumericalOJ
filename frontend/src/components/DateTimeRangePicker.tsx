import {useEffect, useRef, useState, type KeyboardEvent} from 'react'

import {useDismissibleDropdown} from './useDismissibleDropdown'
import './datetime-range-picker.css'

interface DateTimeRangePickerProps {
  start: string
  end: string
  onChange: (start: string, end: string) => void
  id: string
  label: string
  disabled?: boolean
  placeholder?: string
}

type Boundary = 'start' | 'end'
const weekdays = ['一', '二', '三', '四', '五', '六', '日']
const pad = (value: number) => String(value).padStart(2, '0')
const dateValue = (date: Date) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
const displayTime = (value: string) => value.replace('T', ' ')

function dateFromValue(value: string) {
  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(value)
  if (!match) return null
  const year = Number(match[1]), month = Number(match[2]) - 1, day = Number(match[3])
  if (year < 1 || month < 0 || month > 11 || day < 1 || day > 31) return null
  const date = new Date(0)
  date.setFullYear(year, month, day)
  date.setHours(12, 0, 0, 0)
  return date.getFullYear() === year && date.getMonth() === month && date.getDate() === day ? date : null
}

function atMonth(date: Date, shift: number) {
  const next = new Date(date)
  const day = next.getDate()
  next.setDate(1)
  next.setMonth(next.getMonth() + shift)
  const last = new Date(next)
  last.setMonth(last.getMonth() + 1, 0)
  next.setDate(Math.min(day, last.getDate()))
  return next
}

export function DateTimeRangePicker({start, end, onChange, id, label, disabled = false, placeholder = '全部时间'}: DateTimeRangePickerProps) {
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState<Boundary>('start')
  const [month, setMonth] = useState(() => dateFromValue(start || end) || new Date())
  const [cursor, setCursor] = useState(() => dateValue(dateFromValue(start || end) || new Date()))
  const triggerRef = useRef<HTMLButtonElement>(null)
  const focusCalendar = useRef(false)
  const close = () => setOpen(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, close)
  const panelId = `${id}Panel`
  const selectedStart = dateFromValue(start)
  const selectedEnd = dateFromValue(end)
  const firstDay = new Date(month)
  firstDay.setDate(1)
  firstDay.setDate(1 - (firstDay.getDay() + 6) % 7)
  const calendarDays = Array.from({length: 42}, (_, index) => {
    const date = new Date(firstDay)
    date.setDate(firstDay.getDate() + index)
    return date
  })
  const selectedLabel = !start && !end ? placeholder : `${displayTime(start) || '…'} — ${displayTime(end) || '…'}`

  const show = () => {
    const date = dateFromValue(start || end) || new Date()
    setMonth(date)
    setCursor(dateValue(date))
    setActive('start')
    setOpen(true)
  }
  useEffect(() => {
    if (open && !disabled) rootRef.current?.querySelector<HTMLInputElement>(`#${id}Start`)?.focus()
  }, [open, disabled, id, rootRef])
  useEffect(() => {
    if (!focusCalendar.current) return
    focusCalendar.current = false
    rootRef.current?.querySelector<HTMLButtonElement>(`[data-date="${cursor}"]`)?.focus()
  }, [cursor, month, rootRef])

  const activate = (boundary: Boundary) => {
    setActive(boundary)
    const date = dateFromValue(boundary === 'start' ? start : end)
    if (date) {setMonth(date); setCursor(dateValue(date))}
  }
  const chooseDate = (date: Date) => {
    const current = active === 'start' ? start : end
    const clockMatch = /[T ](\d{2}):(\d{2})(?::\d{2})?$/.exec(current)
    const clock = clockMatch && Number(clockMatch[1]) <= 23 && Number(clockMatch[2]) <= 59 ? `${clockMatch[1]}:${clockMatch[2]}` : active === 'start' ? '00:00' : '23:59'
    const value = `${dateValue(date)}T${clock}`
    setCursor(dateValue(date))
    if (active === 'start') {
      onChange(value, end)
      setActive('end')
      rootRef.current?.querySelector<HTMLInputElement>(`#${id}End`)?.focus()
    } else {
      onChange(start, value)
      close()
      triggerRef.current?.focus()
    }
  }
  const dayKeyDown = (event: KeyboardEvent<HTMLButtonElement>, date: Date) => {
    const next = new Date(date)
    if (event.key === 'ArrowLeft') next.setDate(next.getDate() - 1)
    else if (event.key === 'ArrowRight') next.setDate(next.getDate() + 1)
    else if (event.key === 'ArrowUp') next.setDate(next.getDate() - 7)
    else if (event.key === 'ArrowDown') next.setDate(next.getDate() + 7)
    else if (event.key === 'Home') next.setDate(next.getDate() - (next.getDay() + 6) % 7)
    else if (event.key === 'End') next.setDate(next.getDate() + 6 - (next.getDay() + 6) % 7)
    else if (event.key === 'PageUp' || event.key === 'PageDown') {
      const moved = atMonth(date, event.key === 'PageUp' ? -1 : 1)
      next.setTime(moved.getTime())
    } else return
    event.preventDefault()
    event.stopPropagation()
    focusCalendar.current = true
    setMonth(next)
    setCursor(dateValue(next))
  }
  const changeMonth = (shift: number) => {
    const next = atMonth(month, shift)
    setMonth(next)
    setCursor(dateValue(next))
  }

  return <div ref={rootRef} className={`rk-choice datetime-range-picker${open && !disabled ? ' open' : ''}${disabled ? ' is-disabled' : ''}`} onKeyDownCapture={(event) => {
    if (!open) return
    if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      close()
      triggerRef.current?.focus()
    } else if (event.key === 'Tab' && event.target !== triggerRef.current) {
      const fields = Array.from(rootRef.current?.querySelectorAll<HTMLElement>('.datetime-range-panel input, .datetime-range-panel button:not([tabindex="-1"])') || [])
      const index = fields.indexOf(event.target as HTMLElement)
      if (index < 0) return
      if ((!event.shiftKey && index < fields.length - 1) || (event.shiftKey && index > 0)) event.stopPropagation()
      else {
        close()
        triggerRef.current?.focus()
        if (event.shiftKey) {event.preventDefault(); event.stopPropagation()}
      }
    }
  }}>
    <button ref={triggerRef} type="button" className="rk-choice-trigger" id={id} role="combobox" aria-haspopup="dialog" aria-expanded={open && !disabled} aria-controls={panelId} aria-label={label} title={selectedLabel} disabled={disabled} onClick={() => {if (open) close(); else show()}} onKeyDown={(event) => {
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
      event.preventDefault()
      if (!open) show()
    }}><span className="rk-choice-trigger-main"><span>{selectedLabel}</span></span><i className="fas fa-chevron-down rk-choice-caret" aria-hidden="true" /></button>
    {open && !disabled ? <div className="rk-choice-menu datetime-range-panel" id={panelId} role="dialog" aria-label="时间范围">
      <div className="datetime-range-fields">
        {(['start', 'end'] as const).map((boundary) => <label className={`datetime-range-field${active === boundary ? ' is-active' : ''}`} title={boundary === 'start' ? '起始时间' : '结束时间'} key={boundary}>
          <i className={`fas ${boundary === 'start' ? 'fa-hourglass-start' : 'fa-hourglass-end'}`} aria-hidden="true" />
          <input id={`${id}${boundary === 'start' ? 'Start' : 'End'}`} type="text" autoComplete="off" spellCheck={false} aria-label={boundary === 'start' ? '起始时间' : '结束时间'} placeholder="YYYY-MM-DD HH:mm" value={displayTime(boundary === 'start' ? start : end)} onFocus={() => activate(boundary)} onChange={(event) => {
            const value = event.target.value.replace(' ', 'T')
            if (boundary === 'start') onChange(value, end)
            else onChange(start, value)
          }} onKeyDown={(event) => {if (event.key === 'Enter') {event.preventDefault(); close(); triggerRef.current?.focus()}}} />
        </label>)}
      </div>
      <div className="datetime-range-calendar-head"><button type="button" aria-label="上一月" onClick={() => changeMonth(-1)}><i className="fas fa-chevron-left" aria-hidden="true" /></button><strong>{month.getFullYear()} 年 {month.getMonth() + 1} 月</strong><button type="button" aria-label="下一月" onClick={() => changeMonth(1)}><i className="fas fa-chevron-right" aria-hidden="true" /></button></div>
      <div className="datetime-range-weekdays" aria-hidden="true">{weekdays.map((day) => <span key={day}>{day}</span>)}</div>
      <div className="datetime-range-calendar" role="grid" aria-label={`${month.getFullYear()} 年 ${month.getMonth() + 1} 月`}>
        {Array.from({length: 6}, (_, row) => <div className="datetime-range-calendar-row" role="row" key={row}>{calendarDays.slice(row * 7, row * 7 + 7).map((date) => {
          const value = dateValue(date)
          const selected = value === (selectedStart && dateValue(selectedStart)) || value === (selectedEnd && dateValue(selectedEnd))
          const inRange = selectedStart && selectedEnd && date > selectedStart && date < selectedEnd
          return <button type="button" role="gridcell" data-date={value} aria-label={value} aria-selected={selected} tabIndex={value === cursor ? 0 : -1} className={`datetime-range-day${date.getMonth() !== month.getMonth() ? ' is-outside' : ''}${selected ? ' is-selected' : ''}${inRange ? ' is-range' : ''}`} key={value} onClick={() => chooseDate(date)} onKeyDown={(event) => dayKeyDown(event, date)}>{date.getDate()}</button>
        })}</div>)}
      </div>
    </div> : null}
  </div>
}
