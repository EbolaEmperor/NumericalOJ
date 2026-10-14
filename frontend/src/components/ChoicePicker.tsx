import {useEffect, useRef, useState} from 'react'
import {useDismissibleDropdown} from './useDismissibleDropdown'

interface ChoicePickerProps {
  name: string
  value: string
  onChange: (next: string) => void
  label: string
  options: {value: string; label: string; icon: string}[]
  disabled?: boolean
  id?: string
  small?: boolean
  searchable?: boolean
  searchPlaceholder?: string
  searchLabel?: string
  showIcon?: boolean
  placeholder?: string
}

export function ChoicePicker(props: ChoicePickerProps) {
  const {name, label, options, disabled = false, id, small = false, searchable = false, searchPlaceholder = '搜索选项…', searchLabel = '搜索选项', showIcon = true, placeholder = '全部'} = props
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const searchRef = useRef<HTMLInputElement>(null)
  const close = () => {setOpen(false); setSearch('')}
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, close)
  const selected = options.find((item) => item.value === props.value) || (props.placeholder === undefined ? options[0] : undefined)
  const selectedLabel = selected?.label || placeholder
  const optionsId = `${id || name}Options`
  const searchId = `${id || name}Search`
  const needle = search.trim().toLocaleLowerCase()
  const visibleOptions = searchable ? options.filter((item) => !needle || item.label.toLocaleLowerCase().includes(needle)) : options
  const iconClass = (icon: string) => icon.includes(' ') ? icon : `fas ${icon}`
  const focusTrigger = () => rootRef.current?.querySelector<HTMLElement>('[aria-haspopup="listbox"]')?.focus()
  useEffect(() => {if (open && searchable) searchRef.current?.focus()}, [open, searchable])
  const select = (next: string) => {
    props.onChange(next)
    close()
    if (searchable) focusTrigger()
  }
  const renderedOptions = visibleOptions.map((item) => {
    const active = item.value === props.value
    return <button type="button" className={`rk-choice-option${active ? ' active' : ''}`} role="option" aria-selected={active} key={item.value} onClick={() => select(item.value)}><span className="rk-choice-option-main">{showIcon ? <i className={iconClass(item.icon)} aria-hidden="true" /> : null}<span className="rk-choice-option-name">{item.label}</span></span><i className="fas fa-check rk-choice-option-check" aria-hidden="true" /></button>
  })
  return <div ref={rootRef} className={`rk-choice${small ? ' rk-choice-sm' : ''}${searchable ? ' rk-choice-searchable' : ''}${open ? ' open' : ''}${disabled ? ' is-disabled' : ''}`} onKeyDownCapture={(event) => {
    if (open && event.key === 'Escape') {event.preventDefault(); event.stopPropagation(); close(); focusTrigger()}
  }}>
    <input type="hidden" name={name} value={props.value} disabled={disabled} />
    <button type="button" className="rk-choice-trigger" id={id} role={searchable ? 'combobox' : undefined} aria-haspopup="listbox" aria-expanded={open} aria-controls={optionsId} aria-label={label} disabled={disabled} onClick={() => {setSearch(''); setOpen((current) => !current)}}><span className="rk-choice-trigger-main">{showIcon && selected ? <i className={iconClass(selected.icon)} aria-hidden="true" /> : null}<span>{selectedLabel}</span></span><i className="fas fa-chevron-down rk-choice-caret" aria-hidden="true" /></button>
    <div className="rk-choice-menu" role={searchable ? undefined : 'listbox'} id={searchable ? undefined : optionsId} aria-label={searchable ? undefined : label} hidden={!open}>{searchable ? <><div className="rk-choice-search"><label className="visually-hidden" htmlFor={searchId}>{searchLabel}</label><input ref={searchRef} id={searchId} type="text" autoComplete="off" placeholder={searchPlaceholder} value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault()
        const items = rootRef.current?.querySelectorAll<HTMLElement>('[role="option"]')
        const index = event.key === 'ArrowUp' ? (items?.length || 0) - 1 : 0
        items?.[index]?.focus()
      } else if (event.key === 'Enter') {
        event.preventDefault()
        if (visibleOptions.length === 1) select(visibleOptions[0].value)
      }
    }} /></div><div className="rk-choice-options" id={optionsId} role="listbox" aria-label={label}>{renderedOptions}</div>{!visibleOptions.length ? <div className="rk-choice-empty" role="status">没有匹配的选项</div> : null}</> : renderedOptions}</div>
  </div>
}
