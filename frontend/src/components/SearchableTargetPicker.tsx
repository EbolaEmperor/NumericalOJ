import {useState} from 'react'

import {useDismissibleDropdown} from './useDismissibleDropdown'

export interface SearchableTarget {
  id: number | string
  title: string
}

interface SearchableTargetPickerProps {
  items: SearchableTarget[]
  value: string
  onChange: (value: string) => void
  label: string
  id: string
  placeholder: string
  disabled?: boolean
  hideLabel?: boolean
  showSelection?: boolean
}

export default function SearchableTargetPicker({items, value, onChange, label, id, placeholder, disabled = false, hideLabel = false, showSelection = true}: SearchableTargetPickerProps) {
  const [search, setSearch] = useState({value: '', text: ''})
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = items.find((item) => String(item.id) === value)
  const searchText = search.value === value ? search.text : selected ? `#${value} ${selected.title}` : ''
  const needle = searchText.trim().toLowerCase()
  const filtered = items.filter((item) => !needle || String(item.id).includes(needle) || item.title.toLowerCase().includes(needle)).slice(0, 50)

  return <div ref={rootRef} className="mb-3 position-relative">
    <label className={hideLabel ? 'visually-hidden' : 'form-label'} htmlFor={id}>{label}</label>
    <input id={id} type="text" className="form-control" autoComplete="off" placeholder={placeholder} value={searchText} disabled={disabled} role="combobox" aria-haspopup="listbox" aria-expanded={open && !disabled} aria-controls={`${id}Options`} onFocus={() => setOpen(true)} onChange={(event) => {setSearch({value: '', text: event.target.value}); onChange(''); setOpen(true)}} />
    {open && !disabled && filtered.length ? <div id={`${id}Options`} className="list-group position-absolute w-100 shadow-sm" role="listbox" style={{zIndex: 1080, maxHeight: 240, overflow: 'auto'}}>{filtered.map((item) => <button type="button" className="list-group-item list-group-item-action py-2" role="option" aria-label={`#${String(item.id)} ${item.title}`} aria-selected={String(item.id) === value} key={String(item.id)} onClick={() => {const target = String(item.id); setSearch({value: target, text: `#${target} ${item.title}`}); onChange(target); setOpen(false)}}><span className="text-muted me-2">#{String(item.id)}</span>{item.title}</button>)}</div> : null}
    {showSelection ? <div className="form-text">{value ? `已选择：#${value} ${selected?.title || ''}` : ''}</div> : null}
  </div>
}
