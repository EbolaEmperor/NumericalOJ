import {useState} from 'react'
import {useDismissibleDropdown} from './useDismissibleDropdown'

export function ChoicePicker({name, value, onChange, label, options, disabled = false, id, small = false}: {name: string; value: string; onChange: (next: string) => void; label: string; options: {value: string; label: string; icon: string}[]; disabled?: boolean; id?: string; small?: boolean}) {
  const [open, setOpen] = useState(false)
  const rootRef = useDismissibleDropdown<HTMLDivElement>(open, () => setOpen(false))
  const selected = options.find((item) => item.value === value) || options[0]
  const iconClass = (icon: string) => icon.includes(' ') ? icon : `fas ${icon}`
  return <div ref={rootRef} className={`rk-choice${small ? ' rk-choice-sm' : ''}${open ? ' open' : ''}${disabled ? ' is-disabled' : ''}`}><input type="hidden" name={name} value={value} disabled={disabled} /><button type="button" className="rk-choice-trigger" id={id} aria-haspopup="listbox" aria-expanded={open} aria-label={label} disabled={disabled} onClick={() => setOpen((current) => !current)}><span className="rk-choice-trigger-main"><i className={iconClass(selected.icon)} /><span>{selected.label}</span></span><i className="fas fa-chevron-down rk-choice-caret" /></button><div className="rk-choice-menu" role="listbox" aria-label={label} hidden={!open}>{options.map((item) => <button type="button" className={`rk-choice-option${item.value === value ? ' active' : ''}`} role="option" aria-selected={item.value === value} key={item.value} onClick={() => {onChange(item.value); setOpen(false)}}><span className="rk-choice-option-main"><i className={iconClass(item.icon)} /><span className="rk-choice-option-name">{item.label}</span></span><i className="fas fa-check rk-choice-option-check" /></button>)}</div></div>
}
