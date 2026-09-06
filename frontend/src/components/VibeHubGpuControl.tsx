interface Props {
  value: number
  onChange: (value: number) => void
  label: string
  max?: number
  disabled?: boolean
}

export function VibeHubGpuControl({value, onChange, label, max = 24576, disabled = false}: Props) {
  const enabled = value > 0
  return <div className="vibe-gpu-control">
    <button className="vibe-gpu-switch" type="button" role="switch" aria-checked={enabled} disabled={disabled} onClick={() => onChange(enabled ? 0 : Math.min(4096, max))}><i aria-hidden="true" /><span>使用 GPU</span></button>
    {enabled ? <div className="vibe-gpu-memory"><span>{label}</span><div className="vibe-gpu-stepper" role="group" aria-label={label}>
      <button type="button" aria-label={`减少${label}`} disabled={disabled || value <= 256} onClick={() => onChange(Math.max(256, value - 1024))}><i className="fas fa-minus" aria-hidden="true" /></button>
      <output aria-live="polite">{Number((value / 1024).toFixed(3))} GiB</output>
      <button type="button" aria-label={`增加${label}`} disabled={disabled || value >= max} onClick={() => onChange(Math.min(max, value + 1024))}><i className="fas fa-plus" aria-hidden="true" /></button>
    </div></div> : null}
  </div>
}
