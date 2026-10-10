import {faithSieveCostDisplay, type FaithSieveCostSummary} from '../lib/faithSieveCost'
import './faithsieve-cost.css'

export function FaithSieveCost({cost, className = '', label = '本次费用'}: {cost?: FaithSieveCostSummary | null; className?: string; label?: string}) {
  const display = faithSieveCostDisplay(cost)
  return <span className={`faithsieve-cost${className ? ` ${className}` : ''}`} aria-label={`${label}：${display.description}`} title={display.description}>
    <svg className="faithsieve-cost-logo" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" focusable="false">
      <path d="M3.25 2H4.9L8 6.35 11.1 2h1.65L9.4 6.75h3.1V8H8.75v1.9h3.75v1.25H8.75V14h-1.5v-2.85H3.5V9.9h3.75V8H3.5V6.75h3.1L3.25 2Z" />
    </svg>
    <span aria-hidden="true">{display.amount}</span>
  </span>
}
