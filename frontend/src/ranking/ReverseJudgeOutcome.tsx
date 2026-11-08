import type {ReactNode} from 'react'

export function ReverseJudgeOutcome({status, children, icon}: {status: unknown; children: ReactNode; icon?: string}) {
  const passed = status === 'passed'
  const failed = status === 'failed' || status === 'error'
  const outcomeIcon = icon || (passed ? 'fa-circle-check' : failed ? 'fa-circle-xmark' : 'fa-clock')
  return <span className={`rj-step-outcome${failed ? ' is-error' : passed ? '' : ' is-pending'}`}><i className={`fas ${outcomeIcon}`} aria-hidden="true" /><span>{children}</span></span>
}
