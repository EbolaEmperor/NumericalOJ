import type {FaithSieveExecutionMode} from '../pages/faithsieveTypes'
import './ExecutionModeLogo.css'

export function ExecutionModeLogo({mode}: {mode: FaithSieveExecutionMode}) {
  return <svg className="faithsieve-execution-logo" width="1em" height="1em" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" data-execution-mode-logo={mode} aria-hidden="true" focusable="false">{mode === 'workflow' ? <><rect x="9" y="2" width="6" height="5" rx="1" /><rect x="2" y="17" width="6" height="5" rx="1" /><rect x="16" y="17" width="6" height="5" rx="1" /><path d="M12 7v5H5v5m7-5h7v5" /></> : <><path d="M6 2h8l5 5v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1Z" /><path d="M14 2v5h5M9 12h6M9 16h6" /></>}</svg>
}

export function ExecutionModeIdentity({mode}: {mode: FaithSieveExecutionMode}) {
  return <span className="faithsieve-runtime-identity faithsieve-execution-identity"><ExecutionModeLogo mode={mode} /><span>{mode === 'workflow' ? 'Workflow' : 'Skill'}</span></span>
}
