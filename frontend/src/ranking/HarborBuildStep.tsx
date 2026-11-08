import {useEffect, useRef} from 'react'

import type {JsonRecord} from '../api/types'
import {MathCurveLoader} from '../components/MathCurveLoader'
import {ReverseJudgeOutcome} from './ReverseJudgeOutcome'
import './harbor-build.css'

function cleanTerminalOutput(value: unknown) {
  return String(value || '').replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\r(?!\n)/g, '\n')
}

function lineColor(line: string) {
  if (/\b(error|failed|fatal)\b|构建失败/i.test(line)) return 'error'
  if (/\b(warn|warning)\b/i.test(line)) return 'warning'
  if (/\b(cached|done)\b|复用|构建完成/i.test(line)) return 'success'
  if (/^#\d+|\b(FROM|RUN|COPY|WORKDIR)\b/.test(line)) return 'command'
  return 'output'
}

export function HarborBuildStep({step}: {step: JsonRecord}) {
  const terminal = useRef<HTMLPreElement>(null)
  const followOutput = useRef(true)
  const running = step.status === 'running'
  const failed = ['failed', 'error'].includes(String(step.status))
  const logs = cleanTerminalOutput(step.stdout) + (step.stderr ? '\n' + cleanTerminalOutput(step.stderr) : '')
  useEffect(() => {
    if (terminal.current && followOutput.current) terminal.current.scrollTop = terminal.current.scrollHeight
  }, [logs])
  return <section className="rj-build" aria-label="Harbor 构建环境">
    <div className="rj-build-status">
      {running ? <MathCurveLoader size="md" label="正在构建任务环境…" /> : <ReverseJudgeOutcome status={step.status}>{failed ? '构建失败' : step.status === 'passed' ? '任务环境已就绪' : '等待构建任务环境'}</ReverseJudgeOutcome>}
    </div>
    {step.error_message ? <div className="rj-alert" role="alert">{String(step.error_message)}</div> : null}
    <div className="rj-build-terminal">
      <div className="rj-build-terminal-bar"><span className="rj-build-terminal-dots" aria-hidden="true"><i /><i /><i /></span><span><i className="fas fa-terminal" aria-hidden="true" /> Harbor · 构建日志</span><span className={`rj-build-terminal-state${running ? ' is-running' : ''}`}>{running ? 'BUILDING' : failed ? 'FAILED' : step.status === 'passed' ? 'READY' : 'WAITING'}</span></div>
      <pre ref={terminal} className="rj-build-terminal-output" role="log" aria-label="构建日志" aria-live="off" tabIndex={0} onScroll={() => {const node = terminal.current; if (node) followOutput.current = node.scrollHeight - node.scrollTop - node.clientHeight < 32}}>{logs ? logs.split('\n').map((line, index) => <span className={`rj-build-line is-${lineColor(line)}`} key={index}>{line || ' '}{'\n'}</span>) : <span className="rj-build-line is-muted">$ 等待构建日志…</span>}</pre>
    </div>
  </section>
}
