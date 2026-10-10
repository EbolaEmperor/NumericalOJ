import {memo, useRef} from 'react'

import {MarkdownContent} from './MarkdownContent'
import {useMarkdownEnhancements} from './useMarkdownEnhancements'

interface FaithSieveReportProps {
  text: string
  /** 仅接收后端 shared.markdown 清洗后的 HTML。 */
  html?: string
  className?: string
}

function ReportText({text, className}: {text: string; className: string}) {
  const ref = useRef<HTMLDivElement>(null)
  useMarkdownEnhancements(ref, text)
  return <div ref={ref} className={className} style={{whiteSpace: 'pre-wrap'}}>{text}</div>
}

export const FaithSieveReport = memo(function FaithSieveReport({text, html, className = ''}: FaithSieveReportProps) {
  const classes = `faithsieve-report numoj-markdown${className ? ` ${className}` : ''}`
  return html
    ? <MarkdownContent html={html} className={classes} />
    : <ReportText text={text} className={classes} />
})
