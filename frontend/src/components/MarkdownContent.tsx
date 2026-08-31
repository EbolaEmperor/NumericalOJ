import {useRef} from 'react'

import {useMarkdownEnhancements} from './useMarkdownEnhancements'

export function MarkdownContent({html, className, as = 'div'}: {html: string; className: string; as?: 'div' | 'span'}) {
  const ref = useRef<HTMLElement>(null)
  useMarkdownEnhancements(ref, html)

  return as === 'span'
    ? <span ref={ref} className={className} data-numoj-markdown dangerouslySetInnerHTML={{__html: html}} />
    : <div ref={ref as React.Ref<HTMLDivElement>} className={className} data-numoj-markdown dangerouslySetInnerHTML={{__html: html}} />
}
