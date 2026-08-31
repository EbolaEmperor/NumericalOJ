import {memo, useRef} from 'react'

import {useMarkdownEnhancements} from './useMarkdownEnhancements'

export const MarkdownContent = memo(function MarkdownContent({html, className, as = 'div', ariaLabel}: {html: string; className: string; as?: 'div' | 'span' | 'aside'; ariaLabel?: string}) {
  const ref = useRef<HTMLElement>(null)
  useMarkdownEnhancements(ref, html)

  if (as === 'span') return <span ref={ref} className={className} data-numoj-markdown dangerouslySetInnerHTML={{__html: html}} />
  if (as === 'aside') return <aside ref={ref as React.Ref<HTMLElement>} className={className} aria-label={ariaLabel} data-numoj-markdown dangerouslySetInnerHTML={{__html: html}} />
  return <div ref={ref as React.Ref<HTMLDivElement>} className={className} data-numoj-markdown dangerouslySetInnerHTML={{__html: html}} />
})
