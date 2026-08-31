import {useEffect, useRef} from 'react'

type MarkdownRenderer = {
  clear?: (root: Element) => void
  enhance: (root: Element) => Promise<void>
}

declare global {
  interface Window {
    NumericalOJMarkdownRenderer?: MarkdownRenderer
  }
}

export function MarkdownContent({html, className}: {html: string; className: string}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const root = ref.current
    if (!root) return
    void window.NumericalOJMarkdownRenderer?.enhance(root)
    return () => window.NumericalOJMarkdownRenderer?.clear?.(root)
  }, [html])

  return <div ref={ref} className={className} data-numoj-markdown dangerouslySetInnerHTML={{__html: html}} />
}
