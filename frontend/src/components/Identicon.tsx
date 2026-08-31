import {useEffect, useRef} from 'react'

type IdenticonRuntime = {
  cellsForSeed: (seed: string) => unknown
  paint: (element: Element, avatar: unknown, label: string) => void
}

declare global {
  interface Window {
    NumojIdenticon?: IdenticonRuntime
  }
}

export function Identicon({seed, className}: {seed: string; className?: string}) {
  const ref = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    if (ref.current && window.NumojIdenticon) {
      window.NumojIdenticon.paint(
        ref.current,
        window.NumojIdenticon.cellsForSeed(seed || 'numericaloj'),
        seed || '未知用户',
      )
    }
  }, [seed])
  const classes = Array.from(new Set(['numoj-avatar', ...(className || '').split(/\s+/).filter(Boolean)])).join(' ')
  return <span ref={ref} className={classes} data-avatar-seed={seed} data-avatar-label={seed} aria-hidden="true" />
}
