import {useEffect, useId, useMemo, useRef, type CSSProperties} from 'react'

type Point = {x: number; y: number}
type Curve = {particleCount: number; trailSpan: number; durationMs: number; pulseDurationMs: number; rotationDurationMs: number; strokeWidth: number; rotate?: boolean; point: (progress: number, detailScale: number) => Point}

function customRose(petals: number, particleCount: number, trailSpan: number, durationMs: number, pulseDurationMs: number, rotationDurationMs: number): Curve {
  return {particleCount, trailSpan, durationMs, pulseDurationMs, rotationDurationMs, strokeWidth: 5.5, point(progress, detailScale) {
    const t = progress * Math.PI * 2
    const x = 7 * Math.cos(t) - 3 * detailScale * Math.cos(petals * t)
    const y = 7 * Math.sin(t) - 3 * detailScale * Math.sin(petals * t)
    return {x: 50 + x * 3.9, y: 50 + y * 3.9}
  }}
}

function polarRose(petals: number, particleCount: number, trailSpan: number, durationMs: number, pulseDurationMs: number, strokeWidth: number): Curve {
  return {particleCount, trailSpan, durationMs, pulseDurationMs, rotationDurationMs: 28_000, strokeWidth, point(progress, detailScale) {
    const t = progress * Math.PI * 2
    const radius = (9.2 + detailScale * 0.6) * (0.72 + detailScale * 0.28) * Math.cos(petals * t)
    return {x: 50 + Math.cos(t) * radius * 3.25, y: 50 + Math.sin(t) * radius * 3.25}
  }}
}

const curves: Curve[] = [
  customRose(7, 80, .38, 4_600, 4_200, 28_000),
  customRose(5, 78, .38, 4_600, 4_200, 28_000),
  customRose(9, 85, .39, 4_700, 4_200, 30_000),
  {particleCount: 90, trailSpan: .42, durationMs: 5_200, pulseDurationMs: 4_600, rotationDurationMs: 28_000, strokeWidth: 5.2, point(progress, detailScale) {
    const t = progress * Math.PI * 2
    const radius = 7 - 2.7 * detailScale * Math.cos(7 * t)
    return {x: 50 + Math.cos(t) * radius * 3.9, y: 50 + Math.sin(t) * radius * 3.9}
  }},
  polarRose(2, 92, .3, 5_200, 4_300, 4.6),
  polarRose(3, 95, .31, 5_300, 4_400, 4.6),
  {particleCount: 108, trailSpan: .28, durationMs: 7_800, pulseDurationMs: 6_800, rotationDurationMs: 44_000, strokeWidth: 4.3, rotate: false, point(progress, detailScale) {
    const t = progress * Math.PI * 2
    const angle = t * 4
    const radius = 8 + (1 - Math.cos(t)) * (8.5 + detailScale * 2.4)
    return {x: 50 + Math.cos(angle) * radius, y: 50 + Math.sin(angle) * radius}
  }},
]

function normalizeProgress(progress: number) {
  return ((progress % 1) + 1) % 1
}

function buildPath(config: Curve, scale: number) {
  const commands: string[] = []
  for (let index = 0; index <= 150; index += 1) {
    const point = config.point(index / 150, scale)
    commands.push(`${index ? 'L' : 'M'} ${point.x.toFixed(2)} ${point.y.toFixed(2)}`)
  }
  return commands.join(' ')
}

export function MathCurveLoader({label = '正在处理…', size = 'sm', iconOnly = false, className = '', colorA = '#111111', colorB = '#000000', strokeScale = 1, particleCount: particleCountOverride, hidden = false, ariaLabel}: {label?: string; size?: 'xs' | 'sm' | 'md' | 'lg'; iconOnly?: boolean; className?: string; colorA?: string; colorB?: string; strokeScale?: number; particleCount?: number; hidden?: boolean; ariaLabel?: string}) {
  const serial = useId().replace(/[^a-z0-9_-]/gi, '')
  const seed = useMemo(() => [...serial].reduce((value, character) => Math.imul(value ^ character.charCodeAt(0), 16_777_619) >>> 0, 2_166_136_261), [serial])
  const curve = curves[seed % curves.length]
  const particleCount = Math.max(1, Math.round(particleCountOverride ?? {xs: 42, sm: 52, md: 68, lg: curve.particleCount}[size]))
  const rootRef = useRef<HTMLSpanElement>(null)
  const groupRef = useRef<SVGGElement>(null)
  const pathRef = useRef<SVGPathElement>(null)
  const particlesRef = useRef<Array<SVGCircleElement | null>>([])

  useEffect(() => {
    let frame = 0
    let lastPathAt = 0
    const startedAt = performance.now()
    const phase = ((seed >>> 8) % 10_000) / 10_000
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)')
    const render = (now: number) => {
      frame = 0
      const root = rootRef.current
      const group = groupRef.current
      const path = pathRef.current
      if (!root || !group || !path) return
      if (root.hidden || root.getClientRects().length === 0) {
        frame = requestAnimationFrame(render)
        return
      }
      const elapsed = reducedMotion.matches ? 0 : now - startedAt
      const progress = ((elapsed + phase * curve.durationMs) % curve.durationMs) / curve.durationMs
      const pulse = ((elapsed + phase * curve.pulseDurationMs) % curve.pulseDurationMs) / curve.pulseDurationMs
      const scale = .52 + ((Math.sin(pulse * Math.PI * 2 + .55) + 1) / 2) * .48
      const rotation = reducedMotion.matches || curve.rotate === false ? 0 : -(((elapsed + phase * curve.rotationDurationMs) % curve.rotationDurationMs) / curve.rotationDurationMs) * 360
      group.setAttribute('transform', `rotate(${rotation} 50 50)`)
      if (reducedMotion.matches || now - lastPathAt >= 50) {
        path.setAttribute('d', buildPath(curve, scale))
        lastPathAt = now
      }
      particlesRef.current.forEach((node, index) => {
        if (!node) return
        const tailOffset = index / Math.max(1, particleCount - 1)
        const point = curve.point(normalizeProgress(progress - tailOffset * curve.trailSpan), scale)
        const fade = Math.pow(1 - tailOffset, .56)
        node.setAttribute('cx', point.x.toFixed(2))
        node.setAttribute('cy', point.y.toFixed(2))
        node.setAttribute('r', ((.9 + fade * 2.7) * strokeScale).toFixed(2))
        node.setAttribute('opacity', (.04 + fade * .96).toFixed(3))
      })
      if (!reducedMotion.matches) frame = requestAnimationFrame(render)
    }
    frame = requestAnimationFrame(render)
    const resume = () => {if (!frame) frame = requestAnimationFrame(render)}
    document.addEventListener('visibilitychange', resume)
    reducedMotion.addEventListener('change', resume)
    return () => {
      if (frame) cancelAnimationFrame(frame)
      document.removeEventListener('visibilitychange', resume)
      reducedMotion.removeEventListener('change', resume)
    }
  }, [curve, particleCount, seed, strokeScale])

  const gradientId = `math-curve-gradient-${serial}`
  return <span ref={rootRef} className={`math-curve-loader${className ? ` ${className}` : ''}`} data-size={size} role="status" aria-live="polite" aria-label={ariaLabel} hidden={hidden} style={{'--math-curve-color-a': colorA, '--math-curve-color-b': colorB} as CSSProperties}>
    <span className="math-curve-loader__canvas"><svg className="math-curve-loader__svg" viewBox="0 0 100 100" fill="none" aria-hidden="true"><defs><linearGradient id={gradientId} x1="10%" y1="5%" x2="90%" y2="95%"><stop offset="0%" style={{stopColor: 'var(--math-curve-color-a)'}} /><stop offset="100%" style={{stopColor: 'var(--math-curve-color-b)'}} /></linearGradient></defs><g ref={groupRef}><path ref={pathRef} stroke={`url(#${gradientId})`} strokeWidth={curve.strokeWidth * strokeScale} strokeLinecap="round" strokeLinejoin="round" opacity="0" />{Array.from({length: particleCount}, (_, index) => <circle ref={(node) => {particlesRef.current[index] = node}} fill={`url(#${gradientId})`} key={index} />)}</g></svg></span>
    {!iconOnly ? <span className="math-curve-loader__label">{label}</span> : null}
  </span>
}
