import {useLayoutEffect, useRef} from 'react'

type ModelFamilyApi = {
  iconClass?: (name: string) => string
  paint?: (element: HTMLElement, name?: string) => string | null
}

declare global {
  interface Window {
    NumojModelFamily?: ModelFamilyApi
  }
}

export function modelLogoClass(model: unknown) {
  const name = String(model || '')
  return typeof window === 'undefined'
    ? 'fas fa-microchip'
    : window.NumojModelFamily?.iconClass?.(name) || 'fas fa-microchip'
}

export function ModelLogo({model, className = ''}: {model: unknown; className?: string}) {
  const elementRef = useRef<HTMLElement>(null)
  const name = String(model || '')
  const resolvedClass = modelLogoClass(name)

  useLayoutEffect(() => {
    if (elementRef.current) window.NumojModelFamily?.paint?.(elementRef.current, name)
  }, [name])

  return (
    <i
      ref={elementRef}
      className={`${resolvedClass}${className ? ` ${className}` : ''}`}
      data-model-family-logo
      data-model-name={name}
      aria-hidden="true"
    />
  )
}
