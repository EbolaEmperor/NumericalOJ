import {detectModelFamily, modelFamilyIconClass} from '../lib/modelFamily'

export function modelLogoClass(model: unknown) {
  return modelFamilyIconClass(model)
}

export function ModelLogo({model, className = ''}: {model: unknown; className?: string}) {
  const name = String(model || '')
  const resolvedClass = modelLogoClass(name)
  const family = detectModelFamily(name)

  return (
    <i
      className={`${resolvedClass}${className ? ` ${className}` : ''}`}
      data-model-family-logo
      data-model-name={name}
      data-model-family={family || undefined}
      aria-hidden="true"
    />
  )
}
