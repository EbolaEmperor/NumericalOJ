import {harnessLogoClass, harnessName} from '../lib/harnessIdentity'
import {ModelLogo} from './ModelLogo'

export function FaithSieveHarness({harness, iconOnly = false}: {harness?: string | null; iconOnly?: boolean}) {
  const name = harnessName(harness)
  return harness ? <span className="faithsieve-runtime-identity" title={iconOnly ? undefined : name} role={iconOnly ? 'img' : undefined} aria-label={iconOnly ? name : undefined}><i className={harnessLogoClass(harness)} data-harness-logo data-harness-name={harness} aria-hidden="true" />{iconOnly ? null : <span>{name}</span>}</span> : iconOnly ? null : <>—</>
}

export function FaithSieveModel({model}: {model?: string | null}) {
  return model ? <span className="faithsieve-runtime-identity" title={model}><ModelLogo model={model} /><span>{model}</span></span> : <>—</>
}
