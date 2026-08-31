import {identiconCellFlags, identiconCellsForSeed, type IdenticonAvatar} from '../lib/identicon'

export function Identicon({seed, avatar, className}: {seed: string; avatar?: IdenticonAvatar; className?: string}) {
  const label = seed || '未知用户'
  const cells = identiconCellFlags(avatar ?? identiconCellsForSeed(seed || 'numericaloj'))
  const classes = Array.from(new Set(['numoj-avatar', ...(className || '').split(/\s+/).filter(Boolean)])).join(' ')
  return <span className={classes} data-avatar-seed={seed} data-avatar-label={seed} title={label} aria-label={`${label} 的头像`}>{cells.map((filled, index) => <span className={filled ? 'is-filled' : undefined} aria-hidden="true" key={index} />)}</span>
}
