export function ListUsername({username}: {username?: string | null}) {
  const characters = Array.from(username || '')
  const label = characters.length > 10 ? `${characters.slice(0, 10).join('')}…` : username || '—'
  return <span title={username || undefined}>{label}</span>
}
