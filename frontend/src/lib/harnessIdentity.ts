// 沿用通用 Agent 的 Harness 名称与图标映射。
export function harnessLogoClass(value: unknown) {
  const key = String(value || '').trim().toLowerCase().replaceAll('_', '-') === 'pi' ? 'pi' : 'claude-code'
  return `harness-logo harness-logo--${key}`
}

export function harnessName(value: unknown) {
  const text = String(value || '')
  const key = text.trim().toLowerCase().replaceAll('-', '_')
  return ({claude_code: 'Claude Code', pi: 'Pi'} as Record<string, string>)[key] || text
}
