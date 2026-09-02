/**
 * Copy text in both secure contexts and ordinary HTTP deployments.
 *
 * The async Clipboard API is normally unavailable outside HTTPS. The old
 * Jinja runtime deliberately fell back to a temporary textarea, so React
 * callers must not call navigator.clipboard directly.
 */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch { /* Safari and non-secure contexts continue through the fallback. */ }
  }

  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.readOnly = true
  textarea.setAttribute('aria-hidden', 'true')
  Object.assign(textarea.style, {position: 'fixed', left: '-9999px', opacity: '0'})
  document.body.appendChild(textarea)
  textarea.select()
  const copied = typeof document.execCommand === 'function' && document.execCommand('copy')
  textarea.remove()
  if (!copied) throw new Error('复制失败：当前浏览器未提供可用的剪贴板能力')
}
