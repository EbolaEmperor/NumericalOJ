/**
 * 生成浏览器侧幂等请求标识。
 *
 * randomUUID 只在安全上下文中稳定可用；旧版页面在普通 HTTP 下会退回
 * getRandomValues，并手动设置 RFC 4122 v4 的版本位与变体位。
 */
export function browserUuid(browserCrypto: Crypto = window.crypto): string {
  if (typeof browserCrypto.randomUUID === 'function') return browserCrypto.randomUUID()
  const bytes = new Uint8Array(16)
  browserCrypto.getRandomValues(bytes)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
