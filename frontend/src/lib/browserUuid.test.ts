import {describe, expect, it} from 'vitest'

import {browserUuid} from './browserUuid'

describe('browserUuid', () => {
  it('优先沿用 randomUUID', () => {
    const crypto = {randomUUID: () => '12345678-1234-4234-8234-123456789abc'} as unknown as Crypto
    expect(browserUuid(crypto)).toBe('12345678-1234-4234-8234-123456789abc')
  })

  it('HTTP 环境用 getRandomValues 生成 RFC 4122 v4 UUID', () => {
    const crypto = {
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(0)
        return bytes
      },
    } as unknown as Crypto
    expect(browserUuid(crypto)).toBe('00000000-0000-4000-8000-000000000000')
  })
})
