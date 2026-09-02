import {describe, expect, it} from 'vitest'

import {digestSha256Fallback} from './repositoryUpload'

describe('repository upload HTTP fallback', () => {
  it('在 subtle crypto 不可用时仍生成标准 SHA-256', () => {
    expect(digestSha256Fallback(new TextEncoder().encode('').buffer)).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
    expect(digestSha256Fallback(new TextEncoder().encode('abc').buffer)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })
})
