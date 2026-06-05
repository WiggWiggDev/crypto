import { afterEach, describe, expect, it, vi } from 'vitest'

import { pbkdf2Sha256, setNativePbkdf2Provider, type NativePbkdf2Provider } from './pbkdf2.js'

describe('pbkdf2Sha256', () => {
  afterEach(() => {
    setNativePbkdf2Provider(null)
  })

  // RFC 6070 test vector for PBKDF2-HMAC-SHA1 doesn't apply here (we use
  // SHA-256). Use a small iteration count and a known password/salt to verify
  // the JS fallback runs end-to-end.
  it('derives a 32-byte key with the JS fallback', async () => {
    const password = new TextEncoder().encode('password')
    const salt = new TextEncoder().encode('salt')
    const out = await pbkdf2Sha256(password, salt, {
      iterations: 1000,
      outputLen: 32,
    })
    expect(out.length).toBe(32)
  })

  it('is deterministic for fixed inputs', async () => {
    const password = new TextEncoder().encode('password')
    const salt = new TextEncoder().encode('salt')
    const params = { iterations: 1000, outputLen: 32 }
    const a = await pbkdf2Sha256(password, salt, params)
    const b = await pbkdf2Sha256(password, salt, params)
    expect(a).toEqual(b)
  })

  it('scales output length', async () => {
    const password = new TextEncoder().encode('p')
    const salt = new TextEncoder().encode('s')
    const out16 = await pbkdf2Sha256(password, salt, {
      iterations: 100,
      outputLen: 16,
    })
    const out64 = await pbkdf2Sha256(password, salt, {
      iterations: 100,
      outputLen: 64,
    })
    expect(out16.length).toBe(16)
    expect(out64.length).toBe(64)
  })

  it('routes to the native provider when registered', async () => {
    const fakeOutput = new Uint8Array(32).fill(0xcd)
    const provider: NativePbkdf2Provider = {
      pbkdf2Sha256: vi.fn().mockResolvedValue(fakeOutput),
    }
    setNativePbkdf2Provider(provider)

    const password = new Uint8Array([0x70])
    const salt = new Uint8Array([0x73])
    const params = { iterations: 200_000, outputLen: 32 }
    const out = await pbkdf2Sha256(password, salt, params)

    expect(provider.pbkdf2Sha256).toHaveBeenCalledWith(password, salt, params)
    expect(out).toEqual(fakeOutput)
  })
})
