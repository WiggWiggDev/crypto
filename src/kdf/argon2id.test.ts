import { afterEach, describe, expect, it, vi } from 'vitest'

import { ARGON2_PIN_PARAMS } from '../params.js'
import { argon2id, setNativeArgon2idProvider, type NativeArgon2idProvider } from './argon2id.js'

describe('argon2id', () => {
  afterEach(() => {
    setNativeArgon2idProvider(null)
  })

  // Argon2id with PIN params (64 MiB / t=3) is intentionally slow; use a tiny
  // parameter set in unit tests so they finish in <100 ms. Production callers
  // never use these; the real ARGON2_*_PARAMS sets live in `../params.ts`.
  const FAST_PARAMS = {
    memKiB: 256,
    iterations: 1,
    parallelism: 1,
    outputLen: 32,
  } as const

  it('derives a 32-byte key with the JS fallback', async () => {
    const password = new TextEncoder().encode('correct horse battery staple')
    const salt = new Uint8Array(16)
    const out = await argon2id(password, salt, FAST_PARAMS)
    expect(out.length).toBe(32)
  })

  it('is deterministic for fixed (password, salt, params)', async () => {
    const password = new TextEncoder().encode('password')
    const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    const a = await argon2id(password, salt, FAST_PARAMS)
    const b = await argon2id(password, salt, FAST_PARAMS)
    expect(a).toEqual(b)
  })

  it('produces different keys for different salts', async () => {
    const password = new TextEncoder().encode('password')
    // Argon2id requires salt of at least 8 bytes per RFC 9106.
    const saltA = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1])
    const saltB = new Uint8Array([2, 2, 2, 2, 2, 2, 2, 2])
    const a = await argon2id(password, saltA, FAST_PARAMS)
    const b = await argon2id(password, saltB, FAST_PARAMS)
    expect(a).not.toEqual(b)
  })

  it('routes to the native provider when registered', async () => {
    const fakeOutput = new Uint8Array(32).fill(0xab)
    const provider: NativeArgon2idProvider = {
      argon2id: vi.fn().mockResolvedValue(fakeOutput),
    }
    setNativeArgon2idProvider(provider)

    const password = new Uint8Array([0x70, 0x77])
    const salt = new Uint8Array([0x73])
    const out = await argon2id(password, salt, FAST_PARAMS)

    expect(provider.argon2id).toHaveBeenCalledWith(password, salt, FAST_PARAMS)
    expect(out).toEqual(fakeOutput)
  })

  it('falls back to JS after the native provider is unregistered', async () => {
    const provider: NativeArgon2idProvider = {
      argon2id: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xff)),
    }
    setNativeArgon2idProvider(provider)
    setNativeArgon2idProvider(null)

    const out = await argon2id(new TextEncoder().encode('p'), new Uint8Array(8), FAST_PARAMS)
    expect(provider.argon2id).not.toHaveBeenCalled()
    // JS fallback runs to completion: output is 32 bytes, not the 0xff-filled
    // marker the native mock would have returned.
    expect(out.length).toBe(32)
    expect(out.every((b) => b === 0xff)).toBe(false)
  })

  it('ARGON2_PIN_PARAMS is well-formed', () => {
    expect(ARGON2_PIN_PARAMS.outputLen).toBe(32)
    expect(ARGON2_PIN_PARAMS.parallelism).toBeGreaterThanOrEqual(1)
    expect(ARGON2_PIN_PARAMS.iterations).toBeGreaterThanOrEqual(1)
    expect(ARGON2_PIN_PARAMS.memKiB).toBeGreaterThanOrEqual(1024)
  })
})
