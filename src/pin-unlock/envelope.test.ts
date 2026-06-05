import { describe, expect, it } from 'vitest'

import type { Argon2idParams } from '../params.js'
import { derivePinUnlockKey, openMasterKeyWithPin, sealMasterKeyWithPin } from './envelope.js'

describe('pin-unlock envelope', () => {
  const masterKey = new Uint8Array(32).fill(0x77)

  // Tiny Argon2id params for unit tests so the suite finishes in <1s.
  // Production uses ARGON2_PIN_PARAMS (64 MiB / t=3); the per-arg override
  // lets us verify integration without paying that cost in CI.
  const FAST_PARAMS: Argon2idParams = {
    memKiB: 256,
    iterations: 1,
    parallelism: 1,
    outputLen: 32,
  }

  it('seal + open round-trips the master key with the right PIN', async () => {
    const env = await sealMasterKeyWithPin(masterKey, '123456', 'user-abc', FAST_PARAMS)
    const opened = await openMasterKeyWithPin(env, '123456', 'user-abc', FAST_PARAMS)
    expect(opened).not.toBeNull()
    expect(opened).toEqual(masterKey)
  })

  it('returns null (does not throw) on a wrong PIN', async () => {
    const env = await sealMasterKeyWithPin(masterKey, '111111', 'user-abc', FAST_PARAMS)
    const opened = await openMasterKeyWithPin(env, '999999', 'user-abc', FAST_PARAMS)
    expect(opened).toBeNull()
  })

  it('returns null on a different userId (cross-user binding)', async () => {
    const env = await sealMasterKeyWithPin(masterKey, '111111', 'user-a', FAST_PARAMS)
    const opened = await openMasterKeyWithPin(env, '111111', 'user-b', FAST_PARAMS)
    expect(opened).toBeNull()
  })

  it('each seal call uses a fresh salt + nonce', async () => {
    const a = await sealMasterKeyWithPin(masterKey, '123456', 'u', FAST_PARAMS)
    const b = await sealMasterKeyWithPin(masterKey, '123456', 'u', FAST_PARAMS)
    expect(a.salt).not.toEqual(b.salt)
    expect(a.nonce).not.toEqual(b.nonce)
    expect(a.ciphertext).not.toEqual(b.ciphertext)
  })

  it('derivePinUnlockKey is deterministic for fixed (pin, salt, userId)', async () => {
    const salt = new Uint8Array(32).fill(0x33)
    const a = await derivePinUnlockKey('123456', salt, 'user-x', FAST_PARAMS)
    const b = await derivePinUnlockKey('123456', salt, 'user-x', FAST_PARAMS)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  })

  it('derivePinUnlockKey domain-separates by userId', async () => {
    const salt = new Uint8Array(32).fill(0x44)
    const a = await derivePinUnlockKey('123456', salt, 'user-a', FAST_PARAMS)
    const b = await derivePinUnlockKey('123456', salt, 'user-b', FAST_PARAMS)
    expect(a).not.toEqual(b)
  })

  it('rejects a master key that is not 32 bytes', async () => {
    await expect(
      sealMasterKeyWithPin(new Uint8Array(16), '123456', 'u', FAST_PARAMS),
    ).rejects.toThrow()
  })
})
