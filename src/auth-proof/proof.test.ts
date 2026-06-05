import { describe, expect, it } from 'vitest'

import { AUTH_CHALLENGE, computeAuthProofHash, computeAuthProofHashHex } from './proof.js'

describe('computeAuthProofHash', () => {
  it('returns 32 raw bytes', () => {
    const masterKey = new Uint8Array(32).fill(0x11)
    const out = computeAuthProofHash(masterKey)
    expect(out.length).toBe(32)
  })

  it('is deterministic for fixed master key', () => {
    const masterKey = new Uint8Array(32).fill(0x22)
    const a = computeAuthProofHash(masterKey)
    const b = computeAuthProofHash(masterKey)
    expect(a).toEqual(b)
  })

  it('differs for different master keys', () => {
    const a = computeAuthProofHash(new Uint8Array(32).fill(0x33))
    const b = computeAuthProofHash(new Uint8Array(32).fill(0x44))
    expect(a).not.toEqual(b)
  })

  it('rejects a master key that is not 32 bytes', () => {
    expect(() => computeAuthProofHash(new Uint8Array(31))).toThrow()
    expect(() => computeAuthProofHash(new Uint8Array(33))).toThrow()
  })

  it('hex variant returns 64 lowercase hex chars', () => {
    const masterKey = new Uint8Array(32).fill(0x55)
    const hex = computeAuthProofHashHex(masterKey)
    expect(hex.length).toBe(64)
    expect(/^[0-9a-f]+$/.test(hex)).toBe(true)
  })

  it('AUTH_CHALLENGE is the canonical v1 string (do not change post-launch)', () => {
    // Tripwire: changing AUTH_CHALLENGE invalidates every stored proof hash, so
    // a change must go through a versioned migration instead.
    expect(AUTH_CHALLENGE).toBe('wiggwigg-auth-challenge-v1')
  })
})
