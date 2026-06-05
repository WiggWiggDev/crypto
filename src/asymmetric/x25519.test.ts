import { describe, expect, it } from 'vitest'

import { generateX25519Keypair, x25519Ecdh, x25519PublicFromPrivate } from './x25519.js'

describe('x25519', () => {
  it('generateX25519Keypair produces 32-byte components', () => {
    const { privateKey, publicKey } = generateX25519Keypair()
    expect(privateKey.length).toBe(32)
    expect(publicKey.length).toBe(32)
  })

  it('x25519PublicFromPrivate is deterministic', () => {
    const { privateKey } = generateX25519Keypair()
    const p1 = x25519PublicFromPrivate(privateKey)
    const p2 = x25519PublicFromPrivate(privateKey)
    expect(p1).toEqual(p2)
  })

  it('ECDH is commutative (Alice.priv × Bob.pub == Bob.priv × Alice.pub)', () => {
    const alice = generateX25519Keypair()
    const bob = generateX25519Keypair()
    const ab = x25519Ecdh(alice.privateKey, bob.publicKey)
    const ba = x25519Ecdh(bob.privateKey, alice.publicKey)
    expect(ab).toEqual(ba)
  })

  it('rejects malformed key lengths', () => {
    expect(() => x25519Ecdh(new Uint8Array(31), new Uint8Array(32))).toThrow()
    expect(() => x25519Ecdh(new Uint8Array(32), new Uint8Array(31))).toThrow()
    expect(() => x25519PublicFromPrivate(new Uint8Array(31))).toThrow()
  })
})
