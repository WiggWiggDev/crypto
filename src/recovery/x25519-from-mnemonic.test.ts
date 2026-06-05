import { describe, expect, it } from 'vitest'

import { seal, open } from '../asymmetric/hybrid.js'
import {
  deriveRecoveryX25519PrivateKey,
  deriveRecoveryX25519PublicKey,
} from './x25519-from-mnemonic.js'

const STABLE_MNEMONIC =
  'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'

describe('deriveRecoveryX25519PrivateKey', () => {
  it('is deterministic for the same mnemonic', async () => {
    const a = await deriveRecoveryX25519PrivateKey(STABLE_MNEMONIC)
    const b = await deriveRecoveryX25519PrivateKey(STABLE_MNEMONIC)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  })

  it('differs for a different mnemonic', async () => {
    const other =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'
    const a = await deriveRecoveryX25519PrivateKey(STABLE_MNEMONIC)
    const b = await deriveRecoveryX25519PrivateKey(other)
    expect(a).not.toEqual(b)
  })
})

describe('deriveRecoveryX25519PublicKey', () => {
  it('is deterministic and 32 bytes', async () => {
    const a = await deriveRecoveryX25519PublicKey(STABLE_MNEMONIC)
    const b = await deriveRecoveryX25519PublicKey(STABLE_MNEMONIC)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  })
})

describe('recovery seal/open round-trip', () => {
  it('seals and opens a master-key-sized payload using mnemonic-derived keys', async () => {
    const masterKey = crypto.getRandomValues(new Uint8Array(32))
    const publicKey = await deriveRecoveryX25519PublicKey(STABLE_MNEMONIC)
    const envelope = seal(publicKey, masterKey)

    const privateKey = await deriveRecoveryX25519PrivateKey(STABLE_MNEMONIC)
    const opened = open(privateKey, publicKey, envelope)
    expect(opened).toEqual(masterKey)
  })
})
