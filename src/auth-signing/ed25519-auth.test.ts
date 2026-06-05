import { describe, expect, it } from 'vitest'

import {
  buildAuthChallengePayload,
  buildAuthKeyProvisioningPayload,
  deriveAuthPublicKey,
  deriveAuthSigningKeypair,
  signAuthChallenge,
  verifyAuthChallenge,
} from './ed25519-auth.js'
import { deriveRecoveryX25519PublicKey } from '../recovery/x25519-from-mnemonic.js'

const MASTER_A = new Uint8Array(32).fill(0x11)
const MASTER_B = new Uint8Array(32).fill(0x22)

function challenge(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte)
}

describe('deriveAuthSigningKeypair', () => {
  it('returns a 32-byte seed and 32-byte public key', () => {
    const kp = deriveAuthSigningKeypair(MASTER_A)
    expect(kp.privateKey.length).toBe(32)
    expect(kp.publicKey.length).toBe(32)
  })

  it('is deterministic for the same master key', () => {
    expect(deriveAuthSigningKeypair(MASTER_A).publicKey).toEqual(
      deriveAuthSigningKeypair(MASTER_A).publicKey,
    )
  })

  it('differs for different master keys', () => {
    expect(deriveAuthSigningKeypair(MASTER_A).publicKey).not.toEqual(
      deriveAuthSigningKeypair(MASTER_B).publicKey,
    )
  })

  it('rejects a master key that is not 32 bytes', () => {
    expect(() => deriveAuthSigningKeypair(new Uint8Array(31))).toThrow()
    expect(() => deriveAuthSigningKeypair(new Uint8Array(33))).toThrow()
  })
})

describe('deriveAuthPublicKey', () => {
  it('matches the public key from deriveAuthSigningKeypair', () => {
    expect(deriveAuthPublicKey(MASTER_A)).toEqual(deriveAuthSigningKeypair(MASTER_A).publicKey)
  })
})

describe('sign / verify round-trip', () => {
  it('verifies a signature the matching key produced', () => {
    const kp = deriveAuthSigningKeypair(MASTER_A)
    const payload = buildAuthChallengePayload(challenge(0xaa), 'WIGG-1234')
    const sig = signAuthChallenge(kp.privateKey, payload)
    expect(sig.length).toBe(64)
    expect(verifyAuthChallenge(kp.publicKey, payload, sig)).toBe(true)
  })

  it('rejects a signature from a different master key', () => {
    const payload = buildAuthChallengePayload(challenge(0xaa), 'WIGG-1234')
    const sig = signAuthChallenge(deriveAuthSigningKeypair(MASTER_B).privateKey, payload)
    expect(verifyAuthChallenge(deriveAuthSigningKeypair(MASTER_A).publicKey, payload, sig)).toBe(
      false,
    )
  })

  it('rejects when the challenge differs (replay of an old challenge fails)', () => {
    const kp = deriveAuthSigningKeypair(MASTER_A)
    const sig = signAuthChallenge(
      kp.privateKey,
      buildAuthChallengePayload(challenge(0xaa), 'WIGG-1'),
    )
    const otherPayload = buildAuthChallengePayload(challenge(0xbb), 'WIGG-1')
    expect(verifyAuthChallenge(kp.publicKey, otherPayload, sig)).toBe(false)
  })

  it('rejects when the accountId differs (cross-account relay fails)', () => {
    const kp = deriveAuthSigningKeypair(MASTER_A)
    const c = challenge(0xaa)
    const sig = signAuthChallenge(kp.privateKey, buildAuthChallengePayload(c, 'WIGG-1'))
    expect(verifyAuthChallenge(kp.publicKey, buildAuthChallengePayload(c, 'WIGG-2'), sig)).toBe(
      false,
    )
  })

  it('rejects malformed public key / signature lengths', () => {
    const kp = deriveAuthSigningKeypair(MASTER_A)
    const payload = buildAuthChallengePayload(challenge(0xaa), 'WIGG-1')
    const sig = signAuthChallenge(kp.privateKey, payload)
    expect(() => verifyAuthChallenge(new Uint8Array(31), payload, sig)).toThrow()
    expect(() => verifyAuthChallenge(kp.publicKey, payload, new Uint8Array(63))).toThrow()
  })
})

describe('buildAuthChallengePayload', () => {
  it('is deterministic and order-stable', () => {
    expect(buildAuthChallengePayload(challenge(0x01), 'WIGG-1')).toEqual(
      buildAuthChallengePayload(challenge(0x01), 'WIGG-1'),
    )
  })

  it('separates account from challenge (no field-boundary ambiguity)', () => {
    // 'WIGG-1' + chal(0x00..) must not collide with 'WIGG' + '-1' merged into
    // the challenge. The 0x00 separators guarantee distinct payloads.
    const a = buildAuthChallengePayload(challenge(0x31), 'WIGG')
    const b = buildAuthChallengePayload(challenge(0x31), 'WIG')
    expect(a).not.toEqual(b)
  })
})

describe('proof-of-possession (buildAuthKeyProvisioningPayload)', () => {
  it('verifies a self-certifying proof the holder produced for their own key', () => {
    const kp = deriveAuthSigningKeypair(MASTER_A)
    const proof = signAuthChallenge(kp.privateKey, buildAuthKeyProvisioningPayload(kp.publicKey))
    expect(
      verifyAuthChallenge(kp.publicKey, buildAuthKeyProvisioningPayload(kp.publicKey), proof),
    ).toBe(true)
  })

  it('rejects a proof signed by a different key than the one uploaded (poisoned key)', () => {
    const real = deriveAuthSigningKeypair(MASTER_A)
    const attacker = deriveAuthSigningKeypair(MASTER_B)
    // Attacker uploads the real public key but signs the proof with their own
    // key, which must fail: they can't prove possession of the real private key.
    const forgedProof = signAuthChallenge(
      attacker.privateKey,
      buildAuthKeyProvisioningPayload(real.publicKey),
    )
    expect(
      verifyAuthChallenge(
        real.publicKey,
        buildAuthKeyProvisioningPayload(real.publicKey),
        forgedProof,
      ),
    ).toBe(false)
  })

  it('provisioning payload is domain-separated from the login-challenge payload', () => {
    const kp = deriveAuthSigningKeypair(MASTER_A)
    // A login signature must not verify as a provisioning proof and vice-versa.
    const loginSig = signAuthChallenge(
      kp.privateKey,
      buildAuthChallengePayload(challenge(0x01), 'WIGG-1'),
    )
    expect(
      verifyAuthChallenge(kp.publicKey, buildAuthKeyProvisioningPayload(kp.publicKey), loginSig),
    ).toBe(false)
  })

  it('rejects a malformed (non-32-byte) public key', () => {
    expect(() => buildAuthKeyProvisioningPayload(new Uint8Array(31))).toThrow()
  })
})

describe('key separation from other master-key-derived keys', () => {
  it('auth public key never equals the recovery X25519 public key path', async () => {
    // Different derivations (different domain separation) must not collide.
    // Recovery derives from a mnemonic seed; here we only assert the auth key
    // is a stable, distinct 32 bytes.
    const authPub = deriveAuthPublicKey(MASTER_A)
    const recoveryPub = await deriveRecoveryX25519PublicKey(
      'legal winner thank year wave sausage worth useful legal winner thank yellow',
    )
    expect(authPub).not.toEqual(recoveryPub)
  })
})
