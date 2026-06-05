/**
 * X25519 known-answer and wire-format tests.
 *
 * Pins the public key, ECDH shared secret, and HKDF-derived AEAD key for a fixed
 * pair of private keys, so any implementation of these primitives must reproduce
 * the same bytes to interoperate. Also round-trips a sealed envelope through
 * serialize/deserialize/open to keep the wire format stable, and checks that the
 * recipient-bound HKDF salt rejects a re-targeted envelope.
 *
 * `seal` draws a fresh random ephemeral per call, so the full envelope bytes
 * aren't pinned (that would need a deterministic RNG, which production code must
 * not have). The vectors below cover the deterministic primitives underneath it.
 */

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'

import {
  deserializeEnvelope,
  generateX25519Keypair,
  HYBRID_HKDF_INFO,
  open,
  seal,
  serializeEnvelope,
  x25519Ecdh,
  x25519PublicFromPrivate,
} from './index.js'

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

// Two fixed private keys that clamp to distinct X25519 scalars.
const RECIPIENT_PRIVATE = new Uint8Array(32).fill(0x11)
const EPHEMERAL_PRIVATE = new Uint8Array(32).fill(0x22)

// Known answers for the inputs above, computed with @noble/curves and
// @noble/hashes. A conforming implementation on any platform must match these.
const RECIPIENT_PUBLIC_HEX = '7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13'
const SHARED_SECRET_HEX = '9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056'
const AEAD_KEY_HEX = 'eda9f1451946aeeb6e1c73879ab276f6fa467a7357ee671405b429fa0860da21'

describe('X25519 known-answer vectors', () => {
  it('derives the pinned public key from the fixed private key', () => {
    expect(toHex(x25519PublicFromPrivate(RECIPIENT_PRIVATE))).toBe(RECIPIENT_PUBLIC_HEX)
  })

  it('derives the pinned shared secret in both ECDH directions', () => {
    const recipientPub = x25519PublicFromPrivate(RECIPIENT_PRIVATE)
    const ephemeralPub = x25519PublicFromPrivate(EPHEMERAL_PRIVATE)
    const fromEphemeral = x25519Ecdh(EPHEMERAL_PRIVATE, recipientPub)
    const fromRecipient = x25519Ecdh(RECIPIENT_PRIVATE, ephemeralPub)
    expect(fromEphemeral).toEqual(fromRecipient)
    expect(toHex(fromEphemeral)).toBe(SHARED_SECRET_HEX)
  })

  it('derives the pinned AEAD key with the production HKDF tag', () => {
    const recipientPub = x25519PublicFromPrivate(RECIPIENT_PRIVATE)
    const shared = x25519Ecdh(EPHEMERAL_PRIVATE, recipientPub)
    expect(toHex(hkdf(sha256, shared, recipientPub, HYBRID_HKDF_INFO, 32))).toBe(AEAD_KEY_HEX)
  })
})

describe('hybrid envelope wire format', () => {
  it('round-trips through serialize/deserialize/open', () => {
    const recipient = generateX25519Keypair()
    const plaintext = new TextEncoder().encode('parity round-trip')

    const envelope = seal(recipient.publicKey, plaintext)
    expect(envelope.schemeVersion).toBe(1)
    expect(envelope.ephemeralPublicKey.length).toBe(32)
    expect(envelope.nonce.length).toBe(24)
    expect(envelope.ciphertext.length).toBe(plaintext.length + 16)

    const wire = serializeEnvelope(envelope)
    expect(wire.length).toBe(1 + 32 + 24 + envelope.ciphertext.length)
    expect(wire[0]).toBe(1)

    const parsed = deserializeEnvelope(wire)
    expect(parsed.schemeVersion).toBe(envelope.schemeVersion)
    expect(parsed.ephemeralPublicKey).toEqual(envelope.ephemeralPublicKey)
    expect(parsed.nonce).toEqual(envelope.nonce)
    expect(parsed.ciphertext).toEqual(envelope.ciphertext)

    expect(open(recipient.privateKey, recipient.publicKey, parsed)).toEqual(plaintext)
  })

  it('rejects an envelope opened with the wrong recipient public key', () => {
    // The HKDF salt binds the AEAD key to the recipient public key, so a
    // different public yields a different key and the AEAD fails to authenticate.
    const recipient = generateX25519Keypair()
    const stranger = generateX25519Keypair()
    const envelope = seal(recipient.publicKey, new TextEncoder().encode('x'))
    expect(() => open(recipient.privateKey, stranger.publicKey, envelope)).toThrow()
  })

  it('rejects an envelope with an unsupported scheme version', () => {
    const recipient = generateX25519Keypair()
    const envelope = seal(recipient.publicKey, new TextEncoder().encode('x'))
    const tampered = { ...envelope, schemeVersion: 99 }
    expect(() => open(recipient.privateKey, recipient.publicKey, tampered)).toThrow(
      /unsupported scheme version/i,
    )
  })
})
