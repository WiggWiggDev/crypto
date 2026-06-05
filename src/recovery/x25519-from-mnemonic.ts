/**
 * Derive an X25519 keypair from a BIP39 mnemonic.
 *
 * The recovery phrase is the root of trust for account recovery. This module
 * derives a dedicated X25519 private key from the BIP39 seed, domain-separated by
 * the HKDF info tag so it can't collide with any other key derived from the same
 * phrase.
 *
 * Derivation:
 *   mnemonic -> @scure/bip39 mnemonicToSeed (64 bytes) -> first 32 bytes
 *   -> HKDF-SHA256(salt: RECOVERY_KEY_SALT, info: 'wiggwigg-recovery-x25519-v1', len: 32)
 *   -> X25519 scalar (private key), then X25519 public via scalar-mult
 *
 * RECOVERY_KEY_SALT is a domain separator, not a secret. A test vector pins the
 * derived bytes so the constant can't drift unnoticed.
 */

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { mnemonicToSeed } from '@scure/bip39'

import { x25519PublicFromPrivate } from '../asymmetric/x25519.js'

const RECOVERY_KEY_SALT_BYTES = new TextEncoder().encode('wiggwigg-recovery-key-v1')
const X25519_INFO_BYTES = new TextEncoder().encode('wiggwigg-recovery-x25519-v1')

/**
 * Derive the 32-byte X25519 private key for the recovery scheme.
 * Caller is responsible for wiping the returned bytes after use.
 */
export async function deriveRecoveryX25519PrivateKey(mnemonic: string): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(mnemonic)
  // Take a view of the first 32 bytes of the 64-byte seed.
  const seedHalf = new Uint8Array(seed.buffer, seed.byteOffset, 32)
  return hkdf(sha256, seedHalf, RECOVERY_KEY_SALT_BYTES, X25519_INFO_BYTES, 32)
}

/**
 * Derive the 32-byte X25519 public key for the recovery scheme.
 * Computes the private key transiently and wipes it before returning.
 */
export async function deriveRecoveryX25519PublicKey(mnemonic: string): Promise<Uint8Array> {
  const privateKey = await deriveRecoveryX25519PrivateKey(mnemonic)
  try {
    return x25519PublicFromPrivate(privateKey)
  } finally {
    privateKey.fill(0)
  }
}
