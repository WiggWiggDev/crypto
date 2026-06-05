/**
 * X25519 scalar-multiplication primitives.
 *
 * Thin typed wrapper over `@noble/curves`'s X25519 so callers don't depend on
 * the curve library directly, and the implementation can be swapped without
 * touching call sites if the hybrid scheme ever rotates.
 */

import { x25519 } from '@noble/curves/ed25519.js'

export interface X25519Keypair {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
}

/**
 * Generate a fresh X25519 keypair using the platform CSPRNG.
 * Used for the per-seal ephemeral keypair inside `hybrid.seal`.
 */
export function generateX25519Keypair(): X25519Keypair {
  const privateKey = x25519.utils.randomSecretKey()
  const publicKey = x25519.getPublicKey(privateKey)
  return { privateKey, publicKey }
}

/**
 * Derive the X25519 public key corresponding to a given 32-byte secret.
 * Used when the private key comes from a deterministic source (e.g. HKDF
 * over a BIP39 seed in the recovery-key path).
 */
export function x25519PublicFromPrivate(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) {
    throw new Error(`X25519 private key must be 32 bytes, got ${privateKey.length}`)
  }
  return x25519.getPublicKey(privateKey)
}

/**
 * Compute the shared secret between a local private key and a remote public.
 * The raw ECDH output must always pass through a KDF before use; never use the
 * shared secret as a key directly.
 */
export function x25519Ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) {
    throw new Error(`X25519 private key must be 32 bytes, got ${privateKey.length}`)
  }
  if (publicKey.length !== 32) {
    throw new Error(`X25519 public key must be 32 bytes, got ${publicKey.length}`)
  }
  return x25519.getSharedSecret(privateKey, publicKey)
}
