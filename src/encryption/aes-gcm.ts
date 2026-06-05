/**
 * AES-256-GCM over raw `Uint8Array` keys.
 *
 * Uses @noble/ciphers rather than Web Crypto `CryptoKey`, so one code path runs
 * unchanged in browsers, Node, and React Native.
 *
 * Two output shapes are provided. `encrypt`/`decrypt` keep the 16-byte AEAD tag
 * appended to the ciphertext (@noble's native shape); `encryptSplit` and
 * `decryptSplit` expose the tag as its own field for callers that store
 * ciphertext, nonce, and tag separately. The nonce is a fresh 12-byte random IV.
 *
 * Public-key sealing uses XChaCha20-Poly1305 instead; see ../asymmetric/hybrid.ts.
 */

import { gcm } from '@noble/ciphers/aes.js'

const NONCE_LEN = 12
const TAG_LEN = 16

/**
 * Some older ciphertext was written with a 16-byte GCM IV rather than 12.
 * AES-GCM is spec-valid for non-96-bit IVs (NIST SP 800-38D derives J0 via
 * GHASH, and @noble/ciphers and OpenSSL agree byte-for-byte), so decrypt accepts
 * both lengths to read that data. Encrypt always emits 12.
 */
const COMMS_LEGACY_NONCE_LEN = 16
const ALLOWED_DECRYPT_NONCE_LENS: readonly number[] = [NONCE_LEN, COMMS_LEGACY_NONCE_LEN]

export interface AesGcmCiphertext {
  /** Ciphertext WITH the 16-byte AEAD tag appended. */
  readonly ciphertext: Uint8Array
  /** 12-byte nonce (IV). */
  readonly nonce: Uint8Array
}

export interface AesGcmCiphertextSplit {
  /** Ciphertext WITHOUT the AEAD tag. */
  readonly ciphertext: Uint8Array
  /** 12-byte nonce (IV). */
  readonly nonce: Uint8Array
  /** 16-byte AEAD tag. */
  readonly tag: Uint8Array
}

function assertKey(key: Uint8Array): void {
  if (key.length !== 32) {
    throw new Error(`aes-gcm: key must be 32 bytes (AES-256), got ${key.length}`)
  }
}

function randomNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(NONCE_LEN))
}

/**
 * Encrypt `plaintext` with AES-256-GCM. The returned ciphertext includes the
 * 16-byte AEAD tag concatenated at the end (standard GCM wire format).
 *
 * Generates a fresh 12-byte nonce per call. Reusing a `(key, nonce)` pair is a
 * catastrophic AES-GCM failure, so never pass a fixed nonce.
 */
export function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): AesGcmCiphertext {
  assertKey(key)
  const nonce = randomNonce()
  const cipher = gcm(key, nonce, aad)
  const ciphertext = cipher.encrypt(plaintext)
  return { ciphertext, nonce }
}

/**
 * Decrypt an AES-256-GCM ciphertext (with appended tag). Throws on AEAD tag
 * failure rather than returning junk bytes.
 */
export function decrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  assertKey(key)
  if (!ALLOWED_DECRYPT_NONCE_LENS.includes(nonce.length)) {
    throw new Error(
      `aes-gcm: nonce must be ${NONCE_LEN} or ${COMMS_LEGACY_NONCE_LEN} bytes, got ${nonce.length}`,
    )
  }
  const cipher = gcm(key, nonce, aad)
  return cipher.decrypt(ciphertext)
}

/**
 * Encrypt and return ciphertext, nonce, and tag as separate fields, for callers
 * that store the three distinctly.
 */
export function encryptSplit(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): AesGcmCiphertextSplit {
  const { ciphertext: combined, nonce } = encrypt(key, plaintext, aad)
  // @noble's GCM appends the tag to the ciphertext; split it back out for the
  // separate-field wire format.
  return {
    ciphertext: combined.slice(0, -TAG_LEN),
    nonce,
    tag: combined.slice(-TAG_LEN),
  }
}

/**
 * Decrypt the (ciphertext, nonce, tag) shape produced by `encryptSplit`,
 * re-concatenating the tag onto the ciphertext before passing it to the AEAD.
 */
export function decryptSplit(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  if (tag.length !== TAG_LEN) {
    throw new Error(`aes-gcm: tag must be ${TAG_LEN} bytes, got ${tag.length}`)
  }
  const combined = new Uint8Array(ciphertext.length + TAG_LEN)
  combined.set(ciphertext, 0)
  combined.set(tag, ciphertext.length)
  return decrypt(key, combined, nonce, aad)
}
