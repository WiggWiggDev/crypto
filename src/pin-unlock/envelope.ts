/**
 * PIN-encrypted master-key envelope.
 *
 * Wraps the master key with an AES-256-GCM key derived from the user's PIN via
 * Argon2id. The blob is meant to sit in hardware-backed device storage, so both
 * the stretched PIN key and the hardware unwrap are needed to recover the master
 * key. It is Argon2id-only and carries no PBKDF2 read path; a consumer with older
 * PBKDF2 data should add a versioned variant rather than a hidden version field.
 */

import { decryptSplit, encryptSplit, type AesGcmCiphertextSplit } from '../encryption/aes-gcm.js'
import { argon2id } from '../kdf/argon2id.js'
import { ARGON2_PIN_PARAMS, type Argon2idParams } from '../params.js'

const SALT_LEN = 32
const HKDF_CONTEXT_PREFIX = 'pin-unlock'

/**
 * The serialized envelope as written to disk. Salt is included so a fresh
 * device can re-derive the same key from the same PIN.
 */
export interface PinEncryptedEnvelope {
  /** 32-byte random salt fed into Argon2id. */
  readonly salt: Uint8Array
  /** 12-byte AES-GCM nonce. */
  readonly nonce: Uint8Array
  /** 16-byte AES-GCM tag. */
  readonly tag: Uint8Array
  /** Encrypted master key (without the AEAD tag, which is in `tag`). */
  readonly ciphertext: Uint8Array
}

/**
 * Derive the PIN-stretched AES key. Exported so tests and future variants (for
 * example, changing the PIN without re-encrypting the master key) can compute it
 * without the seal/open flow.
 *
 * The salt is `random || ":pin-unlock:" || userId || ":v1"`. Binding the userId
 * into the KDF input stops an attacker who obtains one user's salt and blob from
 * feeding them into another user's PIN guesser.
 */
export async function derivePinUnlockKey(
  pin: string,
  salt: Uint8Array,
  userId: string,
  /** Test-only Argon2id override so unit tests can run a tiny-memory profile.
   *  App code must omit it and take the default. */
  params: Argon2idParams = ARGON2_PIN_PARAMS,
): Promise<Uint8Array> {
  const contextSuffix = new TextEncoder().encode(`:${HKDF_CONTEXT_PREFIX}:${userId}:v1`)
  const contextualSalt = new Uint8Array(salt.length + contextSuffix.length)
  contextualSalt.set(salt, 0)
  contextualSalt.set(contextSuffix, salt.length)
  const password = new TextEncoder().encode(pin)
  return argon2id(password, contextualSalt, params)
}

/**
 * Encrypt the user's master key under a PIN-derived AES key. Generates a
 * fresh random salt + nonce per call.
 */
export async function sealMasterKeyWithPin(
  masterKey: Uint8Array,
  pin: string,
  userId: string,
  /** Test-only Argon2id override. See `derivePinUnlockKey` for the rule. */
  params: Argon2idParams = ARGON2_PIN_PARAMS,
): Promise<PinEncryptedEnvelope> {
  if (masterKey.length !== 32) {
    throw new Error(`pin-unlock: master key must be 32 bytes, got ${masterKey.length}`)
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN))
  const aesKey = await derivePinUnlockKey(pin, salt, userId, params)
  try {
    const split: AesGcmCiphertextSplit = encryptSplit(aesKey, masterKey)
    return {
      salt,
      nonce: split.nonce,
      tag: split.tag,
      ciphertext: split.ciphertext,
    }
  } finally {
    aesKey.fill(0)
  }
}

/**
 * Decrypt a PIN-encrypted master key. Returns `null` on AEAD-tag failure (wrong
 * PIN, tampered blob, or corrupted state); the caller increments a wrong-PIN
 * counter and eventually wipes the envelope. Returning null rather than throwing
 * keeps the expected wrong-PIN case in normal control flow.
 */
export async function openMasterKeyWithPin(
  envelope: PinEncryptedEnvelope,
  pin: string,
  userId: string,
  /** Test-only Argon2id override. See `derivePinUnlockKey` for the rule. */
  params: Argon2idParams = ARGON2_PIN_PARAMS,
): Promise<Uint8Array | null> {
  const aesKey = await derivePinUnlockKey(pin, envelope.salt, userId, params)
  try {
    return decryptSplit(aesKey, envelope.ciphertext, envelope.nonce, envelope.tag)
  } catch {
    return null
  } finally {
    aesKey.fill(0)
  }
}
