/**
 * PBKDF2-SHA256 with optional native-provider injection.
 *
 * Kept for reading data written under the legacy KDF version; new keys use
 * argon2id from ./argon2id.ts. As with Argon2id, a host can register a native
 * implementation so legacy unlocks stay fast.
 */

import { pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { sha256 } from '@noble/hashes/sha2.js'

export interface Pbkdf2Sha256Params {
  /** Iteration count; the master key uses 600k. */
  readonly iterations: number
  /** Output length in bytes; always 32 (256-bit). */
  readonly outputLen: number
}

export interface NativePbkdf2Provider {
  pbkdf2Sha256(
    password: Uint8Array,
    salt: Uint8Array,
    params: Pbkdf2Sha256Params,
  ): Promise<Uint8Array>
}

let nativeProvider: NativePbkdf2Provider | null = null

/**
 * Register a native PBKDF2-SHA256 implementation, typically at app startup, so
 * legacy unlocks stay fast.
 */
export function setNativePbkdf2Provider(p: NativePbkdf2Provider | null): void {
  nativeProvider = p
}

async function pbkdf2Sha256Js(
  password: Uint8Array,
  salt: Uint8Array,
  params: Pbkdf2Sha256Params,
): Promise<Uint8Array> {
  return pbkdf2Async(sha256, password, salt, {
    c: params.iterations,
    dkLen: params.outputLen,
    asyncTick: 250,
  })
}

/**
 * Derive a key with PBKDF2-HMAC-SHA256. Routes through the native provider if
 * registered, otherwise the pure-JS @noble fallback.
 */
export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  params: Pbkdf2Sha256Params,
): Promise<Uint8Array> {
  if (nativeProvider) return nativeProvider.pbkdf2Sha256(password, salt, params)
  return pbkdf2Sha256Js(password, salt, params)
}
