/**
 * Argon2id with optional native-provider injection.
 *
 * Argon2id is expensive in pure JS (seconds on a low-end phone), so a host can
 * register a native implementation at startup and the package routes through it.
 * With no provider registered it falls back to the @noble/hashes pure-JS path.
 * The native implementation is injected at runtime, so no platform-specific code
 * is imported here and the package stays portable.
 */

import { argon2idAsync } from '@noble/hashes/argon2.js'

import type { Argon2idParams } from '../params.js'

export interface NativeArgon2idProvider {
  argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2idParams): Promise<Uint8Array>
}

let nativeProvider: NativeArgon2idProvider | null = null

/**
 * Register a native Argon2id implementation, typically once at app startup. Pass
 * `null` to unregister, which is useful in tests that exercise the JS fallback.
 */
export function setNativeArgon2idProvider(p: NativeArgon2idProvider | null): void {
  nativeProvider = p
}

/**
 * Pure-JS Argon2id via @noble/hashes, used when no native provider is
 * registered. Yields to the event loop every 250 ms so the UI thread stays
 * responsive.
 */
async function argon2idJs(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2idParams,
): Promise<Uint8Array> {
  return argon2idAsync(password, salt, {
    m: params.memKiB,
    t: params.iterations,
    p: params.parallelism,
    dkLen: params.outputLen,
    asyncTick: 250,
  })
}

/**
 * Derive a 32-byte key from `password` + `salt` using Argon2id with the
 * given `params`. Routes through the native provider if registered, else
 * falls back to pure JS.
 */
export async function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2idParams,
): Promise<Uint8Array> {
  if (nativeProvider) return nativeProvider.argon2id(password, salt, params)
  return argon2idJs(password, salt, params)
}
