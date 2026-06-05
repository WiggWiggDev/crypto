/**
 * Argon2id parameter sets, one per use case.
 *
 * Every client imports these constants, so the same password derives the same
 * key on every platform. A set names a use case, not a security level: don't
 * reuse one elsewhere without checking that its latency and parallelism still
 * fit (a server-side check can afford more parallelism than a phone can).
 *
 * Output length is fixed at 32 bytes (256 bits) everywhere.
 */

export interface Argon2idParams {
  /** Memory cost in KiB (64 MiB = 65536). */
  readonly memKiB: number
  /** Time cost, in passes. */
  readonly iterations: number
  /** Lanes. Kept at 1 on clients so it doesn't oversubscribe phone cores. */
  readonly parallelism: number
  /** Output length in bytes; always 32. */
  readonly outputLen: 32
}

/** PIN unlock. The input is a 6-digit PIN, so memory-hardness carries the weight. */
export const ARGON2_PIN_PARAMS: Argon2idParams = {
  memKiB: 65_536, // 64 MiB
  iterations: 3,
  parallelism: 1,
  outputLen: 32,
}

/**
 * Master-password derivation: the heaviest budget a phone or browser can spend
 * in roughly a second, since this key unwraps the whole vault. Must be identical
 * on every platform or cross-device unlock breaks.
 */
export const ARGON2_MASTER_PARAMS: Argon2idParams = {
  memKiB: 131_072, // 128 MiB
  iterations: 3,
  parallelism: 1,
  outputLen: 32,
}

/**
 * Web session unlock key. Cheaper than the master set: it never leaves the tab
 * and is regenerated on every login.
 */
export const ARGON2_UNLOCK_KEY_PARAMS: Argon2idParams = {
  memKiB: 32_768, // 32 MiB
  iterations: 2,
  parallelism: 1,
  outputLen: 32,
}

/**
 * Vault-share password. Often user-chosen and weak, so memory-hardness is the
 * main defense. Runs in the browser, so memory stays modest for older devices.
 */
export const ARGON2_VAULT_SHARE_PARAMS: Argon2idParams = {
  memKiB: 65_536, // 64 MiB
  iterations: 3,
  parallelism: 1,
  outputLen: 32,
}

/**
 * Voicemail PIN, verified server-side where the cores are ours, so parallelism
 * can go higher.
 */
export const ARGON2_VOICEMAIL_PIN_PARAMS: Argon2idParams = {
  memKiB: 65_536, // 64 MiB
  iterations: 3,
  parallelism: 4,
  outputLen: 32,
}

/**
 * Maps a KDF version to its Argon2id parameter set. Version 1 (PBKDF2) is absent
 * on purpose: its parameters live in the legacy read path. A new version means a
 * new entry here plus a new current version in versions.ts.
 */
export const MASTER_KDF_PARAMS_BY_VERSION: Readonly<Record<2, Argon2idParams>> = {
  2: ARGON2_MASTER_PARAMS,
}

export const PIN_KDF_PARAMS_BY_VERSION: Readonly<Record<2, Argon2idParams>> = {
  2: ARGON2_PIN_PARAMS,
}
