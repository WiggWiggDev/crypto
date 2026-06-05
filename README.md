# @wiggwigg/crypto

The cryptographic core of [WIGGWIGG](https://wiggwigg.ca), a privacy-first phone-number and
identity product. These are the key-derivation, encryption, sealing, and signing primitives
the WIGGWIGG clients use to protect your data on your device.

This repository is open so the cryptography can be reviewed independently of the rest of the
application, which is closed source. The
[security whitepaper](https://wiggwigg.ca/en/security/whitepaper/) describes how these
primitives fit together and where the guarantees end.

## What's here

- **Key derivation** (`kdf/`): Argon2id for password and PIN stretching, with PBKDF2-SHA256
  kept for reading data written under the older scheme. Both accept an injected native
  implementation and fall back to pure JS.
- **Symmetric encryption** (`encryption/`): AES-256-GCM over raw keys.
- **Public-key sealing** (`asymmetric/`): a libsodium-style sealed box (X25519 ECDH,
  HKDF-SHA256, then XChaCha20-Poly1305).
- **Authentication signing** (`auth-signing/`): Ed25519 challenge-response derived from the
  master key.
- **Recovery** (`recovery/`): an X25519 key derived from a BIP-39 mnemonic.
- **PIN unlock** (`pin-unlock/`): a master key wrapped under a PIN-derived AES key.
- **Scheme versions** (`versions.ts`, `params.ts`): the registry that lets a primitive
  rotate without breaking data written under an older version.

It is built on [`@noble`](https://github.com/paulmillr/noble-curves) and
[`@scure`](https://github.com/paulmillr/scure-bip39). We do not implement our own
primitives.

## Design

- **No platform crypto at the boundary.** The package never imports Web Crypto, Node
  `crypto`, or a native module directly. Where a primitive needs a native implementation for
  speed (Argon2id, PBKDF2), the host registers it at startup and the package routes through
  it, falling back to pure JS otherwise. The same source runs in browsers, Node, and React
  Native.
- **Domain-separated keys.** Every key derived from the master key uses a distinct HKDF
  `info` tag, so compromise of one derived key never yields another.
- **Versioned schemes.** Each on-disk format carries a version; readers dispatch on it and
  writers use the current version, so a primitive can rotate without a rewrite.

## Usage

```ts
import { seal, open, generateX25519Keypair } from '@wiggwigg/crypto/asymmetric'

const recipient = generateX25519Keypair()
const envelope = seal(recipient.publicKey, new TextEncoder().encode('hello'))
const plaintext = open(recipient.privateKey, recipient.publicKey, envelope)
```

Subpath exports mirror the directories: `@wiggwigg/crypto/kdf`, `/encryption`, `/asymmetric`,
`/auth-signing`, `/recovery`, `/pin-unlock`, `/versions`, plus the package root.

Publishing to npm is planned. For now, build from source:

```
npm install
npm run build
```

## Security review

This code is self-attested today and built on the established `@noble` and `@scure`
libraries rather than home-grown primitives. It has not had an independent third-party audit;
one is planned, and we will publish it when it is complete. Open source proves the design and
the client-side primitives; it does not by itself prove that any server runs them unmodified.
See the [whitepaper](https://wiggwigg.ca/en/security/whitepaper/) for the full scope.

To report a vulnerability, see [SECURITY.md](./SECURITY.md).

## About this repository

This is a read-only mirror, generated from the WIGGWIGG monorepo where the code is developed
and tested. Issues are welcome; code changes land upstream and sync here. See
[CONTRIBUTING.md](./CONTRIBUTING.md) for how to report a bug or raise a question, and the
[Code of Conduct](./CODE_OF_CONDUCT.md) for the ground rules.

## License

[MIT](./LICENSE)
