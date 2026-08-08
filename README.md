# Krypt04Mcg

[![Build and Release](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/release.yml/badge.svg)](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/release.yml) [![CodeQL](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/github-code-scanning/codeql) [![Generate Gradle Wrapper](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/generate-wrapper.yml/badge.svg)](https://github.com/jinnang233/Krypt04Mcg/actions/workflows/generate-wrapper.yml) 

Krypt04Mcg (Aka: Krypt04Msg) means "Crypto for message (MineCraft message)".

The project was renamed from ObscuraLink-MC/ObscuraLink because "Obscura" is already used by a Minecraft modding organization. Krypt04Mcg is the chosen name to avoid that naming conflict.

> [!WARNING]
> This codebase was **generated with AI assistance**. Review the implementation carefully, especially the cryptography, key storage, networking behavior, and dependency configuration, before using it in any real environment.
> 
> If possible, please run it in an **ISOLATED** environment, such as a virtual machine, to avoid potential security risks from build artifacts, such as the possibility that the maintainer’s computer has been infected with malware.
>
> If you discover any code security issues, or any copyright or licensing concerns, please report them in Issues. Thank you for your understanding.

> [!WARNING]
> Krypt04Mcg is **EXPERIMENTAL** software and has not undergone independent security auditing. The protocol, implementation, and cryptographic design **may contain vulnerabilities or design flaws**. Do not rely on this mod to protect highly sensitive, important, or production-critical data. If you require mature and battle-tested end-to-end encrypted communication, consider using established tools such as Signal or SimpleX instead.

## Disclaimer

Krypt04Mcg is an **EXPERIMENTAL** mod project. Its build environment, release artifacts, dependencies, and runtime behavior are provided as-is, with **NO GUARANTEE** that they are secure, trustworthy, virus-free, or suitable for any particular use. Before installing or running any downloaded artifact, **scan it with VirusTotal** or a comparable malware-scanning service whenever possible.

**Never use this project in production environments, and never use it to protect sensitive, important, private, regulated, or high-value data. This project is not expected to receive active long-term maintenance, security response, or compatibility updates.**

Krypt04Mcg is a Fabric client mod that transports post-quantum encrypted chat packets through ordinary Minecraft chat. It uses compact binary packets, Base64URL transport encoding, automatic fragmentation, TOFU public-key storage, and authenticated AEAD encryption.

## Features

- Client-side `/enc` command tree.
- Classic McEliece/CMCE KEM key pairs generated automatically.
- Falcon signing key pairs generated automatically.
- AES-256-GCM with random 96-bit nonce per message.
- HKDF-SHA256 derives AEAD keys from KEM shared secrets.
- Optional signature verification for signed packets.
- Public-key import/export with Trust On First Use checks.
- Automatic chat fragmentation and out-of-order reassembly.
- Timeout cleanup and bounded receive caches.
- Optional Cloth AutoConfig-backed configuration.

## Supported Versions

This implementation targets:

- Minecraft Java `26.2`
- Fabric Loader `0.19.2`
- Fabric API `0.152.2+26.2`
- Loom `1.16-SNAPSHOT`
- Java `25`

Compatibility Notes: Minecraft/Fabric 26.1+ uses Mojang's unobfuscated names and the non-remapping Fabric Loom plugin. Krypt04Mcg keeps its protocol and crypto layers independent from Minecraft APIs so future 26.x ports should mostly be limited to the client entrypoint, command, and chat-event adapters.

## Build

```bash
gradle build
```

If you prefer a wrapper, generate one with a local Gradle install:

```bash
gradle wrapper
./gradlew build
```

## Releases

GitHub Actions builds the mod and publishes release artifacts automatically when a tag matching `v*` is pushed:

```bash
git tag v0.9.3
git push origin v0.9.3
```

The release workflow can also be triggered manually from the Actions tab. Manual builds are published under generated `snapshot-YYYYMMDD-HHMMSS` tags.

Release artifacts include:

- the mod JAR from `build/libs`
- a detached `.jar.sign` signature for each release JAR
- `public_key.pem` for signature verification

To verify a downloaded release JAR:

```bash
openssl dgst -verify public_key.pem -signature krypt04mcg-0.8.7.jar.sign krypt04mcg-0.8.7.jar
```

## License

Krypt04Mcg is licensed under the BSD Zero Clause License (`0BSD`), a very permissive license with no attribution requirement.

## Run Client

```bash
gradle runClient
```

## Install

Build the project, then copy `build/libs/krypt04mcg-<version>.jar` into the client `mods` directory together with Fabric API. Cloth Config is optional and only needed for the ModMenu settings screen.

## Key Storage

Krypt04Mcg stores data under:

```text
config/krypt04mcg/
  keys/
    private/local.json
    public/*.json
  export/
  sessions/
  cache/
```

Private and public key material are stored separately. Public-key records include algorithm, owner, UUID, fingerprint, creation time, and Base64URL key data.
`/enc key export` writes your shareable public key JSON to `config/krypt04mcg/export/self-public.json`.

## Commands

```text
/enc tell <receiver> <message>
/enc stell <receiver> <message>
/enc exchange <receiver>
/enc etell <receiver> <message>
/enc gtell <group> <message>
/enc group create <name> <members>
/enc group list
/enc group delete <name>
/enc resend [messageId]
/enc session list
/enc session clear <player>
/enc session refresh <player>
/enc showalgs
/enc status <player>
/enc key list
/enc key fingerprint <player>
/enc key export
/enc key import <player> <data-or-file>
/enc key verify <player> <fingerprint>
/enc key confirm <player>
/enc key trust <player>
/enc key distrust <player>
```

Import flow:

1. The other player runs `/enc key export`.
2. They send you the exported JSON file through a trusted side channel and tell you the printed fingerprints.
3. You run `/enc key import <player> <file-or-json>`.
4. First import is trusted automatically. If a key changes later, Krypt04Mcg refuses to overwrite it silently.

## Protocol Format

Packets are compact binary and then Base64URL encoded for chat transport. The binary packet layout is:

```text
u8   protocolVersion
u8   packetType
u8   flags
u16  senderLength
bytes senderUtf8
u16  receiverLength
bytes receiverUtf8
i64  timestampMillis
16   messageId
i16  aadFragmentIndex
i16  aadFragmentTotal
u16  kemAlgorithmLength
bytes kemAlgorithmUtf8
u16  signatureAlgorithmLength
bytes signatureAlgorithmUtf8
u16  aeadAlgorithmLength
bytes aeadAlgorithmUtf8
u16  hkdfAlgorithmLength
bytes hkdfAlgorithmUtf8
u16  nonceLength
bytes nonce
i32  kemCiphertextLength
bytes kemCiphertext
i32  ciphertextLength
bytes ciphertext
i32  signatureLength
bytes signature
```

Packet types:

- `1`: KEM encrypted message.
- `2`: signed KEM encrypted message.
- `3`: session exchange.
- `4`: session message.

## Security Design

- AES/ECB is not used.
- AES-GCM is used with a fresh random nonce per encrypted message.
- `SecureRandom` generates message IDs, nonces, KEM randomness, and session material.
- KEM shared secrets are never used directly as AES keys.
- HKDF-SHA256 derives AEAD keys with the message ID as salt.
- AEAD AAD covers protocol version, packet type, flags, sender, receiver, message ID, packet-level fragment fields, and algorithm identifiers.
- Signatures cover AAD plus timestamp, nonce, KEM encapsulation, and ciphertext.
- Decryption rejects wrong receivers before attempting plaintext display.
- Decryption failures do not display garbage plaintext.
- Signature failures are displayed explicitly as invalid.

## Fragment Design

Each chat fragment has this form:

```text
[KRYPT04MCG] <messageIdHex> <index> <total> <payload>
```

The receiver supports out-of-order fragments, ignores duplicate fragments, cleans up timed-out partial messages, caps pending messages, and rejects excessive fragment counts.

## Optional Payload Channel

Krypt04Mcg remains a client-side mod. Servers do not need to install any plugin or mod for the default chat transport, and the optional payload channel is not used for mandatory login or configuration negotiation.

If a server plugin wants to relay fragments without normal chat, it can declare support for this play-stage custom payload channel:

```text
channel id: krypt04mcg:chat_fragment
direction C2S: client -> server
direction S2C: server -> client
payload fields:
  string receiver
  string fragment
  varint version
```

Client send mode `CUSTOM_PAYLOAD` only sends on this channel when Fabric reports the connected server can receive `krypt04mcg:chat_fragment`; otherwise the client simply skips payload sending and does not require server-side support.

## Session Design

`/enc exchange` creates and persists local session material, then sends the session data inside a signed encrypted KEM envelope. `/enc etell` currently uses the same signed KEM envelope while keeping the session API and storage in place. The protocol already reserves packet types for direct PSK session packets.

## GUI Chat

The encrypted chat panel can be opened with the configured Krypt04Mcg key binding. It lists imported players, recent peers, and configured groups. Group targets are shown with a `#` prefix and send through the existing group fan-out flow.

Recent plaintext conversation history is cached locally under:

```text
config/krypt04mcg/cache/conversations.json
```

The cache is bounded to the most recent 300 entries.
This can be disabled with the `enableConversationHistory` config option.

## Known Limitations

- This is a client-only chat transport. Server chat filtering, signing, rate limits, and antispam plugins may interfere with large encrypted payloads.
- Minecraft chat channels have a limited number of characters per message, so fragmentation is expected.
- Direct PSK-only session packets are reserved but not yet enabled as the default sending path.
- Public-key authenticity is TOFU-based; verify fingerprints out of band for stronger protection.

## Tests

Implemented test coverage:

- packet encode/decode
- encrypt/decrypt
- sign/verify
- fragment/reassemble
- timeout cleanup
- wrong receiver rejection
- modified ciphertext rejection
