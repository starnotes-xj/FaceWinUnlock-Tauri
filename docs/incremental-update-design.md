# Update System

This document describes the implemented update path. It is not a future design proposal.

## Release Metadata

`.github/workflows/release.yml` derives the version from the tag or manual input and synchronizes:

- `UI/src-tauri/tauri.conf.json`
- `UI/src-tauri/Cargo.toml`
- `UI/package.json` and lock metadata
- `PasskeyPlugin/Package.appxmanifest`

Tags containing `-rc`, `-beta`, or `-alpha` are published as pre-releases. Stable update checks use GitHub's latest stable release, so a release candidate does not replace the production update channel.

After building every release asset, the workflow writes `update_manifest.json` with version, path, SHA-256, size, and immutable tag URL. It signs the exact UTF-8 bytes as `update_manifest.json.sig` with Minisign. It also creates `SHA256SUMS` for every uploaded release payload and signs that file as `SHA256SUMS.sig`.

`SHA256SUMS` covers the Credential Provider DLL, Unlock and Launcher executables, Passkey MSIX and certificate, the NSIS installer(s), `update_manifest.json`, and `update_manifest.json.sig`. It excludes `SHA256SUMS` and `SHA256SUMS.sig` to avoid a signature/checksum cycle. The detached signature authenticates the checksum list; SHA-256 detects byte changes in the listed files.

The updater public key is checked into `UI/src-tauri/release-signing-public-keys.txt` and compiled into the Tauri client. It accepts one or more comma- or whitespace-separated Minisign Ed25519 public keys to allow a planned key transition. The private key is a separate GitHub Secret from `TAURI_SIGNING_PRIVATE_KEY`. The release workflow fails before publishing if the public key is unconfigured, either signing Secret is missing, signing fails, or the generated signatures do not verify against the embedded keyring.

## Client Check

`modules/update_check.rs`:

1. Reads the latest stable GitHub Release.
2. Compares semantic versions, including pre-release ordering.
3. Never prompts for a downgrade.
4. When versions are equal, reads the manifest and checks hashes so a missing/corrupted runtime file can still be repaired.

## Differential Download

`modules/update_download.rs`:

1. Downloads `update_manifest.json.sig` and the raw `update_manifest.json` bytes from the stable latest Release endpoint.
2. Verifies the Minisign signature against the compiled public-key ring. A missing signature, malformed signature, unknown key, missing keyring, or invalid signature stops the update before JSON parsing.
3. Parses the authenticated manifest and rejects absolute paths, traversal, unsupported URLs, duplicate entries, malformed hashes, and unreasonable sizes.
4. Computes SHA-256 for managed local files and returns only missing/changed files and total bytes.
5. Downloads changed files to `<install dir>\update_temp`, retaining the signed manifest and signature in a metadata subdirectory.
6. Revalidates each downloaded file's exact size and SHA-256. A failed download or hash check removes the incomplete staging directory.

The updater accepts asset URLs only from this repository's immutable release-tag path.

## Apply

The UI asks before downloading and before restart. On application shutdown, the code verifies the staged manifest signature again, checks the staging list against that signed manifest, and rechecks every staged file's size and SHA-256 before stopping the service or copying any component. Only then are staged files copied into place. Locked files use the existing replacement/next-start path. The installer remains the fallback for changes that cannot be represented as managed-file replacement.

The differential manifest currently covers the files that can be safely replaced in the install root:

- Unlock service executable
- Launcher executable
- Passkey MSIX
- Passkey certificate

The Credential Provider DLL is deployed to System32 and requires `deploy_core_components`; it is therefore updated through the full installer. The NSIS setup executable is published as a release asset and is the full-update/download fallback, but it is not a differential replacement entry.

## Recovery And Safety

- Same-version hash checks repair antivirus-deleted or corrupted runtime files.
- The runtime healer remains a separate installed safeguard for critical local files.
- A failed download leaves the active installation unchanged.
- Signature or staged-file verification failures never enter the component-replacement path.
- Pre-releases must not be exposed through the stable `latest` endpoint.
- Changing package identity, installer layout, registry migration, or Passkey data format requires a full installer path and explicit migration test.

## Client migration

The new signature check only protects clients built with this validation code. Older installed clients do not verify `update_manifest.json.sig` and continue to have their prior hash-only behavior; adding signatures to a release cannot protect those clients retroactively. The differential path does not replace the UI executable, so moving an installed client to this trust model requires installing a full installer built with the pinned public key. See [release-signing.md](release-signing.md) for the publisher and Windows verification steps, key setup, and rotation process.

## Tests

Unit tests cover semantic-version ordering, downgrade suppression, changed-file diffing, and path traversal rejection. Release CI must also verify every manifest asset exists and matches its recorded hash.

Manual update validation is included in [testing.md](testing.md).
