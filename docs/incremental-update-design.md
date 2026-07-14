# Update System

This document describes the implemented update path. It is not a future design proposal.

## Release Metadata

`.github/workflows/release.yml` derives the version from the tag or manual input and synchronizes:

- `UI/src-tauri/tauri.conf.json`
- `UI/src-tauri/Cargo.toml`
- `UI/package.json` and lock metadata
- `PasskeyPlugin/Package.appxmanifest`

Tags containing `-rc`, `-beta`, or `-alpha` are published as pre-releases. Stable update checks use GitHub's latest stable release, so a release candidate does not replace the production update channel.

The workflow publishes the installer and standalone runtime assets, then writes `update_manifest.json` with version, path, SHA-256, size, and immutable tag URL.

## Client Check

`modules/update_check.rs`:

1. Reads the latest stable GitHub Release.
2. Compares semantic versions, including pre-release ordering.
3. Never prompts for a downgrade.
4. When versions are equal, reads the manifest and checks hashes so a missing/corrupted runtime file can still be repaired.

## Differential Download

`modules/update_download.rs`:

1. Downloads `releases/latest/download/update_manifest.json`.
2. Rejects absolute paths, traversal, unsupported URLs, and malformed hashes.
3. Computes SHA-256 for managed local files.
4. Returns only missing/changed files and total bytes.
5. Downloads to `<install dir>\update_temp`.
6. Revalidates downloaded size and hash before staging.

The updater accepts asset URLs only from this repository's immutable release-tag path.

## Apply

The UI asks before downloading and before restart. On application shutdown, staged files are copied into place. Locked files use the existing replacement/next-start path. The installer remains the fallback for changes that cannot be represented as managed-file replacement.

The differential manifest currently covers the files that can be safely replaced in the install root:

- Unlock service executable
- Passkey MSIX
- Passkey certificate

The Credential Provider DLL is deployed to System32 and requires `deploy_core_components`; it is therefore updated through the full installer. The NSIS setup executable is published as a release asset and is the full-update/download fallback, but it is not a differential replacement entry.

## Recovery And Safety

- Same-version hash checks repair antivirus-deleted or corrupted runtime files.
- The runtime healer remains a separate installed safeguard for critical local files.
- A failed download leaves the active installation unchanged.
- Pre-releases must not be exposed through the stable `latest` endpoint.
- Changing package identity, installer layout, registry migration, or Passkey data format requires a full installer path and explicit migration test.

## Tests

Unit tests cover semantic-version ordering, downgrade suppression, changed-file diffing, and path traversal rejection. Release CI must also verify every manifest asset exists and matches its recorded hash.

Manual update validation is included in [testing.md](testing.md).
