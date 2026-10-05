# Release Signing Operations

## Scheme and coverage

The workflow uses the Minisign Ed25519 file-signing format already used by the Tauri updater tooling. The application verifies with `minisign-verify`; CI creates detached `.sig` files with the locked Tauri CLI. This reuses a mature, interoperable signature format without replacing the existing differential-update flow or defining a new cryptographic format.

`update_manifest.json.sig` signs the exact bytes of `update_manifest.json`. The client verifies this signature before JSON parsing, then retains its existing URL, path, size, and per-file SHA-256 checks. At shutdown, the client verifies the staged manifest signature and all staged file hashes again before stopping the service or replacing a component.

`SHA256SUMS` lists every binary asset uploaded by `.github/workflows/release.yml`: the Credential Provider DLL, Unlock executable, Launcher executable, Passkey MSIX and certificate, every NSIS installer, `update_manifest.json`, and `update_manifest.json.sig`. `SHA256SUMS.sig` signs the exact checksum-list bytes. The list excludes itself and its signature to avoid a cycle. GitHub-generated source archive links are not workflow-uploaded binary assets and are outside this list.

These checks have distinct jobs:

- SHA-256 detects changed file bytes when the expected digest is trusted.
- Minisign authenticates the manifest and checksum list under the publisher's private key. The public key must reach users through a trusted channel.
- Authenticode is Windows code signing backed by a certificate trust chain and provides Windows publisher identity/UI integration. This work does not buy a certificate, sign installers with Authenticode, or change Windows certificate trust.

## Configure the first signing key

`UI/src-tauri/release-signing-public-keys.txt` contains the public key used by CI. Its matching passphrase-protected private key is stored locally at `%USERPROFILE%\.tauri\facewinunlock-release.key` and configured as a repository Actions Secret alongside its passphrase. The private key is not committed. The workflow requires both Secrets and fails closed if either is absent or the key does not match the embedded public key. No formal Release has been run with this signer in this task.

1. For CI releases, use a trusted maintainer environment and choose a fresh key path outside the repository. Check that both the private-key path and any corresponding public-key path do not already exist. Do not use `--force` or overwrite an existing key.

   ```powershell
   Set-Location UI
   npm ci
   $keyPath = Join-Path $env:USERPROFILE '.tauri\facewinunlock-release-ci.key'
   if ((Test-Path -LiteralPath $keyPath) -or (Test-Path -LiteralPath "$keyPath.pub")) { throw 'Choose a new, unused key path' }
   npm run tauri -- signer generate --write-keys $keyPath
   ```

   Set a strong passphrase when prompted. The Tauri signer uses Minisign-compatible keys; its CLI documentation describes the key format and signing command: [Tauri updater signing](https://v2.tauri.app/plugin/updater/) and [Tauri CLI signer](https://v2.tauri.app/reference/cli/).

2. The Tauri CLI `.pub` output is itself base64-wrapped text. Decode that wrapper and copy only the inner Minisign Ed25519 key line (the line beginning with `RW`) to `UI/src-tauri/release-signing-public-keys.txt`, one key per line. Commit that public key so it is reviewable and embedded in subsequent clients. For a keyring, list each trusted base64 key on a separate line.

   ```powershell
   $tauriPublicKey = (Get-Content -Raw "$keyPath.pub").Trim()
   $minisignPublicText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($tauriPublicKey))
   $publicKey = $minisignPublicText -split '\r?\n' |
       Where-Object { $_ -match '^RW[A-Za-z0-9+/]+=*$' } |
       Select-Object -Last 1
   if (-not $publicKey) { throw 'Could not extract the Minisign public key' }
   $publicKey | Set-Content -NoNewline src-tauri/release-signing-public-keys.txt
   ```

3. The currently pinned public key is also the CI signing key. Its Minisign key ID is `6492f0a830f2d333`. The repository Actions Secret `UPDATE_RELEASE_SIGNING_PRIVATE_KEY` contains the private key file's literal text, not its path, and `UPDATE_RELEASE_SIGNING_PRIVATE_KEY_PASSWORD` contains its non-empty passphrase. The existing `TAURI_SIGNING_PRIVATE_KEY` is a separate setting and is not reused: the current `tauri.conf.json` does not enable Tauri updater artifacts or define its updater public key, so that setting alone does not sign this custom manifest path.

4. Record the public-key fingerprint/Minisign key ID in the maintainer's release records and verify it against the checked-in key before release. For the Minisign Ed25519 base64 value, the 8-byte key ID follows the two-byte `Ed` algorithm marker:

   ```powershell
   $publicKey = '<base64 public key>'
   $decoded = [Convert]::FromBase64String($publicKey)
   if ($decoded.Length -ne 42 -or [Text.Encoding]::ASCII.GetString($decoded, 0, 2) -ne 'Ed') {
       throw 'Not a Minisign Ed25519 public key'
   }
   [BitConverter]::ToUInt64($decoded, 2).ToString('x16')
   ```

   The current CI signing key's Minisign key ID is `6492f0a830f2d333`. Record the CI key ID and verify it against the checked-in public key before release. CI signs temporary release metadata and runs the client's verifier against the embedded keyring; a mismatched private key blocks release creation.

The workflow checks for a configured Ed25519 public key and both Secrets before building. Tauri's signer returns a base64-wrapped Minisign signature; the workflow decodes that wrapper to the standard Minisign detached-signature text before publishing `.sig` files. It generates all final assets, signs the raw manifest, writes and signs `SHA256SUMS`, verifies both signatures against the compiled keyring, and only then calls the GitHub Release action. Missing Secrets, signer errors, or a public/private key mismatch fail the job before the Release action.

## Windows user verification

Download `SHA256SUMS`, `SHA256SUMS.sig`, `update_manifest.json`, `update_manifest.json.sig`, and the intended assets from the same release. Obtain Minisign from its [official project](https://github.com/jedisct1/minisign), and obtain the public key from the repository's versioned `UI/src-tauri/release-signing-public-keys.txt`. Run the PowerShell verification example in [testing.md](testing.md) before launching the installer.

Verify the signature before trusting the checksum list. A hash by itself does not establish who supplied the file. The Minisign signature authenticates the exact list and manifest; the hashes then confirm the downloaded bytes match that list. A valid release signature does not provide Authenticode's Windows certificate publisher identity.

## Legacy client migration

Clients released before manifest-signature verification do not check `.sig` files and retain their previous hash-only update behavior. Publishing a signed manifest does not retroactively protect those installations. Also, the differential updater does not replace the Tauri UI executable that contains the new trusted key. Existing users must download and verify a full installer, then install a build containing the pinned keyring. Installed-program acceptance remains a separate Windows test.

## Key custody and planned rotation

- Keep the encrypted private key and passphrase in separate, access-controlled stores. Restrict repository Actions Secret access to release maintainers and keep an encrypted offline backup. Never commit the private key, print it in logs, or use the signing Secret as a general build credential.
- Do not overwrite keys. Preserve the old key while a rotation is in progress; the public key may remain in source and historical releases.
- To rotate, generate a new key at a fresh path and add both old and new public keys to the checked-in keyring. Keep the old private key as the active Secret while publishing a transition build; verify its signed `SHA256SUMS` with the old key and have users install the full transition installer so their client embeds both keys. The differential updater cannot update that UI/keyring itself.
- After the transition build is available, switch the private-key Secrets to the new key and passphrase while retaining both public keys. New and transitioned clients accept the new signer. After the supported population has moved, remove the old key from the keyring in a later reviewed client build. Clients that skipped the transition cannot accept a new-key manifest and need a manually installed transition/full installer.
- If a private key is suspected compromised, stop releases, remove it from Actions Secrets, publish a reviewed client/key transition and communicate the required full-installer migration. A client that trusts only the compromised key cannot be made to trust a replacement key by signing with that replacement alone.
