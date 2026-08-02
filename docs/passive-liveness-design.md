# Passive Liveness Design

## Scope

Passive presentation-attack detection (PAD) runs in both places where FaceWinUnlock
can release or accept a face credential:

- the UI enrollment consistency check; and
- the Unlock service's single recognition loop used by Win+L, browser password
  verification, and the Passkey face-authorization pipe.

Both paths are deliberately passive: the user is never asked to blink, turn,
open their mouth, or complete an interactive challenge. A face match alone is
never sufficient to release credentials; a model error, incomplete window, or
spoof decision fails closed.

This is an RGB-camera convenience control. It reduces ordinary print and screen
replay risk, but it is not equivalent to Windows Hello and cannot guarantee
resistance to high-quality replay, virtual-camera injection, or 3D masks.

## Issue #30 Root Cause

The bundled `face_liveness.onnx` is the facenox 98.20 model, but the former
runtime treated it as a different MiniFASNet variant:

- the runtime sent `80x80`; the model input is `128x128`;
- the runtime subtracted `127.5`; the model expects RGB values divided by 255;
- the runtime read output index 1 as real; the model output is `[real, spoof]`;
- the runtime clamped a raw logit instead of applying Softmax.

The input-shape error was ignored by the multi-frame caller, leaving zero valid
votes and making consistency verification fail whenever liveness was enabled.

## Model Contract

| Item | Value |
|---|---|
| Upstream | `facenox/face-antispoof-onnx`, model 98.20 |
| Pinned commit | `2b0a221fda633ac0aa0b0797b578580ecbbb4f81` |
| Local file | `UI/resources/face_liveness.onnx` |
| SHA-256 | `AF2381B88F38769222ED93379E12444E2A50814575DE1C46170DE570C55A42B6` |
| Input | NCHW `1x3x128x128`, RGB, float32, range `[0,1]` |
| Output | two raw logits in order `[real, spoof]` |

The download script uses the immutable upstream commit and verifies the hash so
the binary cannot silently drift away from this preprocessing contract.

## Login Model Contract

The Unlock service keeps its login PAD models separate from the enrollment model
because the preprocessing contracts are different:

| File | Role | Contract |
|---|---|---|
| `anti_spoof_mn3.onnx` | primary login PAD | Open Model Zoo probability output |
| `face_liveness_mini_fasnet_v2.onnx` | secondary login PAD | MiniFASNetV2 two-score output |

The corresponding OpenVINO `.xml`/`.bin` files are packaged for the NPU path.
The service loads both models before recognition; it does not silently continue
with only one model.

## Runtime Pipeline

1. Detect the face with YuNet.
2. Expand its largest dimension by `1.5`, preserving a square crop.
3. Use reflection padding when the crop reaches a frame edge.
4. Resize to `128x128` with the reference interpolation (`INTER_AREA` when
   shrinking, `LANCZOS4` when enlarging), convert camera BGR to RGB, and divide
   by 255.
5. Convert `[real, spoof]` logits to real probability with a stable two-class
   Softmax.
6. Target five valid samples from no more than seven captured frames; require at
   least three.
7. Fuse successful samples with the median and compare the real probability to
   the configured threshold.

Median fusion prevents one focus or exposure outlier from deciding the result.
The small retry budget tolerates momentary detector loss without adding an
explicit user-visible wait.

## Login Runtime Pipeline

1. `Unlock` detects and recognizes the same face rectangle used for PAD.
2. Once an enrolled identity matches, the service collects six observations over
   at least 350 ms. The window is reset if the candidate identity changes.
3. Each frame is scored by both login models. At least four live votes, no spoof
   votes, and positive model margins are required.
4. `Live` is the only decision that reaches the credential or Passkey face gate.
   `Spoof`, `Inconclusive`, model load failure, and inference failure release
   nothing and are logged without frames, scores, passwords, or PINs.

This gate is shared by Win+L, Chrome password verification, and Passkey login;
the browser/WebAuthn classifier still decides whether the generic provider is
allowed to start, while PAD decides whether a matched face may authorize.

## Alternatives Rejected

- Full-frame pixel motion cannot distinguish a live but still person from
  camera noise, exposure changes, or a moved photograph. It is not used as the
  login authorization decision.
- Blink detection needs a reliable open-closed-open sequence and a much longer
  observation window. A five-frame window is unlikely to contain a natural
  blink, while accepting closed frames alone can accept a closed-eye photo.
- RGB rPPG usually needs several seconds of stable video and can survive
  high-quality video replay. That latency conflicts with a near-invisible
  consistency check.
- Active random challenges are stronger against replay but violate the
  no-complex-action product requirement.

## Release Gate

PAD quality must be measured on target cameras, lighting, and attack media.
Do not tune the default threshold from a few hand-picked examples. Record live
false rejects and attack accepts separately and retain camera/OS/backend
metadata with every result. The release candidate must repeat the attack matrix
through Win+L, Chrome password verification, and Passkey login, and confirm the
log contains `face and passive liveness matched` only after a live subject passes
the full window.
