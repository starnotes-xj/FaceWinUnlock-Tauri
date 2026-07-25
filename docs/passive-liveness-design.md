# Passive Liveness Design

## Scope

Passive presentation-attack detection (PAD) runs only during the enrollment
consistency check. It does not run in the lock-screen Unlock service. The check
is deliberately passive: the user is never asked to blink, turn, open their
mouth, or wait through a challenge.

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

## Alternatives Rejected

- Full-frame pixel motion cannot distinguish a live but still person from
  camera noise, exposure changes, or a moved photograph. It also created a
  lock-screen false-rejection path and was removed.
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
metadata with every result.
