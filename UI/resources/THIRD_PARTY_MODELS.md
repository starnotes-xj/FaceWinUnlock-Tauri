# Third-Party Model Notice

## face_liveness.onnx

- Project: [facenox/face-antispoof-onnx](https://github.com/facenox/face-antispoof-onnx)
- Model: `models/best/98.20/best_model.onnx`
- Commit: `2b0a221fda633ac0aa0b0797b578580ecbbb4f81`
- SHA-256: `AF2381B88F38769222ED93379E12444E2A50814575DE1C46170DE570C55A42B6`
- Upstream license: Apache License 2.0

The model is redistributed without a claim that RGB presentation-attack
detection provides Windows Hello-equivalent biometric assurance.

## Login passive-liveness models

The Unlock service uses two independent models before releasing a credential.
They are intentionally separate from `face_liveness.onnx`, which is owned by
the UI enrollment consistency check.

### anti_spoof_mn3.onnx

- Project: [Open Model Zoo anti-spoof-mn3](https://github.com/openvinotoolkit/open_model_zoo)
- SHA-384: `6DE4534964B723397B3E8C995CADCF43BC007CC2F9930B95AE25F76ADCCECE5D1D4D058D0B15117B9E4A9F758424F92A`

### face_liveness_mini_fasnet_v2.onnx

- Project: [Silent-Face-Anti-Spoofing](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- Model: `2.7_80x80_MiniFASNetV2.onnx`
- SHA-384: `0E3EC9E62C09E3387B27E44D7C6122AC617A4F3ACF512EEB3B7D789757B5C251CCF5EE601384D58FF474CE3FC57A6B22`

The login service requires a live decision from both models over a short
multi-frame window. A model load or inference error fails closed and no
credential is released.

