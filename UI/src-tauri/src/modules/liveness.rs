use opencv::{
    core::{self, Mat, Rect, Scalar, Size, CV_32F},
    dnn,
    imgproc,
    prelude::*,
};

/// Contract of `resources/face_liveness.onnx`.
///
/// The bundled model is facenox/face-antispoof-onnx 98.20. It consumes a
/// 128x128 RGB image normalized to [0, 1] and returns two raw logits in the
/// order `[real, spoof]`.
pub const LIVENESS_INPUT_SIZE: i32 = 128;
pub const LIVENESS_FACE_EXPANSION: f32 = 1.5;

/// Five successful samples keep the check below a normal camera's perceptible
/// startup latency while making a single noisy frame unable to decide the
/// result. Up to seven frames may be read so momentary detector misses do not
/// reject a real user.
pub const TARGET_LIVENESS_SAMPLES: usize = 5;
pub const MIN_LIVENESS_SAMPLES: usize = 3;
pub const MAX_LIVENESS_CAPTURE_FRAMES: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq)]
struct CropGeometry {
    source: Rect,
    top: i32,
    bottom: i32,
    left: i32,
    right: i32,
    size: i32,
}

fn crop_geometry(
    frame_width: i32,
    frame_height: i32,
    face_x: f32,
    face_y: f32,
    face_width: f32,
    face_height: f32,
) -> Result<CropGeometry, String> {
    if frame_width <= 0 || frame_height <= 0 {
        return Err("活体检测收到空画面".to_string());
    }
    if ![face_x, face_y, face_width, face_height]
        .iter()
        .all(|v| v.is_finite())
        || face_width <= 0.0
        || face_height <= 0.0
    {
        return Err("活体检测收到无效人脸框".to_string());
    }

    let center_x = face_x + face_width / 2.0;
    let center_y = face_y + face_height / 2.0;
    let expanded_size = face_width.max(face_height) * LIVENESS_FACE_EXPANSION;
    // Match Python's `int()` truncation in the model's reference preprocessing.
    let size = expanded_size.max(1.0) as i32;
    let wanted_x = (center_x - expanded_size / 2.0) as i32;
    let wanted_y = (center_y - expanded_size / 2.0) as i32;
    let wanted_right = wanted_x.saturating_add(size);
    let wanted_bottom = wanted_y.saturating_add(size);

    let source_x = wanted_x.clamp(0, frame_width);
    let source_y = wanted_y.clamp(0, frame_height);
    let source_right = wanted_right.clamp(0, frame_width);
    let source_bottom = wanted_bottom.clamp(0, frame_height);
    let source_width = source_right - source_x;
    let source_height = source_bottom - source_y;
    if source_width <= 0 || source_height <= 0 {
        return Err("活体检测人脸框位于画面外".to_string());
    }

    Ok(CropGeometry {
        source: Rect::new(source_x, source_y, source_width, source_height),
        top: (source_y - wanted_y).max(0),
        bottom: (wanted_bottom - source_bottom).max(0),
        left: (source_x - wanted_x).max(0),
        right: (wanted_right - source_right).max(0),
        size,
    })
}

fn expanded_square_face(frame: &Mat, faces: &Mat) -> Result<Mat, String> {
    if faces.rows() <= 0 {
        return Err("活体检测未收到人脸".to_string());
    }

    let geometry = crop_geometry(
        frame.cols(),
        frame.rows(),
        *faces
            .at_2d::<f32>(0, 0)
            .map_err(|e| format!("读取人脸横坐标失败: {:?}", e))?,
        *faces
            .at_2d::<f32>(0, 1)
            .map_err(|e| format!("读取人脸纵坐标失败: {:?}", e))?,
        *faces
            .at_2d::<f32>(0, 2)
            .map_err(|e| format!("读取人脸宽度失败: {:?}", e))?,
        *faces
            .at_2d::<f32>(0, 3)
            .map_err(|e| format!("读取人脸高度失败: {:?}", e))?,
    )?;

    let source = frame
        .roi(geometry.source)
        .map_err(|e| format!("裁剪活体人脸失败: {:?}", e))?
        .try_clone()
        .map_err(|e| format!("复制活体人脸失败: {:?}", e))?;

    if geometry.top == 0
        && geometry.bottom == 0
        && geometry.left == 0
        && geometry.right == 0
    {
        return Ok(source);
    }

    let mut padded = Mat::default();
    core::copy_make_border(
        &source,
        &mut padded,
        geometry.top,
        geometry.bottom,
        geometry.left,
        geometry.right,
        core::BORDER_REFLECT_101,
        Scalar::default(),
    )
    .map_err(|e| format!("补齐活体人脸边缘失败: {:?}", e))?;

    if padded.cols() != geometry.size || padded.rows() != geometry.size {
        return Err(format!(
            "活体人脸裁剪尺寸异常: {}x{}，预期 {}x{}",
            padded.cols(),
            padded.rows(),
            geometry.size,
            geometry.size
        ));
    }
    Ok(padded)
}

/// Convert the model's `[real, spoof]` logits to a numerically stable real-face
/// probability. The ONNX graph deliberately does not contain a Softmax node.
pub fn real_probability_from_logits(real_logit: f32, spoof_logit: f32) -> Result<f32, String> {
    if !real_logit.is_finite() || !spoof_logit.is_finite() {
        return Err("活体模型返回了非有限数值".to_string());
    }
    let spoof_minus_real = (spoof_logit - real_logit).clamp(-80.0, 80.0);
    Ok(1.0 / (1.0 + spoof_minus_real.exp()))
}

/// Run one passive PAD sample using the exact preprocessing contract of the
/// bundled model. No blink, head turn, smile, or other user action is required.
pub fn score_face_liveness(
    net: &mut dnn::Net,
    frame: &Mat,
    faces: &Mat,
) -> Result<f32, String> {
    let face_crop = expanded_square_face(frame, faces)?;
    let interpolation = if face_crop.cols() < LIVENESS_INPUT_SIZE {
        imgproc::INTER_LANCZOS4
    } else {
        imgproc::INTER_AREA
    };
    let mut resized = Mat::default();
    imgproc::resize(
        &face_crop,
        &mut resized,
        Size::new(LIVENESS_INPUT_SIZE, LIVENESS_INPUT_SIZE),
        0.0,
        0.0,
        interpolation,
    )
    .map_err(|e| format!("缩放活体人脸失败: {:?}", e))?;

    let blob = dnn::blob_from_image(
        &resized,
        1.0 / 255.0,
        Size::new(LIVENESS_INPUT_SIZE, LIVENESS_INPUT_SIZE),
        Scalar::default(),
        true, // Camera frames are BGR; the model was trained on RGB.
        false,
        CV_32F,
    )
    .map_err(|e| format!("构建活体模型输入失败: {:?}", e))?;

    net.set_input(&blob, "", 1.0, Scalar::default())
        .map_err(|e| format!("设置活体模型输入失败: {:?}", e))?;
    let output = net
        .forward_single("")
        .map_err(|e| format!("活体模型推理失败: {:?}", e))?;
    let flat = output
        .reshape(1, 1)
        .map_err(|e| format!("整理活体模型输出失败: {:?}", e))?;
    if flat.cols() != 2 {
        return Err(format!(
            "活体模型输出契约不匹配: 得到 {} 个值，预期 2 个 [real, spoof] logits",
            flat.cols()
        ));
    }

    let real_logit = *flat
        .at_2d::<f32>(0, 0)
        .map_err(|e| format!("读取真人 logit 失败: {:?}", e))?;
    let spoof_logit = *flat
        .at_2d::<f32>(0, 1)
        .map_err(|e| format!("读取假体 logit 失败: {:?}", e))?;
    real_probability_from_logits(real_logit, spoof_logit)
}

/// Median fusion is robust to one or two transient exposure/focus outliers and
/// does not let a single high-confidence frame override the rest of the burst.
pub fn median_liveness_score(scores: &[f32]) -> Option<f32> {
    let mut finite: Vec<f32> = scores
        .iter()
        .copied()
        .filter(|score| score.is_finite())
        .collect();
    if finite.is_empty() {
        return None;
    }
    finite.sort_by(|a, b| a.total_cmp(b));
    let middle = finite.len() / 2;
    if finite.len() % 2 == 0 {
        Some((finite[middle - 1] + finite[middle]) / 2.0)
    } else {
        Some(finite[middle])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logits_are_interpreted_as_real_then_spoof() {
        let real = real_probability_from_logits(4.0, -1.0).unwrap();
        let spoof = real_probability_from_logits(-1.0, 4.0).unwrap();
        assert!(real > 0.99);
        assert!(spoof < 0.01);
    }

    #[test]
    fn equal_logits_map_to_half_probability() {
        assert_eq!(real_probability_from_logits(0.0, 0.0).unwrap(), 0.5);
    }

    #[test]
    fn probability_matches_reference_logit_threshold_conversion() {
        let configured_probability = 0.7_f32;
        let logit_difference =
            (configured_probability / (1.0 - configured_probability)).ln();
        let actual = real_probability_from_logits(logit_difference, 0.0).unwrap();
        assert!((actual - configured_probability).abs() < 1e-6);
    }

    #[test]
    fn non_finite_logits_are_rejected() {
        assert!(real_probability_from_logits(f32::NAN, 0.0).is_err());
        assert!(real_probability_from_logits(0.0, f32::INFINITY).is_err());
    }

    #[test]
    fn crop_is_square_and_expanded_around_face() {
        let geometry = crop_geometry(640, 480, 220.0, 140.0, 100.0, 120.0).unwrap();
        assert_eq!(geometry.size, 180);
        assert_eq!(geometry.source, Rect::new(180, 110, 180, 180));
        assert_eq!(
            (
                geometry.top,
                geometry.bottom,
                geometry.left,
                geometry.right
            ),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn crop_near_edge_uses_reflection_padding() {
        let geometry = crop_geometry(640, 480, 0.0, 0.0, 100.0, 100.0).unwrap();
        assert_eq!(geometry.size, 150);
        assert_eq!(geometry.source, Rect::new(0, 0, 125, 125));
        assert_eq!(
            (
                geometry.top,
                geometry.bottom,
                geometry.left,
                geometry.right
            ),
            (25, 0, 25, 0)
        );
    }

    #[test]
    fn crop_matches_reference_integer_truncation() {
        let geometry = crop_geometry(640, 480, 0.0, 0.0, 101.0, 99.0).unwrap();
        assert_eq!(geometry.size, 151);
        assert_eq!(geometry.source, Rect::new(0, 0, 126, 125));
        assert_eq!(
            (
                geometry.top,
                geometry.bottom,
                geometry.left,
                geometry.right
            ),
            (26, 0, 25, 0)
        );
    }

    #[test]
    fn crop_rejects_invalid_face_boxes() {
        assert!(crop_geometry(640, 480, 10.0, 10.0, 0.0, 100.0).is_err());
        assert!(crop_geometry(640, 480, f32::NAN, 10.0, 100.0, 100.0).is_err());
        assert!(crop_geometry(0, 480, 10.0, 10.0, 100.0, 100.0).is_err());
    }

    #[test]
    fn median_rejects_single_high_outlier() {
        let score = median_liveness_score(&[0.08, 0.12, 0.11, 0.09, 0.99]).unwrap();
        assert!((score - 0.11).abs() < f32::EPSILON);
    }

    #[test]
    fn median_even_sample_count_averages_middle_values() {
        let score = median_liveness_score(&[0.8, 0.2, 0.6, 0.4]).unwrap();
        assert!((score - 0.5).abs() < f32::EPSILON);
    }
}
