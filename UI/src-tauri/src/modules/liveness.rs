use opencv::{
    core::{self, Mat, Point, Scalar, Size, Vector, CV_32F},
    dnn,
    imgproc,
    prelude::*,
};

// ─── MotionDetector ──────────────────────────────────────────────────────────

/// 基于帧间运动量的被动活体检测：检测人脸是否为静态照片。
///
/// 通过连续帧的灰度差均值量化运动量，完全静止说明可能是照片翻拍。
pub struct MotionDetector {
    prev_gray: Option<Mat>,
    /// 最近 15 帧的运动量环形缓冲
    motion_history: Vec<f32>,
}

impl MotionDetector {
    pub fn new() -> Self {
        Self {
            prev_gray: None,
            motion_history: Vec::with_capacity(15),
        }
    }

    /// 输入新帧，返回当前运动量（0.0 = 完全静止，越大运动越剧烈）。
    pub fn update(&mut self, frame: &Mat) -> Result<f32, String> {
        let mut gray = Mat::default();
        imgproc::cvt_color(frame, &mut gray, imgproc::COLOR_BGR2GRAY, 0, opencv::core::AlgorithmHint::ALGO_HINT_DEFAULT)
            .map_err(|e| format!("灰度转换失败: {:?}", e))?;

        let motion = if let Some(ref prev) = self.prev_gray {
            let mut diff = Mat::default();
            opencv::core::absdiff(prev, &gray, &mut diff)
                .map_err(|e| format!("帧差计算失败: {:?}", e))?;
            let mean_val = opencv::core::mean(&diff, &Mat::default())
                .map_err(|e| format!("均值计算失败: {:?}", e))?;
            // 灰度图仅第 0 通道有值
            mean_val[0] as f32
        } else {
            0.0
        };

        if self.motion_history.len() >= 15 {
            self.motion_history.remove(0);
        }
        self.motion_history.push(motion);
        self.prev_gray = Some(gray);

        Ok(motion)
    }

    /// 判断是否为静态照片（连续 10+ 帧运动量 < 0.02）。
    pub fn is_likely_photo(&self) -> bool {
        if self.motion_history.len() < 10 {
            return false;
        }
        self.motion_history.iter().rev().take(10).all(|&v| v < 0.02)
    }
}

// ─── EAR (Eye Aspect Ratio) ─────────────────────────────────────────────────

/// 计算单眼 Eye Aspect Ratio（EAR），用于眨眼检测。
///
/// `eye_pts` 是 6 个关键点的 (x,y) 坐标平铺：12 个 float。
/// 68 点模型中左眼为索引 36-41，右眼为 42-47。
/// 对应关系（0-based 数组）：
///   index 0 → landmark 36/42（外眼角）
///   index 1 → landmark 37/43
///   index 2 → landmark 38/44
///   index 3 → landmark 39/45（内眼角）
///   index 4 → landmark 40/46
///   index 5 → landmark 41/47
///
/// EAR = (|p1-p5| + |p2-p4|) / (2 * |p0-p3|)
pub fn compute_ear(eye_pts: &[f32]) -> f32 {
    debug_assert!(
        eye_pts.len() >= 12,
        "EAR requires 6 landmark points (12 floats)"
    );
    // p1 (floats 2,3) ↔ p5 (floats 10,11)
    let vert1 = ((eye_pts[2] - eye_pts[10]).powi(2) + (eye_pts[3] - eye_pts[11]).powi(2)).sqrt();
    // p2 (floats 4,5) ↔ p4 (floats 8,9)
    let vert2 = ((eye_pts[4] - eye_pts[8]).powi(2) + (eye_pts[5] - eye_pts[9]).powi(2)).sqrt();
    // p0 (floats 0,1) ↔ p3 (floats 6,7)
    let horiz = ((eye_pts[0] - eye_pts[6]).powi(2) + (eye_pts[1] - eye_pts[7]).powi(2)).sqrt();

    if horiz < 1e-6 {
        return 0.0;
    }
    (vert1 + vert2) / (2.0 * horiz)
}

// ─── BlinkDetector ──────────────────────────────────────────────────────────

/// 基于眼纵横比（EAR）的眨眼检测活体。
///
/// 连续 3+ 帧左右眼平均 EAR < 0.2 判定为一次眨眼。
/// 超过 150 帧仍未检测到眨眼则认为超时。
pub struct BlinkDetector {
    below_threshold_counter: u32,
    pub blink_detected: bool,
    frame_count: u32,
}

impl BlinkDetector {
    pub fn new() -> Self {
        Self {
            below_threshold_counter: 0,
            blink_detected: false,
            frame_count: 0,
        }
    }

    /// 输入 68 个面部关键点（136 floats），返回检测状态：
    /// - `Some(true)` — 首次检测到眨眼
    /// - `None` — 仍在观察中
    /// - `Some(false)` — 超时未眨眼
    pub fn update(&mut self, landmarks_68: &[f32]) -> Result<Option<bool>, String> {
        if landmarks_68.len() < 136 {
            return Err(format!(
                "需要 68 个关键点 (136 floats)，实际收到 {}",
                landmarks_68.len()
            ));
        }

        // 左眼索引 36-41 → float 偏移 72-84
        let left_eye = &landmarks_68[72..84];
        // 右眼索引 42-47 → float 偏移 84-96
        let right_eye = &landmarks_68[84..96];

        let left_ear = compute_ear(left_eye);
        let right_ear = compute_ear(right_eye);
        let avg_ear = (left_ear + right_ear) / 2.0;

        self.frame_count += 1;

        // 一旦检测到眨眼，后续不再触发
        if self.blink_detected {
            return Ok(None);
        }

        if avg_ear < 0.2 {
            self.below_threshold_counter += 1;
            if self.below_threshold_counter >= 3 {
                self.blink_detected = true;
                return Ok(Some(true));
            }
        } else {
            self.below_threshold_counter = 0;
        }

        // 默认超时 150 帧（约 5 秒 @30fps）
        const TIMEOUT_FRAMES: u32 = 150;
        if self.frame_count >= TIMEOUT_FRAMES {
            return Ok(Some(false));
        }

        Ok(None)
    }
}

// ─── PIPNet Landmark Extraction ────────────────────────────────────────────────

/// 使用 PIPNet ONNX 模型从人脸裁剪图中提取 68 个面部关键点。
///
/// 返回 136 个 f32（68 个 (x,y) 坐标对，原点为人脸裁剪图的左上角）。
/// 若模型缺失或推理失败则返回 `None`，调用方应优雅回退。
pub fn extract_landmarks_pipnet(
    net: &dnn::Net,
    face_crop: &Mat,
) -> Option<Vec<f32>> {
    // PIPNet 期望 256x256 RGB 输入，归一化至 [0,1]
    let input_size = Size::new(256, 256);
    let blob = dnn::blob_from_image(
        face_crop,
        1.0 / 255.0,
        input_size,
        Scalar::new(0.0, 0.0, 0.0, 0.0),
        true,  // swapRB: BGR → RGB
        false,
        CV_32F,
    )
    .ok()?;

    // 获取所有输出层名称并执行前向推理
    let out_names = net.get_unconnected_out_layers_names().ok()?;
    if out_names.is_empty() {
        return None;
    }

    let mut outputs = Vector::<Mat>::new();
    net.forward(&mut outputs, &out_names).ok()?;

    // PIPNet 输出：cls_map, offset_x, offset_y, nb_x, nb_y
    // 测试版简化处理：仅使用 cls_map 热力图的 argmax 位置
    if outputs.len() < 1 {
        return None;
    }

    let cls_map = &outputs[0]; // 形状 (1, 68, 64, 64)
    let sizes = cls_map.size().ok()?;
    let num_landmarks = sizes[1] as i32; // 通常 68
    let feature_size = sizes[2] as i32; // 通常 64
    let stride = 256.0 / feature_size as f32;

    // 将 cls_map 展平为 (num_landmarks, feature_size*feature_size) 便于逐行 argmax
    let cls_2d = cls_map.reshape(1, num_landmarks).ok()?;

    let total = cls_2d.rows();
    let mut landmarks: Vec<f32> = Vec::with_capacity((total as usize) * 2);

    for c in 0..total {
        let row = cls_2d.row(c).ok()?;
        let mut min_val: f64 = 0.0;
        let mut max_val: f64 = 0.0;
        let mut min_loc = Point::default();
        let mut max_loc = Point::default();
        if core::min_max_loc(
            &row,
            Some(&mut min_val),
            Some(&mut max_val),
            Some(&mut min_loc),
            Some(&mut max_loc),
            &Mat::default(),
        )
        .is_err()
        {
            // 该通道处理失败，填入零
            landmarks.push(0.0);
            landmarks.push(0.0);
            continue;
        }

        // max_loc.x 是展平索引 (0 .. feature_size*feature_size)
        let idx = max_loc.x;
        let gy = (idx / feature_size) as f32;
        let gx = (idx % feature_size) as f32;
        landmarks.push(gx * stride);
        landmarks.push(gy * stride);
    }

    // 同时提取偏移量做亚像素精修（若可用）
    if outputs.len() >= 3 {
        let off_x = &outputs[1];
        let off_y = &outputs[2];
        let off_x_2d = off_x.reshape(1, num_landmarks).ok();
        let off_y_2d = off_y.reshape(1, num_landmarks).ok();
        if let (Some(ox), Some(oy)) = (off_x_2d, off_y_2d) {
            for c in 0..total {
                let row_x = ox.row(c).ok();
                let row_y = oy.row(c).ok();
                if let (Some(rx), Some(ry)) = (row_x, row_y) {
                    let idx = (c as f32 * feature_size as f32 * feature_size as f32
                        + landmarks[(c as usize) * 2 + 1] / stride * feature_size as f32
                        + landmarks[(c as usize) * 2] / stride) as i32;
                    if idx >= 0 && idx < rx.cols() {
                        let dx = rx.at::<f32>(idx).map(|v| *v).unwrap_or(0.0);
                        let dy = ry.at::<f32>(idx).map(|v| *v).unwrap_or(0.0);
                        landmarks[(c as usize) * 2] += dx * stride;
                        landmarks[(c as usize) * 2 + 1] += dy * stride;
                    }
                }
            }
        }
    }

    Some(landmarks)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use opencv::core::Scalar;

    // ── EAR ──────────────────────────────────────────────────────────────────

    #[test]
    fn ear_open_eye_above_threshold() {
        // 模拟睁眼：近似水平椭圆
        let eye: [f32; 12] = [
            0.0, 0.0, // p0 外眼角
            -0.8, 1.5, // p1
            -0.5, 3.0, // p2
            0.0, 5.0, // p3 内眼角
            0.5, 3.0, // p4
            0.8, 1.5, // p5
        ];
        let ear = compute_ear(&eye);
        // vert1 = |p1-p5| = 1.6,  vert2 = |p2-p4| = 1.0,  horiz = |p0-p3| = 5.0
        // EAR = (1.6 + 1.0) / (2 * 5.0) = 0.26
        assert!(
            (ear - 0.26).abs() < 0.01,
            "睁眼 EAR 应约 0.26，实际 {}",
            ear
        );
        assert!(ear > 0.2, "睁眼 EAR 应高于阈值 0.2");
    }

    #[test]
    fn ear_closed_eye_below_threshold() {
        // 模拟闭眼：所有点几乎在一条水平线上
        let eye: [f32; 12] = [
            0.0, 0.0, // p0
            -0.8, 0.1, // p1
            -0.5, 0.2, // p2
            0.0, 0.0, // p3
            0.5, 0.2, // p4
            0.8, 0.1, // p5
        ];
        let ear = compute_ear(&eye);
        // vertical 与 horizontal 都接近 0 时保护返回 0.0
        assert!(ear < 0.2, "闭眼 EAR 应低于阈值 0.2，实际 {}", ear);
    }

    #[test]
    fn ear_degenerate_horiz_zero_returns_zero() {
        // 水平距离为零时应返回 0.0 而非除零崩溃
        let eye: [f32; 12] = [
            5.0, 5.0, // p0
            5.0, 6.0, // p1
            5.0, 7.0, // p2
            5.0, 5.0, // p3 (= p0)
            5.0, 7.0, // p4 (= p2)
            5.0, 6.0, // p5 (= p1)
        ];
        let ear = compute_ear(&eye);
        assert_eq!(ear, 0.0, "水平距离为 0 时应返回 0.0");
    }

    // ── MotionDetector ──────────────────────────────────────────────────────

    #[test]
    fn motion_detector_initial_state() {
        let md = MotionDetector::new();
        assert!(!md.is_likely_photo());
        assert!(md.motion_history.is_empty());
        assert!(md.prev_gray.is_none());
    }

    #[test]
    fn motion_detector_first_frame_returns_zero() {
        let frame =
            Mat::new_rows_cols_with_default(50, 50, opencv::core::CV_8UC3, Scalar::all(128.0))
                .unwrap();
        let mut md = MotionDetector::new();
        let motion = md.update(&frame).unwrap();
        assert_eq!(motion, 0.0, "首帧 prev_gray 为 None 应返回 0.0");
    }

    #[test]
    fn motion_detector_identical_frames_detected_as_photo() {
        let frame =
            Mat::new_rows_cols_with_default(50, 50, opencv::core::CV_8UC3, Scalar::all(128.0))
                .unwrap();
        let mut md = MotionDetector::new();
        // 连续 12 帧完全相同 → 运动量 ≈ 0
        for _ in 0..12 {
            md.update(&frame).unwrap();
        }
        assert!(md.is_likely_photo(), "连续 12 帧完全相同应被判定为照片");
    }

    #[test]
    fn motion_detector_history_capped_at_15() {
        let frame =
            Mat::new_rows_cols_with_default(50, 50, opencv::core::CV_8UC3, Scalar::all(128.0))
                .unwrap();
        let mut md = MotionDetector::new();
        for _ in 0..20 {
            md.update(&frame).unwrap();
        }
        assert!(
            md.motion_history.len() <= 15,
            "history 长度不应超过 15，实际 {}",
            md.motion_history.len()
        );
    }

    #[test]
    fn motion_detector_not_enough_frames_for_photo() {
        let frame =
            Mat::new_rows_cols_with_default(50, 50, opencv::core::CV_8UC3, Scalar::all(128.0))
                .unwrap();
        let mut md = MotionDetector::new();
        for _ in 0..5 {
            md.update(&frame).unwrap();
        }
        // 仅 5 帧，不足 10 帧 → is_likely_photo = false
        assert!(!md.is_likely_photo());
    }

    // ── BlinkDetector ───────────────────────────────────────────────────────

    /// 构造一组睁眼参考关键点（左右眼 EAR > 0.2）
    fn open_eye_landmarks() -> [f32; 136] {
        let mut lm = [0.0f32; 136];
        // 左眼 (36-42 → floats 72-84)：开放构型
        lm[72] = 10.0;
        lm[73] = 20.0; // p0
        lm[74] = 8.0;
        lm[75] = 24.0; // p1
        lm[76] = 9.0;
        lm[77] = 28.0; // p2
        lm[78] = 10.0;
        lm[79] = 32.0; // p3
        lm[80] = 11.0;
        lm[81] = 28.0; // p4
        lm[82] = 12.0;
        lm[83] = 24.0; // p5
                       // 右眼 (42-48 → floats 84-96)：开放构型
        lm[84] = 20.0;
        lm[85] = 20.0;
        lm[86] = 18.0;
        lm[87] = 24.0;
        lm[88] = 19.0;
        lm[89] = 28.0;
        lm[90] = 20.0;
        lm[91] = 32.0;
        lm[92] = 21.0;
        lm[93] = 28.0;
        lm[94] = 22.0;
        lm[95] = 24.0;
        lm
    }

    /// 构造一组闭眼参考关键点（左右眼 EAR < 0.2）
    fn closed_eye_landmarks() -> [f32; 136] {
        let mut lm = open_eye_landmarks();
        // 左眼：所有 y 接近 p0.y，EAR → 0
        lm[75] = 20.5; // p1.y
        lm[77] = 21.0; // p2.y
        lm[79] = 20.0; // p3.y
        lm[81] = 21.0; // p4.y
        lm[83] = 20.5; // p5.y
                       // 右眼：同理
        lm[87] = 20.5;
        lm[89] = 21.0;
        lm[91] = 20.0;
        lm[93] = 21.0;
        lm[95] = 20.5;
        lm
    }

    #[test]
    fn blink_detector_no_blink_open_eyes() {
        let mut bd = BlinkDetector::new();
        let lm = open_eye_landmarks();
        for _ in 0..10 {
            assert_eq!(bd.update(&lm).unwrap(), None, "睁眼不应检测到眨眼");
        }
    }

    #[test]
    fn blink_detector_detects_blink() {
        let mut bd = BlinkDetector::new();
        // 先送几帧睁眼建立基线
        let open = open_eye_landmarks();
        for _ in 0..5 {
            bd.update(&open).unwrap();
        }
        // 连续 3 帧闭眼触发眨眼检测
        let closed = closed_eye_landmarks();
        // 第 1-2 帧闭眼：still observing
        assert_eq!(bd.update(&closed).unwrap(), None, "第1帧闭眼 → None");
        assert_eq!(bd.update(&closed).unwrap(), None, "第2帧闭眼 → None");
        // 第 3 帧闭眼：blink detected
        assert_eq!(
            bd.update(&closed).unwrap(),
            Some(true),
            "第3帧闭眼 → Some(true)"
        );
        // 后续帧不再重复触发
        assert_eq!(bd.update(&closed).unwrap(), None, "触发后应返回 None");
    }

    #[test]
    fn blink_detector_timeout() {
        let mut bd = BlinkDetector::new();
        let open = open_eye_landmarks();
        for i in 0..151 {
            let result = bd.update(&open).unwrap();
            if result == Some(false) {
                return; // 超时正常
            }
            if i >= 150 {
                panic!("BlinkDetector 应在 150 帧后超时");
            }
        }
    }

    #[test]
    fn blink_detector_requires_136_floats() {
        let mut bd = BlinkDetector::new();
        let short = [0.0f32; 100];
        let result = bd.update(&short);
        assert!(result.is_err(), "不足 136 个 float 应返回错误");
    }
}
