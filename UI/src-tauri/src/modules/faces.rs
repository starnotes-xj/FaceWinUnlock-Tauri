use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use opencv::{
    core::{Mat, Rect, Scalar, Size, Vector},
    imgcodecs, imgproc,
    prelude::*,
};
use serde_json::json;

use crate::utils::custom_result::CustomResult;
use crate::{APP_STATE, ROOT_DIR};

/// 缓存参考图的人脸特征，避免每帧重复提取 (#121)
struct VerificationCache {
    reference_hash: String,
    reference_feature: Mat,
    #[allow(dead_code)] // 缓存时的检测阈值，保留备查
    threshold: f32,
}
static VERIFY_CACHE: std::sync::LazyLock<Mutex<Option<VerificationCache>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

// ─── Private helpers ──────────────────────────────────────────────────────────

/// 旋转帧（rotation: 0/90/180/270，270 等同逆时针 90°）
fn rotate_frame(frame: &Mat, rotation: i32) -> Result<Mat, String> {
    if rotation == 0 {
        return frame.try_clone().map_err(|e| e.to_string());
    }
    let code = match rotation {
        90 => opencv::core::ROTATE_90_CLOCKWISE,
        180 => opencv::core::ROTATE_180,
        270 => opencv::core::ROTATE_90_COUNTERCLOCKWISE,
        _ => return frame.try_clone().map_err(|e| e.to_string()),
    };
    let mut rotated = Mat::default();
    opencv::core::rotate(frame, &mut rotated, code).map_err(|e| format!("旋转帧失败: {:?}", e))?;
    Ok(rotated)
}

fn mat_to_data_url(frame: &Mat) -> Result<String, String> {
    let params = Vector::<i32>::new();
    let mut buf = Vector::<u8>::new();
    imgcodecs::imencode(".jpg", frame, &mut buf, &params)
        .map_err(|e| format!("JPEG 编码失败: {:?}", e))?;
    Ok(format!(
        "data:image/jpeg;base64,{}",
        B64.encode(buf.as_slice())
    ))
}

fn base64_to_mat(b64: &str) -> Result<Mat, String> {
    let payload = if let Some(p) = b64.find(',') {
        &b64[p + 1..]
    } else {
        b64
    };
    let bytes = B64
        .decode(payload)
        .map_err(|e| format!("base64 解码失败: {:?}", e))?;
    let buf = Vector::<u8>::from_iter(bytes);
    imgcodecs::imdecode(&buf, imgcodecs::IMREAD_COLOR).map_err(|e| format!("图片解码失败: {:?}", e))
}

/// 大图（如 4K 3840×2160）会让 YuNet 检测极慢甚至漏检（issue #20，用户反馈"像素问题"导入本地图片
/// 出错）。按最长边降采样到 <= MAX_SIDE，保持宽高比；已足够小则原样返回。SFace 会对人脸区域对齐裁剪，
/// 降采样不影响特征质量。
fn clamp_detect_size(frame: Mat) -> Result<Mat, String> {
    const MAX_SIDE: i32 = 1600;
    let (w, h) = (frame.cols(), frame.rows());
    let longest = w.max(h);
    if longest <= MAX_SIDE || longest <= 0 {
        return Ok(frame);
    }
    let scale = MAX_SIDE as f64 / longest as f64;
    let new_size = Size::new(
        ((w as f64) * scale).round() as i32,
        ((h as f64) * scale).round() as i32,
    );
    let mut out = Mat::default();
    imgproc::resize(&frame, &mut out, new_size, 0.0, 0.0, imgproc::INTER_AREA)
        .map_err(|e| format!("图片降采样失败: {:?}", e))?;
    Ok(out)
}

/// 从帧中检测人脸，返回检测结果 Mat（rows == 0 表示未检测到）
fn detect_faces(frame: &Mat, threshold: f32) -> Result<Mat, String> {
    let mut state = APP_STATE
        .lock()
        .map_err(|e| format!("获取 APP_STATE 失败: {}", e))?;
    let det = state
        .detector
        .as_mut()
        .ok_or_else(|| "模型未加载，请先调用 load_opencv_model".to_string())?;

    det.inner
        .set_score_threshold(threshold)
        .map_err(|e| format!("设置检测阈值失败: {:?}", e))?;
    det.inner
        .set_input_size(Size::new(frame.cols(), frame.rows()))
        .map_err(|e| format!("设置输入尺寸失败: {:?}", e))?;

    let mut faces = Mat::default();
    det.inner
        .detect(frame, &mut faces)
        .map_err(|e| format!("人脸检测失败: {:?}", e))?;
    Ok(faces)
}

/// 在帧上绘制第一个检测框（绿色）
fn draw_face_box(frame: &mut Mat, faces: &Mat) -> Result<(), String> {
    if faces.rows() == 0 {
        return Ok(());
    }
    let x = (*faces.at_2d::<f32>(0, 0).map_err(|e| e.to_string())?).max(0.0) as i32;
    let y = (*faces.at_2d::<f32>(0, 1).map_err(|e| e.to_string())?).max(0.0) as i32;
    let w = (*faces.at_2d::<f32>(0, 2).map_err(|e| e.to_string())?).max(1.0) as i32;
    let h = (*faces.at_2d::<f32>(0, 3).map_err(|e| e.to_string())?).max(1.0) as i32;
    imgproc::rectangle(
        frame,
        Rect::new(x, y, w.min(frame.cols() - x), h.min(frame.rows() - y)),
        Scalar::new(0.0, 255.0, 0.0, 0.0),
        2,
        imgproc::LINE_8,
        0,
    )
    .map_err(|e| format!("绘制人脸框失败: {:?}", e))?;
    Ok(())
}

/// 对齐并提取人脸特征向量（1×128 f32 Mat）
fn extract_feature(frame: &Mat, face_row: &Mat) -> Result<Mat, String> {
    let mut state = APP_STATE
        .lock()
        .map_err(|e| format!("获取 APP_STATE 失败: {}", e))?;
    let rec = state
        .recognizer
        .as_mut()
        .ok_or_else(|| "识别模型未加载".to_string())?;

    let mut aligned = Mat::default();
    rec.inner
        .align_crop(frame, face_row, &mut aligned)
        .map_err(|e| format!("人脸对齐失败: {:?}", e))?;
    let mut feature = Mat::default();
    rec.inner
        .feature(&aligned, &mut feature)
        .map_err(|e| format!("特征提取失败: {:?}", e))?;
    Ok(feature)
}

/// 计算两个特征向量的余弦相似度（0.0 ~ 1.0）
fn cosine_similarity(feat1: &Mat, feat2: &Mat) -> Result<f64, String> {
    let mut state = APP_STATE
        .lock()
        .map_err(|e| format!("获取 APP_STATE 失败: {}", e))?;
    let rec = state
        .recognizer
        .as_mut()
        .ok_or_else(|| "识别模型未加载".to_string())?;

    // FR_COSINE = 0
    rec.inner
        .match_(feat1, feat2, 0)
        .map_err(|e| format!("特征比对失败: {:?}", e))
}

/// 活体检测，返回真实人脸置信度（0.0 ~ 1.0）
fn liveness_score(frame: &Mat, faces: &Mat) -> Result<f32, String> {
    let x = (*faces.at_2d::<f32>(0, 0).map_err(|e| e.to_string())?).max(0.0) as i32;
    let y = (*faces.at_2d::<f32>(0, 1).map_err(|e| e.to_string())?).max(0.0) as i32;
    let w = (*faces.at_2d::<f32>(0, 2).map_err(|e| e.to_string())?).max(1.0) as i32;
    let h = (*faces.at_2d::<f32>(0, 3).map_err(|e| e.to_string())?).max(1.0) as i32;
    let w = w.min(frame.cols() - x);
    let h = h.min(frame.rows() - y);
    if w <= 0 || h <= 0 {
        return Ok(0.0);
    }

    let face_crop = frame
        .roi(Rect::new(x, y, w, h))
        .map_err(|e| format!("裁剪人脸失败: {:?}", e))?;

    let blob = opencv::dnn::blob_from_image(
        &face_crop,
        1.0 / 255.0,
        Size::new(80, 80),
        Scalar::new(0.5 * 255.0, 0.5 * 255.0, 0.5 * 255.0, 0.0),
        true,
        false,
        opencv::core::CV_32F,
    )
    .map_err(|e| format!("构建 liveness blob 失败: {:?}", e))?;

    let mut state = APP_STATE
        .lock()
        .map_err(|e| format!("获取 APP_STATE 失败: {}", e))?;
    let net = state
        .liveness
        .as_mut()
        .ok_or_else(|| "活体模型未加载".to_string())?;

    net.inner
        .set_input(&blob, "", 1.0, Scalar::default())
        .map_err(|e| format!("设置 liveness 输入失败: {:?}", e))?;

    // forward_single 是返回 Mat 的变体（区别于填充 OutputArray 的 forward）
    let output = net
        .inner
        .forward_single("")
        .map_err(|e| format!("liveness 前向推理失败: {:?}", e))?;

    let flat = output
        .reshape(1, 1)
        .map_err(|e| format!("reshape 失败: {:?}", e))?;
    let cols = flat.cols();
    let idx = if cols >= 2 { 1 } else { 0 };
    let score = *flat.at::<f32>(idx).map_err(|e| e.to_string())?;
    Ok(score.clamp(0.0, 1.0))
}

// ─── 共用：从给定帧检测人脸并返回带框/原始 base64 ────────────────────────────

fn check_face_inner(frame: Mat, detection_threshold: f64) -> Result<CustomResult, CustomResult> {
    let threshold = detection_threshold as f32;

    let faces = detect_faces(&frame, threshold)
        .map_err(|e| CustomResult::error(Some(format!("人脸检测失败: {}", e)), None))?;

    let raw_b64 = mat_to_data_url(&frame).map_err(|e| CustomResult::error(Some(e), None))?;

    if faces.rows() == 0 {
        return Ok(CustomResult::success(
            None,
            Some(json!({ "display_base64": "未检测到人脸", "raw_base64": raw_b64 })),
        ));
    }

    let mut display = frame.clone();
    draw_face_box(&mut display, &faces).map_err(|e| CustomResult::error(Some(e), None))?;
    let display_b64 = mat_to_data_url(&display).map_err(|e| CustomResult::error(Some(e), None))?;

    Ok(CustomResult::success(
        None,
        Some(json!({ "display_base64": display_b64, "raw_base64": raw_b64 })),
    ))
}

// ─── Tauri commands ───────────────────────────────────────────────────────────

/// 从摄像头拍一帧并检测人脸
#[tauri::command]
pub fn check_face_from_camera(
    face_detection_threshold: f64,
    camera_rotation: i32,
) -> Result<CustomResult, CustomResult> {
    let frame = {
        let mut state = APP_STATE
            .lock()
            .map_err(|e| CustomResult::error(Some(format!("获取 APP_STATE 失败: {}", e)), None))?;
        let cam = state.camera.as_mut().ok_or_else(|| {
            CustomResult::error(Some("摄像头未打开，请先调用 open_camera".to_string()), None)
        })?;
        let mut f = Mat::default();
        cam.inner
            .read(&mut f)
            .map_err(|e| CustomResult::error(Some(format!("读取摄像头帧失败: {:?}", e)), None))?;
        if f.empty() {
            return Err(CustomResult::error(
                Some("摄像头返回空帧".to_string()),
                None,
            ));
        }
        f
    };
    let frame =
        rotate_frame(&frame, camera_rotation).map_err(|e| CustomResult::error(Some(e), None))?;
    check_face_inner(frame, face_detection_threshold)
}

/// 从图片文件加载并检测人脸
#[tauri::command]
pub fn check_face_from_img(
    img_path: String,
    face_detection_threshold: f64,
) -> Result<CustomResult, CustomResult> {
    // 中文 / Unicode 路径：OpenCV imread 底层用 fopen，打不开非 ASCII 路径（issue #20）。改为用
    // Rust 读取字节再 imdecode，Unicode 路径安全。
    let bytes = std::fs::read(&img_path)
        .map_err(|e| CustomResult::error(Some(format!("读取图片失败: {}", e)), None))?;
    let buf = Vector::<u8>::from_iter(bytes);
    let frame = imgcodecs::imdecode(&buf, imgcodecs::IMREAD_COLOR)
        .map_err(|e| CustomResult::error(Some(format!("图片解码失败: {:?}", e)), None))?;
    if frame.empty() {
        return Err(CustomResult::error(
            Some(format!("图片为空或路径无效: {}", img_path)),
            None,
        ));
    }
    // 4K 等大图降采样，避免 YuNet 漏检 / 极慢（issue #20）
    let frame = clamp_detect_size(frame).map_err(|e| CustomResult::error(Some(e), None))?;
    check_face_inner(frame, face_detection_threshold)
}

/// 保存人脸注册信息（特征 .face 文件 + 图片 .faceimg 文件），返回 { file_name: uuid }
/// reference_base64: 不含 data URI 前缀的 JPEG base64
#[tauri::command]
pub fn save_face_registration(
    _name: String,
    reference_base64: String,
    face_detection_threshold: f64,
) -> Result<CustomResult, CustomResult> {
    let frame = base64_to_mat(&reference_base64).map_err(|e| CustomResult::error(Some(e), None))?;
    // 本地导入的大图（如 4K）同样降采样后再检测 / 提取特征（issue #20）
    let frame = clamp_detect_size(frame).map_err(|e| CustomResult::error(Some(e), None))?;

    let threshold = face_detection_threshold as f32;
    let faces = detect_faces(&frame, threshold).map_err(|e| CustomResult::error(Some(e), None))?;

    if faces.rows() == 0 {
        return Err(CustomResult::error(
            Some("图片中未检测到人脸".to_string()),
            None,
        ));
    }

    let face_row = faces
        .row(0)
        .map_err(|e| CustomResult::error(Some(format!("获取检测结果失败: {:?}", e)), None))?
        .try_clone()
        .map_err(|e| CustomResult::error(Some(format!("克隆检测行失败: {:?}", e)), None))?;
    let feature =
        extract_feature(&frame, &face_row).map_err(|e| CustomResult::error(Some(e), None))?;

    let uuid = uuid::Uuid::new_v4().to_string();
    let faces_dir = ROOT_DIR.join("faces");
    std::fs::create_dir_all(&faces_dir)
        .map_err(|e| CustomResult::error(Some(format!("创建 faces 目录失败: {}", e)), None))?;

    // 写特征文件（128 × f32 小端字节）
    let feature_bytes = feature
        .data_bytes()
        .map_err(|e| CustomResult::error(Some(format!("获取特征数据失败: {:?}", e)), None))?;
    std::fs::write(faces_dir.join(format!("{}.face", uuid)), feature_bytes)
        .map_err(|e| CustomResult::error(Some(format!("写特征文件失败: {}", e)), None))?;

    // 写图片文件（原始 JPEG 字节，base64 解码）
    let img_bytes = B64.decode(&reference_base64).unwrap_or_default();
    std::fs::write(faces_dir.join(format!("{}.faceimg", uuid)), &img_bytes)
        .map_err(|e| CustomResult::error(Some(format!("写图片文件失败: {}", e)), None))?;

    Ok(CustomResult::success(
        None,
        Some(json!({ "file_name": uuid })),
    ))
}

/// 从参考图提取特征向量（带缓存），避免每帧重复解码+检测+特征提取 (#121)
fn get_ref_feature(reference_base64: &str, threshold: f32) -> Result<Mat, String> {
    // 用 base64 长度+前16字符做简易哈希，检测参考图变化
    let hash_key = format!(
        "{}:{}:{}",
        reference_base64.len(),
        threshold,
        &reference_base64[..reference_base64.len().min(64)]
    );

    {
        let cache = VERIFY_CACHE.lock().map_err(|e| e.to_string())?;
        if let Some(c) = cache.as_ref() {
            if c.reference_hash == hash_key {
                return c
                    .reference_feature
                    .try_clone()
                    .map_err(|e| format!("克隆缓存特征失败: {:?}", e));
            }
        }
    }

    // 缓存未命中，提取参考图特征
    let ref_frame = base64_to_mat(reference_base64)?;
    let ref_faces = detect_faces(&ref_frame, threshold)?;
    if ref_faces.rows() == 0 {
        return Err("参考图中未检测到人脸".to_string());
    }
    let ref_row = ref_faces
        .row(0)
        .map_err(|e| e.to_string())?
        .try_clone()
        .map_err(|e| format!("克隆检测行失败: {:?}", e))?;
    let ref_feature = extract_feature(&ref_frame, &ref_row)?;

    // 存入缓存
    if let Ok(mut cache) = VERIFY_CACHE.lock() {
        if let Ok(cloned) = ref_feature.try_clone() {
            *cache = Some(VerificationCache {
                reference_hash: hash_key,
                reference_feature: cloned,
                threshold,
            });
        }
    }

    Ok(ref_feature)
}

/// 人脸验证（摄像头当前帧 vs 参考图），返回 { display_base64, success, score, message }
/// reference_base64: 不含 data URI 前缀的 JPEG base64
#[tauri::command]
pub fn verify_face(
    reference_base64: String,
    face_detection_threshold: f64,
    liveness_enabled: bool,
    liveness_threshold: f64,
    _face_aligned_type: String,
    camera_rotation: i32,
) -> Result<CustomResult, CustomResult> {
    let threshold = face_detection_threshold as f32;

    // 1. 从摄像头读取一帧
    let frame = {
        let mut state = APP_STATE
            .lock()
            .map_err(|e| CustomResult::error(Some(format!("获取 APP_STATE 失败: {}", e)), None))?;
        let cam = state
            .camera
            .as_mut()
            .ok_or_else(|| CustomResult::error(Some("摄像头未打开".to_string()), None))?;
        let mut f = Mat::default();
        cam.inner
            .read(&mut f)
            .map_err(|e| CustomResult::error(Some(format!("读取摄像头帧失败: {:?}", e)), None))?;
        if f.empty() {
            return Err(CustomResult::error(
                Some("摄像头返回空帧".to_string()),
                None,
            ));
        }
        f
    };
    let frame =
        rotate_frame(&frame, camera_rotation).map_err(|e| CustomResult::error(Some(e), None))?;

    // 2. 检测摄像头帧中的人脸
    let cam_faces =
        detect_faces(&frame, threshold).map_err(|e| CustomResult::error(Some(e), None))?;

    if cam_faces.rows() == 0 {
        // 返回裸帧用于预览（不做参考图处理，节省时间）
        let raw_b64 = mat_to_data_url(&frame).map_err(|e| CustomResult::error(Some(e), None))?;
        return Ok(CustomResult::success(
            None,
            Some(json!({
                "display_base64": raw_b64,
                "success": false,
                "score": 0.0,
                "message": "未检测到人脸"
            })),
        ));
    }

    // 3. 活体检测（可选）
    if liveness_enabled {
        let live_score =
            liveness_score(&frame, &cam_faces).map_err(|e| CustomResult::error(Some(e), None))?;
        if (live_score as f64) < liveness_threshold {
            let mut display = frame.clone();
            let _ = draw_face_box(&mut display, &cam_faces);
            let display_b64 =
                mat_to_data_url(&display).map_err(|e| CustomResult::error(Some(e), None))?;
            return Ok(CustomResult::success(
                None,
                Some(json!({
                    "display_base64": display_b64,
                    "success": false,
                    "score": (live_score as f64 * 100.0).round() / 100.0,
                    "message": "活体检测未通过"
                })),
            ));
        }
    }

    // 4. 提取摄像头人脸特征
    let cam_row = cam_faces
        .row(0)
        .map_err(|e| CustomResult::error(Some(format!("获取检测结果行失败: {:?}", e)), None))?
        .try_clone()
        .map_err(|e| CustomResult::error(Some(format!("克隆检测行失败: {:?}", e)), None))?;
    let cam_feature =
        extract_feature(&frame, &cam_row).map_err(|e| CustomResult::error(Some(e), None))?;

    // 5. 获取参考图特征（首次提取后缓存复用 #121）
    let ref_feature = get_ref_feature(&reference_base64, threshold)
        .map_err(|e| CustomResult::error(Some(e), None))?;

    // 6. 计算余弦相似度
    let score = cosine_similarity(&cam_feature, &ref_feature)
        .map_err(|e| CustomResult::error(Some(e), None))?;

    // 7. 绘制结果并返回
    let mut display = frame.clone();
    let _ = draw_face_box(&mut display, &cam_faces);
    let display_b64 = mat_to_data_url(&display).map_err(|e| CustomResult::error(Some(e), None))?;

    let success = score >= 0.5;
    let message = if success {
        format!("验证通过，相似度: {:.1}%", score * 100.0)
    } else {
        format!("相似度不足: {:.1}%", score * 100.0)
    };

    Ok(CustomResult::success(
        None,
        Some(json!({
            "display_base64": display_b64,
            "success": success,
            "score": (score * 100.0).round() / 100.0,
            "message": message
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencv::core::CV_8UC3;

    // #20a：4K 等大图应按最长边降采样到 <=1600 且保持宽高比
    #[test]
    fn clamp_downscales_4k_keeps_aspect() {
        let big = Mat::new_rows_cols_with_default(2160, 3840, CV_8UC3, Scalar::all(0.0)).unwrap();
        let out = clamp_detect_size(big).unwrap();
        assert_eq!(out.cols(), 1600, "最长边应=1600");
        assert_eq!(out.rows(), 900, "16:9 应缩到 1600x900");
    }

    // 已足够小的图应原样返回（不放大、不改尺寸）
    #[test]
    fn clamp_keeps_small_untouched() {
        let small = Mat::new_rows_cols_with_default(480, 640, CV_8UC3, Scalar::all(0.0)).unwrap();
        let out = clamp_detect_size(small).unwrap();
        assert_eq!((out.cols(), out.rows()), (640, 480));
    }

    // #20c：中文路径下 std::fs::read + imdecode 能成功解码（imread 底层 fopen 通常打不开）
    #[test]
    fn chinese_path_decodes_via_fs_read() {
        let dir = std::env::temp_dir().join("facewin_测试_录入");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("人脸图片_测试.jpg");

        let img = Mat::new_rows_cols_with_default(120, 100, CV_8UC3, Scalar::all(128.0)).unwrap();
        let mut jpg = Vector::<u8>::new();
        imgcodecs::imencode(".jpg", &img, &mut jpg, &Vector::<i32>::new()).unwrap();
        std::fs::write(&path, jpg.as_slice()).unwrap();

        // 修复后路径：fs::read + imdecode
        let bytes = std::fs::read(&path).unwrap();
        let buf = Vector::<u8>::from_iter(bytes);
        let frame = imgcodecs::imdecode(&buf, imgcodecs::IMREAD_COLOR).unwrap();
        assert!(!frame.empty(), "中文路径应能解码出非空图");
        assert_eq!((frame.cols(), frame.rows()), (100, 120));

        // 对照旧路径 imread（仅打印，不同 OpenCV 构建行为可能不同）
        let via_imread =
            imgcodecs::imread(path.to_str().unwrap(), imgcodecs::IMREAD_COLOR).unwrap();
        println!("对照 imread(中文路径) empty = {}", via_imread.empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
