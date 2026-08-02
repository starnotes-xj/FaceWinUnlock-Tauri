use std::{collections::VecDeque, path::Path, time::Instant};

use opencv::{
    core::{self, Mat, Rect, Scalar, Size, Vec3f, CV_32FC3},
    dnn::{self, Net},
    imgproc,
    prelude::*,
    Result,
};

pub const LIVENESS_WINDOW_SAMPLES: usize = 6;
pub const LIVENESS_MIN_WINDOW_MS: u64 = 350;

const MODEL_INPUT_SIZE: i32 = 128;
const FACE_EXPAND_SCALE: f32 = 1.35;
const PRIMARY_MEANS: [f32; 3] = [151.2405, 119.5950, 107.8395];
const PRIMARY_SCALES: [f32; 3] = [63.0105, 56.4570, 55.0035];
const SECONDARY_MEANS: [f32; 3] = [127.5, 127.5, 127.5];
const SECONDARY_SCALES: [f32; 3] = [128.0, 128.0, 128.0];
const LIVE_MARGIN_MIN: f32 = 0.08;
const SPOOF_MARGIN_MIN: f32 = 0.12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessDecision {
    Live,
    Spoof,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessStatus {
    Collecting,
    Ready(LivenessDecision),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LivenessScores {
    pub primary_live: f32,
    pub primary_spoof: f32,
    pub secondary_live: Option<f32>,
    pub secondary_spoof: Option<f32>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LivenessObservation {
    pub status: LivenessStatus,
    pub scores: LivenessScores,
    pub samples_collected: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
pub struct PassiveLiveness {
    primary: Net,
    secondary: Net,
    primary_contract: ModelContract,
    secondary_contract: ModelContract,
    window: DecisionWindow,
    observation_started_at: Option<Instant>,
}

#[derive(Clone, Debug)]
struct ModelContract {
    output_name: String,
    output_is_softmax: bool,
}

#[derive(Clone, Copy, Debug)]
struct FrameScores {
    elapsed_ms: u64,
    primary_live: f32,
    primary_spoof: f32,
    secondary_live: f32,
    secondary_spoof: f32,
}

#[derive(Debug, Default)]
struct DecisionWindow {
    frames: VecDeque<FrameScores>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameVote {
    Live,
    Spoof,
    Inconclusive,
}

impl PassiveLiveness {
    pub fn load(resources: &Path, backend_id: i32, target_id: i32) -> Result<Self> {
        let extension = if backend_id == 2 && target_id == 9 {
            "xml"
        } else {
            "onnx"
        };
        let primary_path = resources.join(format!("anti_spoof_mn3.{extension}"));
        let secondary_path = resources.join(format!("face_liveness.{extension}"));

        let (primary, primary_contract) =
            load_model(&primary_path, backend_id, target_id, ExpectedModel::Primary)?;
        let (secondary, secondary_contract) = load_model(
            &secondary_path,
            backend_id,
            target_id,
            ExpectedModel::Secondary,
        )?;

        Ok(Self {
            primary,
            secondary,
            primary_contract,
            secondary_contract,
            window: DecisionWindow::default(),
            observation_started_at: None,
        })
    }

    pub fn reset(&mut self) {
        self.window = DecisionWindow::default();
        self.observation_started_at = None;
    }

    pub fn observe(&mut self, frame_bgr: &Mat, face_rect: Rect) -> Result<LivenessObservation> {
        if frame_bgr.empty() {
            return Err(cv_error("liveness frame is empty"));
        }
        if face_rect.width <= 0 || face_rect.height <= 0 {
            return Err(cv_error("liveness face rect must be positive"));
        }

        let frame_size = frame_bgr.size()?;
        let crop_rect = expanded_face_rect(face_rect, frame_size)?;
        let face_crop = copy_face_crop(frame_bgr, crop_rect)?;

        let (primary_live, primary_spoof) =
            run_primary_model(&mut self.primary, &self.primary_contract, &face_crop)?;
        let (secondary_live, secondary_spoof) =
            run_secondary_model(&mut self.secondary, &self.secondary_contract, &face_crop)?;

        let scores = LivenessScores {
            primary_live,
            primary_spoof,
            secondary_live: Some(secondary_live),
            secondary_spoof: Some(secondary_spoof),
        };

        let elapsed_ms = self.elapsed_ms();
        self.window.push(FrameScores {
            elapsed_ms,
            primary_live,
            primary_spoof,
            secondary_live,
            secondary_spoof,
        });

        Ok(LivenessObservation {
            status: self.window.status(),
            scores,
            samples_collected: self.window.len(),
            elapsed_ms,
        })
    }

    fn elapsed_ms(&mut self) -> u64 {
        let now = Instant::now();
        let start = self.observation_started_at.get_or_insert(now);
        now.duration_since(*start).as_millis().min(u64::MAX as u128) as u64
    }
}

impl DecisionWindow {
    fn len(&self) -> usize {
        self.frames.len()
    }

    fn push(&mut self, frame: FrameScores) {
        if self.frames.len() == LIVENESS_WINDOW_SAMPLES {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
    }

    fn status(&self) -> LivenessStatus {
        if self.frames.len() < LIVENESS_WINDOW_SAMPLES {
            return LivenessStatus::Collecting;
        }

        let last = self.frames.back().expect("non-empty").elapsed_ms;
        if last < LIVENESS_MIN_WINDOW_MS {
            return LivenessStatus::Collecting;
        }

        LivenessStatus::Ready(decide_window(&self.frames))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedModel {
    Primary,
    Secondary,
}

fn load_model(
    model_path: &Path,
    backend_id: i32,
    target_id: i32,
    expected: ExpectedModel,
) -> Result<(Net, ModelContract)> {
    let path_str = model_path
        .to_str()
        .ok_or_else(|| cv_error("model path is not valid UTF-8"))?;

    let mut net = dnn::read_net(path_str, "", "")?;
    net.set_preferable_backend(backend_id)?;
    net.set_preferable_target(target_id)?;

    let output_names = net.get_unconnected_out_layers_names()?;
    if output_names.len() != 1 {
        return Err(cv_error("liveness model must expose exactly one output"));
    }

    let output_name = output_names.get(0)?;
    // OpenCV may expose an ONNX graph output as an Identity layer even when the graph's
    // preceding node is Softmax. These two pinned models have different verified contracts:
    // anti-spoof-mn3 emits probabilities, MiniFASNetV2 emits raw logits.
    let output_is_softmax = expected == ExpectedModel::Primary;

    match expected {
        ExpectedModel::Primary => {
            let _ = run_model_with_contract(
                &mut net,
                &ModelContract {
                    output_name: output_name.clone(),
                    output_is_softmax,
                },
                &blank_input_image()?,
                ExpectedModel::Primary,
            )?;
        }
        ExpectedModel::Secondary => {
            let _ = run_model_with_contract(
                &mut net,
                &ModelContract {
                    output_name: output_name.clone(),
                    output_is_softmax,
                },
                &blank_input_image()?,
                ExpectedModel::Secondary,
            )?;
        }
    }

    Ok((
        net,
        ModelContract {
            output_name,
            output_is_softmax,
        },
    ))
}

fn blank_input_image() -> Result<Mat> {
    Mat::new_nd_with_default(
        &[MODEL_INPUT_SIZE, MODEL_INPUT_SIZE],
        core::CV_8UC3,
        Scalar::all(0.0),
    )
}

fn run_primary_model(
    net: &mut Net,
    contract: &ModelContract,
    face_bgr: &Mat,
) -> Result<(f32, f32)> {
    run_model_with_contract(net, contract, face_bgr, ExpectedModel::Primary)
}

fn run_secondary_model(
    net: &mut Net,
    contract: &ModelContract,
    face_bgr: &Mat,
) -> Result<(f32, f32)> {
    run_model_with_contract(net, contract, face_bgr, ExpectedModel::Secondary)
}

fn run_model_with_contract(
    net: &mut Net,
    contract: &ModelContract,
    face_bgr: &Mat,
    expected: ExpectedModel,
) -> Result<(f32, f32)> {
    let (means, scales) = match expected {
        ExpectedModel::Primary => (&PRIMARY_MEANS, &PRIMARY_SCALES),
        ExpectedModel::Secondary => (&SECONDARY_MEANS, &SECONDARY_SCALES),
    };

    let tensor = prepare_nchw_tensor(face_bgr, means, scales)?;
    let blob = Mat::new_nd_with_data(&[1, 3, MODEL_INPUT_SIZE, MODEL_INPUT_SIZE], &tensor)?;
    net.set_input_def(&blob)?;
    let output = net.forward_single(&contract.output_name)?;
    parse_model_output(&output, contract.output_is_softmax, expected)
}

fn prepare_nchw_tensor(face_bgr: &Mat, means: &[f32; 3], scales: &[f32; 3]) -> Result<Vec<f32>> {
    let mut resized = Mat::default();
    imgproc::resize(
        face_bgr,
        &mut resized,
        Size::new(MODEL_INPUT_SIZE, MODEL_INPUT_SIZE),
        0.0,
        0.0,
        imgproc::INTER_LINEAR,
    )?;

    let mut rgb = Mat::default();
    // Use the generated default-argument wrapper so this remains compatible
    // with OpenCV 4.11 and 4.12 bindings (the latter adds AlgorithmHint).
    imgproc::cvt_color_def(&resized, &mut rgb, imgproc::COLOR_BGR2RGB)?;

    let mut rgb_float = Mat::default();
    rgb.convert_to(&mut rgb_float, CV_32FC3, 1.0, 0.0)?;

    let plane_len = (MODEL_INPUT_SIZE * MODEL_INPUT_SIZE) as usize;
    let mut tensor = vec![0.0f32; plane_len * 3];
    for row in 0..MODEL_INPUT_SIZE {
        for col in 0..MODEL_INPUT_SIZE {
            let pixel = *rgb_float.at_2d::<Vec3f>(row, col)?;
            let base = (row * MODEL_INPUT_SIZE + col) as usize;
            tensor[base] = (pixel[0] - means[0]) / scales[0];
            tensor[plane_len + base] = (pixel[1] - means[1]) / scales[1];
            tensor[(plane_len * 2) + base] = (pixel[2] - means[2]) / scales[2];
        }
    }

    Ok(tensor)
}

fn parse_model_output(
    output: &Mat,
    already_softmax: bool,
    expected: ExpectedModel,
) -> Result<(f32, f32)> {
    let values = output.data_typed::<f32>()?;
    if values.len() != 2 {
        return Err(cv_error(
            "liveness model output must contain exactly two scores",
        ));
    }
    if values.iter().any(|value| !value.is_finite()) {
        return Err(cv_error("liveness model output must be finite"));
    }

    let scores = if already_softmax {
        let scores = [values[0], values[1]];
        validate_softmax_probabilities(scores)?;
        scores
    } else {
        softmax2([values[0], values[1]])
    };

    match expected {
        ExpectedModel::Primary => Ok((scores[0], scores[1])),
        ExpectedModel::Secondary => Ok((scores[1], scores[0])),
    }
}

fn copy_face_crop(frame_bgr: &Mat, crop_rect: Rect) -> Result<Mat> {
    let roi = frame_bgr.roi(crop_rect)?;
    let mut face_crop = Mat::default();
    roi.copy_to(&mut face_crop)?;
    Ok(face_crop)
}

fn expanded_face_rect(face_rect: Rect, frame_size: Size) -> Result<Rect> {
    if frame_size.width <= 0 || frame_size.height <= 0 {
        return Err(cv_error("frame size must be positive"));
    }
    if face_rect.width <= 0 || face_rect.height <= 0 {
        return Err(cv_error("face rect must be positive"));
    }

    let center_x = face_rect.x as f32 + face_rect.width as f32 * 0.5;
    let center_y = face_rect.y as f32 + face_rect.height as f32 * 0.5;
    let expanded_w = (face_rect.width as f32 * FACE_EXPAND_SCALE)
        .round()
        .max(1.0);
    let expanded_h = (face_rect.height as f32 * FACE_EXPAND_SCALE)
        .round()
        .max(1.0);

    let left = (center_x - expanded_w * 0.5).floor() as i32;
    let top = (center_y - expanded_h * 0.5).floor() as i32;
    let right = (center_x + expanded_w * 0.5).ceil() as i32;
    let bottom = (center_y + expanded_h * 0.5).ceil() as i32;

    let x = left.clamp(0, frame_size.width - 1);
    let y = top.clamp(0, frame_size.height - 1);
    let right = right.clamp(x + 1, frame_size.width);
    let bottom = bottom.clamp(y + 1, frame_size.height);

    Ok(Rect::new(x, y, right - x, bottom - y))
}

fn decide_window(frames: &VecDeque<FrameScores>) -> LivenessDecision {
    let mut live_votes = 0usize;
    let mut spoof_votes = 0usize;
    let mut primary_margin_sum = 0.0f32;
    let mut secondary_margin_sum = 0.0f32;

    for frame in frames {
        primary_margin_sum += frame.primary_live - frame.primary_spoof;
        secondary_margin_sum += frame.secondary_live - frame.secondary_spoof;
        match classify_frame(*frame) {
            FrameVote::Live => live_votes += 1,
            FrameVote::Spoof => spoof_votes += 1,
            FrameVote::Inconclusive => {}
        }
    }

    let count = frames.len() as f32;
    let primary_margin_avg = primary_margin_sum / count;
    let secondary_margin_avg = secondary_margin_sum / count;

    if spoof_votes >= 3 || (spoof_votes >= 2 && primary_margin_avg < 0.0) {
        LivenessDecision::Spoof
    } else if live_votes >= 4
        && spoof_votes == 0
        && primary_margin_avg >= LIVE_MARGIN_MIN
        && secondary_margin_avg >= 0.0
    {
        LivenessDecision::Live
    } else {
        LivenessDecision::Inconclusive
    }
}

fn classify_frame(frame: FrameScores) -> FrameVote {
    let primary_margin = frame.primary_live - frame.primary_spoof;
    let secondary_margin = frame.secondary_live - frame.secondary_spoof;

    if primary_margin <= -SPOOF_MARGIN_MIN || secondary_margin <= -SPOOF_MARGIN_MIN {
        FrameVote::Spoof
    } else if primary_margin >= LIVE_MARGIN_MIN && secondary_margin >= 0.0 {
        FrameVote::Live
    } else {
        FrameVote::Inconclusive
    }
}

fn softmax2(logits: [f32; 2]) -> [f32; 2] {
    let max_logit = logits[0].max(logits[1]);
    let e0 = (logits[0] - max_logit).exp();
    let e1 = (logits[1] - max_logit).exp();
    let denom = e0 + e1;
    [e0 / denom, e1 / denom]
}

fn validate_softmax_probabilities(scores: [f32; 2]) -> Result<()> {
    if scores
        .iter()
        .any(|score| !score.is_finite() || !(0.0..=1.0).contains(score))
    {
        return Err(cv_error(
            "liveness Softmax probabilities must be finite and within [0, 1]",
        ));
    }

    let sum = scores[0] + scores[1];
    if (sum - 1.0).abs() > 1e-3 {
        return Err(cv_error(
            "liveness Softmax probabilities must sum to approximately 1",
        ));
    }

    Ok(())
}

fn cv_error(message: impl Into<String>) -> opencv::Error {
    opencv::Error::new(core::StsError, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_is_stable_for_large_logits() {
        let scores = softmax2([1200.0, 1190.0]);
        assert!((scores[0] + scores[1] - 1.0).abs() < 1e-6);
        assert!(scores[0] > 0.9999);
        assert!(scores[1] < 0.0001);
    }

    #[test]
    fn expanded_face_rect_clamps_to_frame_bounds() {
        let rect = expanded_face_rect(Rect::new(90, 70, 20, 20), Size::new(100, 80)).unwrap();
        assert_eq!(rect.x, 86);
        assert_eq!(rect.y, 66);
        assert_eq!(rect.width, 14);
        assert_eq!(rect.height, 14);
    }

    #[test]
    fn expanded_face_rect_expands_centered_faces() {
        let rect = expanded_face_rect(Rect::new(40, 20, 20, 30), Size::new(200, 120)).unwrap();
        assert_eq!(rect, Rect::new(36, 14, 28, 42));
    }

    #[test]
    fn window_requires_both_sample_count_and_duration() {
        let mut window = DecisionWindow::default();
        for idx in 0..LIVENESS_WINDOW_SAMPLES {
            window.push(FrameScores {
                elapsed_ms: (idx as u64) * 40,
                primary_live: 0.9,
                primary_spoof: 0.1,
                secondary_live: 0.7,
                secondary_spoof: 0.3,
            });
        }
        assert_eq!(window.status(), LivenessStatus::Collecting);
    }

    #[test]
    fn window_resolves_live_when_votes_are_consistent() {
        let mut window = DecisionWindow::default();
        for idx in 0..LIVENESS_WINDOW_SAMPLES {
            window.push(FrameScores {
                elapsed_ms: (idx as u64) * 90,
                primary_live: 0.86,
                primary_spoof: 0.14,
                secondary_live: 0.74,
                secondary_spoof: 0.26,
            });
        }
        assert_eq!(
            window.status(),
            LivenessStatus::Ready(LivenessDecision::Live)
        );
    }

    #[test]
    fn window_resolves_spoof_when_spoof_votes_dominate() {
        let mut window = DecisionWindow::default();
        for idx in 0..LIVENESS_WINDOW_SAMPLES {
            let spoof = idx < 3;
            window.push(FrameScores {
                elapsed_ms: (idx as u64) * 80,
                primary_live: if spoof { 0.20 } else { 0.78 },
                primary_spoof: if spoof { 0.80 } else { 0.22 },
                secondary_live: if spoof { 0.18 } else { 0.70 },
                secondary_spoof: if spoof { 0.82 } else { 0.30 },
            });
        }
        assert_eq!(
            window.status(),
            LivenessStatus::Ready(LivenessDecision::Spoof)
        );
    }

    #[test]
    fn window_resolves_inconclusive_for_mixed_votes() {
        let mut window = DecisionWindow::default();
        let frames = [
            (0.82, 0.18, 0.62, 0.38),
            (0.80, 0.20, 0.60, 0.40),
            (0.76, 0.24, 0.55, 0.45),
            (0.44, 0.56, 0.49, 0.51),
            (0.78, 0.22, 0.52, 0.48),
            (0.49, 0.51, 0.50, 0.50),
        ];
        for (idx, frame) in frames.into_iter().enumerate() {
            window.push(FrameScores {
                elapsed_ms: (idx as u64) * 75,
                primary_live: frame.0,
                primary_spoof: frame.1,
                secondary_live: frame.2,
                secondary_spoof: frame.3,
            });
        }
        assert_eq!(
            window.status(),
            LivenessStatus::Ready(LivenessDecision::Inconclusive)
        );
    }

    #[test]
    fn window_becomes_ready_on_seventh_frame_after_min_duration() {
        let mut window = DecisionWindow::default();
        for idx in 0..LIVENESS_WINDOW_SAMPLES {
            window.push(FrameScores {
                elapsed_ms: (idx as u64) * 60,
                primary_live: 0.85,
                primary_spoof: 0.15,
                secondary_live: 0.70,
                secondary_spoof: 0.30,
            });
        }
        assert_eq!(window.status(), LivenessStatus::Collecting);

        window.push(FrameScores {
            elapsed_ms: 360,
            primary_live: 0.85,
            primary_spoof: 0.15,
            secondary_live: 0.70,
            secondary_spoof: 0.30,
        });
        assert_eq!(
            window.status(),
            LivenessStatus::Ready(LivenessDecision::Live)
        );
    }
}
