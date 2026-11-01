//! S22-2: read-only geometry and private-buffer resource budgeting.
//! This does not acquire frames or publish files; capture remains disabled.

use super::{CaptureSource, CaptureUnavailable, validate_source};

/// The maximum private bytes one unqualified screenshot request may ask to
/// stage. No such staging is registered as a runtime operation.
const MAX_PRIVATE_FRAME_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenshotBudgetError {
    InvalidGeometry,
    UnboundWindowGeometry,
    UnsupportedPixelFormat,
    InconsistentFrameExtent,
    ExcessiveStride,
    ExcessiveFrameBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateFrameBudget {
    /// Upper bound for one native frame, including row padding.
    pub bytes: u64,
}

/// Validate a source-bound frame's declared memory cost *before* allocation.
/// A geometry result never authorizes source acquisition or disclosure.
pub fn private_frame_budget(
    source: &CaptureSource,
    pixel_width: u32,
    pixel_height: u32,
    bytes_per_pixel: u8,
    stride_bytes: u64,
) -> Result<PrivateFrameBudget, ScreenshotBudgetError> {
    validate_source(source).map_err(|reason| match reason {
        CaptureUnavailable::InvalidNativeGeometry => ScreenshotBudgetError::InvalidGeometry,
        _ => ScreenshotBudgetError::InvalidGeometry,
    })?;
    if bytes_per_pixel != 4 {
        return Err(ScreenshotBudgetError::UnsupportedPixelFormat);
    }
    let (expected_width, expected_height) = match source {
        CaptureSource::Output { width, height, .. }
        | CaptureSource::Region { width, height, .. } => (*width, *height),
        CaptureSource::Window { .. } => {
            return Err(ScreenshotBudgetError::UnboundWindowGeometry);
        }
    };
    if expected_width != pixel_width || expected_height != pixel_height {
        return Err(ScreenshotBudgetError::InconsistentFrameExtent);
    }
    let minimum_stride = u64::from(pixel_width)
        .checked_mul(u64::from(bytes_per_pixel))
        .ok_or(ScreenshotBudgetError::ExcessiveStride)?;
    if stride_bytes < minimum_stride
        || stride_bytes > minimum_stride.saturating_add(4096)
        || stride_bytes % u64::from(bytes_per_pixel) != 0
    {
        return Err(ScreenshotBudgetError::ExcessiveStride);
    }
    let bytes = stride_bytes
        .checked_mul(u64::from(pixel_height))
        .ok_or(ScreenshotBudgetError::ExcessiveFrameBytes)?;
    if bytes > MAX_PRIVATE_FRAME_BYTES {
        return Err(ScreenshotBudgetError::ExcessiveFrameBytes);
    }
    Ok(PrivateFrameBudget { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output() -> CaptureSource {
        CaptureSource::Output {
            output_id: "DP-1".into(),
            width: 1920,
            height: 1080,
            scale_milli: 1000,
            transform: 0,
        }
    }

    #[test]
    fn accepts_only_consistent_bounded_private_frame_metadata() {
        assert_eq!(
            private_frame_budget(&output(), 1920, 1080, 4, 7680),
            Ok(PrivateFrameBudget { bytes: 8_294_400 })
        );
        assert_eq!(
            private_frame_budget(&output(), 1921, 1080, 4, 7684),
            Err(ScreenshotBudgetError::InconsistentFrameExtent)
        );
        assert_eq!(
            private_frame_budget(&output(), 1920, 1080, 3, 5760),
            Err(ScreenshotBudgetError::UnsupportedPixelFormat)
        );
        assert_eq!(
            private_frame_budget(&output(), 1920, 1080, 4, 100_000),
            Err(ScreenshotBudgetError::ExcessiveStride)
        );
    }

    #[test]
    fn unsupported_window_source_cannot_guess_size() {
        let source = CaptureSource::Window {
            window_id: "20".into(),
            output_id: "DP-1".into(),
            window_generation: 1,
        };
        assert_eq!(
            private_frame_budget(&source, 100, 100, 4, 400),
            Err(ScreenshotBudgetError::UnboundWindowGeometry)
        );
    }

    #[test]
    fn large_frames_and_overflows_fail_closed() {
        let source = CaptureSource::Output {
            output_id: "DP-1".into(),
            width: 12_000,
            height: 7_000,
            scale_milli: 1000,
            transform: 0,
        };
        assert_eq!(
            private_frame_budget(&source, 12_000, 7_000, 4, 48_000),
            Err(ScreenshotBudgetError::ExcessiveFrameBytes)
        );
        assert_eq!(
            private_frame_budget(&output(), 1920, 1080, 4, 0),
            Err(ScreenshotBudgetError::ExcessiveStride)
        );
    }
}
