// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! L3 shadow for the `sharp` npm package.
//!
//! Upstream `sharp` ships a libvips-backed `.node` native addon;
//! inside the WASM sandbox we intercept `require('sharp')` and
//! dispatch to pure-Rust crates: [`image`](https://crates.io/crates/image)
//! handles codecs (PNG / JPEG / WebP / GIF / BMP) and the per-pixel
//! ops (rotate / flip / grayscale / extract / blur), while
//! [`fast_image_resize`](https://crates.io/crates/fast_image_resize)
//! drives the SIMD-accelerated resize path - that's the operation
//! real `sharp` users hit hardest, so it earns its own crate.
//!
//! ## Pipeline shape
//!
//! Sharp is a fluent builder: `sharp(buf).resize(W, H).rotate(90).jpeg().toBuffer()`.
//! We mirror that on the JS side by accumulating ops into an array.
//! When a terminal call (`toBuffer` / `toFile` / `metadata`) is
//! invoked, the polyfill serializes the whole pipeline into one
//! JSON blob and crosses the host boundary in a **single host
//! call**. No per-op host roundtrip; no handle-map state.
//!
//! ```text
//! { source: { kind: "buffer", data_b64: "..." },
//!   ops:    [ { op: "resize", width: 800, height: 600, fit: "cover" },
//!             { op: "rotate", degrees: 90 } ],
//!   output: { format: "jpeg", quality: 80 } }
//! ```
//!
//! ## Errors
//!
//! Decoder / encoder failures, invalid op parameters (negative
//! dimensions, zero-sized extract, etc.), and unsupported
//! formats / ops surface as a single `Result<_, String>` from each
//! entry point. The JS bridge upstream wraps the message into an
//! `Error` with `code: 'ERR_SHADOW_SHARP'`.

use base64::Engine as _;
use fast_image_resize::images::Image;
use fast_image_resize::{PixelType, ResizeAlg, ResizeOptions, Resizer};
use image::{
    DynamicImage, GenericImageView, ImageDecoder, ImageFormat, ImageReader,
    codecs::{jpeg::JpegEncoder, png::PngEncoder, webp::WebPEncoder},
};
use std::io::Cursor;

// ----- types --------------------------------------------------------------

#[derive(Debug, Clone)]
enum Source {
    /// Raw image bytes (typical sharp(buffer) usage).
    Buffer(Vec<u8>),
    /// File path. The polyfill is responsible for reading the file
    /// itself (so the manifold's FS allow-list applies); we only see
    /// bytes here, but expose the variant in case a future iteration
    /// hands the path through directly.
    #[allow(dead_code)]
    File(String),
}

#[derive(Debug, Clone)]
struct ResizeOpts {
    width: Option<u32>,
    height: Option<u32>,
    fit: ResizeFit,
    kernel: ResizeKernel,
}

#[derive(Debug, Clone, Copy)]
enum ResizeFit {
    /// Resize to cover both dimensions, cropping overflow (default).
    Cover,
    /// Resize to fit within both dimensions, preserving aspect ratio.
    Contain,
    /// Stretch to exact dimensions (no aspect-ratio preservation).
    Fill,
    /// Same as Contain but never enlarges.
    Inside,
    /// Resize to outside both dimensions (≥ both); preserving aspect.
    Outside,
}

#[derive(Debug, Clone, Copy)]
enum ResizeKernel {
    Nearest,
    Linear,
    Cubic,
    Mitchell,
    Lanczos3,
}

#[derive(Debug, Clone)]
struct Extract {
    left: u32,
    top: u32,
    width: u32,
    height: u32,
}

#[derive(Debug, Clone)]
enum Op {
    Resize(ResizeOpts),
    /// Rotation in degrees clockwise. Only multiples of 90 are
    /// guaranteed lossless (image's rotate90/180/270). Arbitrary
    /// angles are rejected - the npm package supports them via
    /// libvips, but the rust `image` crate's general rotate isn't
    /// in this minimum subset.
    Rotate(i32),
    Grayscale,
    /// Vertical flip (top↔bottom).
    Flip,
    /// Horizontal flip (left↔right).
    Flop,
    Extract(Extract),
    /// Gaussian blur with the given sigma. Sharp accepts > 0.3.
    Blur(f32),
    /// Negate (invert) the image.
    Negate,
    /// Per-pixel multiply by an RGB tint colour.
    Tint {
        r: u8,
        g: u8,
        b: u8,
    },
    /// HSL adjustment - brightness multiplier, saturation multiplier,
    /// hue rotation in degrees. brightness=1, saturation=1, hue=0 is
    /// the identity.
    Modulate {
        brightness: f32,
        saturation: f32,
        hue: f32,
    },
    /// Unsharp mask. `sigma` controls the blur radius of the mask;
    /// `flat` and `jagged` are the strength multipliers from sharp's
    /// `m1` / `m2`.
    Sharpen {
        sigma: f32,
        flat: f32,
        jagged: f32,
    },
    /// Histogram stretch - find min/max per channel, scale to [0,255].
    Normalize,
    /// Threshold to binary; pixels with luminance ≥ level go white.
    /// `grayscale: true` returns a single-channel image.
    Threshold {
        level: u8,
        grayscale: bool,
    },
    /// Composite layers over the base image. Each layer is decoded
    /// from its own source bytes and alpha-blended at (left, top).
    Composite(Vec<CompositeLayer>),
}

#[derive(Debug, Clone)]
struct CompositeLayer {
    bytes: Vec<u8>,
    top: u32,
    left: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Some fields are placeholders for upstream-image-crate
// knobs we don't honor yet (PNG compression level
// isn't exposed by image 0.25's PngEncoder; WebP
// quality + lossless are accepted but the encoder
// is lossless-only). Keep the parse path so a
// future swap to image-webp's lossy path is purely
// additive.
enum Output {
    /// `quality` 1–100; defaults to 80.
    Jpeg { quality: u8 },
    /// `compression` 0–9; image always uses zlib so we just pick a
    /// best-effort level.
    Png { compression: u8 },
    /// Lossy quality 0–100; lossless not exposed in the minimum
    /// subset (image's WebP encoder defaults to lossless). Set
    /// `lossless: true` to flip to that path.
    Webp { quality: u8, lossless: bool },
    /// `metadata()` request - the encode step is skipped.
    Metadata,
}

#[derive(Debug, Clone)]
struct Pipeline {
    source: Source,
    ops: Vec<Op>,
    output: Output,
}

// ----- public entry points -----------------------------------------------

/// Run a full pipeline (decode → ops → encode) and return the
/// encoded bytes. For `Output::Metadata`, returns an empty Vec -
/// callers should use [`metadata`] for that path instead.
pub fn run(pipeline_json: &str) -> Result<Vec<u8>, String> {
    let p = parse_pipeline(pipeline_json)?;
    let mut img = decode_source(&p.source)?;
    for op in &p.ops {
        img = apply_op(img, op)?;
    }
    encode_output(&img, &p.output)
}

/// Inspect the source bytes and return JSON metadata
/// `{width, height, format, channels, hasAlpha, space}`.
pub fn metadata(source_json: &str) -> Result<String, String> {
    let s: serde_json::Value = serde_json::from_str(source_json)
        .map_err(|e| format!("sharp.metadata: bad source JSON: {e}"))?;
    let source = parse_source(&s)?;
    metadata_for_source(&source)
}

/// Compute per-channel statistics on the decoded image. Mirrors
/// `sharp.stats()`: `{channels:[{min,max,sum,squaresSum,mean,stdev}], isOpaque, entropy, sharpness}`.
/// Entropy + sharpness fields stay 0 - those require a full FFT /
/// kernel pass that costs more than the rest of the metadata combined
/// and are rarely consumed.
pub fn stats(source_json: &str) -> Result<String, String> {
    let s: serde_json::Value = serde_json::from_str(source_json)
        .map_err(|e| format!("sharp.stats: bad source JSON: {e}"))?;
    let source = parse_source(&s)?;
    let bytes = match &source {
        Source::Buffer(b) => b.clone(),
        Source::File(p) => std::fs::read(p).map_err(|e| format!("sharp: read {p}: {e}"))?,
    };
    let img = image::load_from_memory(&bytes).map_err(|e| format!("sharp.stats: decode: {e}"))?;
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width() as u64, rgba.height() as u64);
    let pixel_count = (w * h) as f64;
    // Channels in RGBA order: R, G, B, A. We accumulate sum and
    // sum-of-squares incrementally to compute mean + stdev without a
    // second pass over the pixel array.
    let mut sum = [0f64; 4];
    let mut sq_sum = [0f64; 4];
    let mut min_v = [255u8; 4];
    let mut max_v = [0u8; 4];
    let mut is_opaque = true;
    for px in rgba.pixels() {
        for c in 0..4 {
            let v = px.0[c];
            sum[c] += v as f64;
            sq_sum[c] += (v as f64) * (v as f64);
            if v < min_v[c] {
                min_v[c] = v;
            }
            if v > max_v[c] {
                max_v[c] = v;
            }
        }
        if px.0[3] != 255 {
            is_opaque = false;
        }
    }
    let n = pixel_count.max(1.0);
    let channels: Vec<serde_json::Value> = (0..4)
        .map(|c| {
            let mean = sum[c] / n;
            // Variance via E[X^2] - E[X]^2; clamp to >= 0 for
            // floating-point noise on a constant channel.
            let var = (sq_sum[c] / n - mean * mean).max(0.0);
            serde_json::json!({
                "min": min_v[c],
                "max": max_v[c],
                "sum": sum[c],
                "squaresSum": sq_sum[c],
                "mean": mean,
                "stdev": var.sqrt(),
                "minX": 0,
                "minY": 0,
                "maxX": 0,
                "maxY": 0,
            })
        })
        .collect();
    let v = serde_json::json!({
        "channels": channels,
        "isOpaque": is_opaque,
        "entropy": 0.0,
        "sharpness": 0.0,
        "dominant": { "r": 0, "g": 0, "b": 0 },
    });
    serde_json::to_string(&v).map_err(|e| format!("sharp.stats: serialize: {e}"))
}

// ----- pipeline parsing --------------------------------------------------

fn parse_pipeline(json: &str) -> Result<Pipeline, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("sharp: pipeline JSON: {e}"))?;
    let source = parse_source(
        v.get("source")
            .ok_or_else(|| "sharp: pipeline missing `source`".to_string())?,
    )?;
    let ops = match v.get("ops") {
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().map(parse_op).collect::<Result<Vec<_>, _>>()?
        }
        Some(_) => return Err("sharp: `ops` must be an array".into()),
        None => Vec::new(),
    };
    let output = parse_output(
        v.get("output")
            .ok_or_else(|| "sharp: pipeline missing `output`".to_string())?,
    )?;
    Ok(Pipeline {
        source,
        ops,
        output,
    })
}

fn parse_source(v: &serde_json::Value) -> Result<Source, String> {
    let kind = v
        .get("kind")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "sharp: source needs `kind`".to_string())?;
    match kind {
        "buffer" => {
            let b64 = v
                .get("data_b64")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "sharp: buffer source needs `data_b64`".to_string())?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| format!("sharp: source base64: {e}"))?;
            Ok(Source::Buffer(bytes))
        }
        "file" => {
            let path = v
                .get("path")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "sharp: file source needs `path`".to_string())?;
            Ok(Source::File(path.to_string()))
        }
        other => Err(format!("sharp: unknown source kind {other}")),
    }
}

fn parse_op(v: &serde_json::Value) -> Result<Op, String> {
    let name = v
        .get("op")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "sharp: op missing `op` field".to_string())?;
    match name {
        "resize" => {
            let width = v.get("width").and_then(|x| x.as_u64()).map(|n| n as u32);
            let height = v.get("height").and_then(|x| x.as_u64()).map(|n| n as u32);
            if width.is_none() && height.is_none() {
                return Err("sharp.resize: either width or height required".into());
            }
            if matches!(width, Some(0)) || matches!(height, Some(0)) {
                return Err("sharp.resize: dimensions must be > 0".into());
            }
            let fit = match v.get("fit").and_then(|x| x.as_str()).unwrap_or("cover") {
                "cover" => ResizeFit::Cover,
                "contain" => ResizeFit::Contain,
                "fill" => ResizeFit::Fill,
                "inside" => ResizeFit::Inside,
                "outside" => ResizeFit::Outside,
                other => return Err(format!("sharp.resize: unknown fit {other}")),
            };
            let kernel = match v
                .get("kernel")
                .and_then(|x| x.as_str())
                .unwrap_or("lanczos3")
            {
                "nearest" => ResizeKernel::Nearest,
                "linear" => ResizeKernel::Linear,
                "cubic" => ResizeKernel::Cubic,
                "mitchell" => ResizeKernel::Mitchell,
                "lanczos3" => ResizeKernel::Lanczos3,
                other => return Err(format!("sharp.resize: unknown kernel {other}")),
            };
            Ok(Op::Resize(ResizeOpts {
                width,
                height,
                fit,
                kernel,
            }))
        }
        "rotate" => {
            let deg = v
                .get("degrees")
                .and_then(|x| x.as_i64())
                .ok_or_else(|| "sharp.rotate: `degrees` required".to_string())?;
            if deg.rem_euclid(90) != 0 {
                return Err(
                    "sharp.rotate: only 0/90/180/270 degree multiples are supported".into(),
                );
            }
            Ok(Op::Rotate(deg as i32))
        }
        "grayscale" => Ok(Op::Grayscale),
        "flip" => Ok(Op::Flip),
        "flop" => Ok(Op::Flop),
        "negate" => Ok(Op::Negate),
        "extract" => {
            let left = v
                .get("left")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| "sharp.extract: `left` required".to_string())?
                as u32;
            let top = v
                .get("top")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| "sharp.extract: `top` required".to_string())?
                as u32;
            let width = v
                .get("width")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| "sharp.extract: `width` required".to_string())?
                as u32;
            let height = v
                .get("height")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| "sharp.extract: `height` required".to_string())?
                as u32;
            if width == 0 || height == 0 {
                return Err("sharp.extract: width/height must be > 0".into());
            }
            Ok(Op::Extract(Extract {
                left,
                top,
                width,
                height,
            }))
        }
        "blur" => {
            let sigma = v
                .get("sigma")
                .and_then(|x| x.as_f64())
                .ok_or_else(|| "sharp.blur: `sigma` required".to_string())?;
            if !(0.3..=1000.0).contains(&sigma) {
                return Err("sharp.blur: sigma must be in [0.3, 1000]".into());
            }
            Ok(Op::Blur(sigma as f32))
        }
        "tint" => {
            let r = v.get("r").and_then(|x| x.as_u64()).unwrap_or(255) as u8;
            let g = v.get("g").and_then(|x| x.as_u64()).unwrap_or(255) as u8;
            let b = v.get("b").and_then(|x| x.as_u64()).unwrap_or(255) as u8;
            Ok(Op::Tint { r, g, b })
        }
        "modulate" => {
            let brightness = v.get("brightness").and_then(|x| x.as_f64()).unwrap_or(1.0) as f32;
            let saturation = v.get("saturation").and_then(|x| x.as_f64()).unwrap_or(1.0) as f32;
            let hue = v.get("hue").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
            Ok(Op::Modulate {
                brightness,
                saturation,
                hue,
            })
        }
        "sharpen" => {
            let sigma = v.get("sigma").and_then(|x| x.as_f64()).unwrap_or(1.0) as f32;
            let flat = v.get("flat").and_then(|x| x.as_f64()).unwrap_or(1.0) as f32;
            let jagged = v.get("jagged").and_then(|x| x.as_f64()).unwrap_or(2.0) as f32;
            if sigma <= 0.0 {
                return Err("sharp.sharpen: sigma must be > 0".into());
            }
            Ok(Op::Sharpen {
                sigma,
                flat,
                jagged,
            })
        }
        "normalize" => Ok(Op::Normalize),
        "threshold" => {
            let level = v
                .get("level")
                .and_then(|x| x.as_u64())
                .map(|n| n.clamp(0, 255) as u8)
                .unwrap_or(128);
            let grayscale = v.get("grayscale").and_then(|x| x.as_bool()).unwrap_or(true);
            Ok(Op::Threshold { level, grayscale })
        }
        "composite" => {
            let arr = v
                .get("layers")
                .and_then(|x| x.as_array())
                .ok_or_else(|| "sharp.composite: `layers` array required".to_string())?;
            let mut layers = Vec::with_capacity(arr.len());
            for layer in arr {
                use base64::Engine;
                let b64 = layer
                    .get("source_b64")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| "sharp.composite: layer.source_b64 required".to_string())?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| format!("sharp.composite: base64: {e}"))?;
                let top = layer.get("top").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let left = layer.get("left").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                layers.push(CompositeLayer { bytes, top, left });
            }
            Ok(Op::Composite(layers))
        }
        other => Err(format!("sharp: unsupported op `{other}`")),
    }
}

fn parse_output(v: &serde_json::Value) -> Result<Output, String> {
    let format = v
        .get("format")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "sharp: output needs `format`".to_string())?;
    match format {
        "jpeg" | "jpg" => {
            let q = v
                .get("quality")
                .and_then(|x| x.as_u64())
                .map(|n| n.clamp(1, 100) as u8)
                .unwrap_or(80);
            Ok(Output::Jpeg { quality: q })
        }
        "png" => {
            let c = v
                .get("compression")
                .and_then(|x| x.as_u64())
                .map(|n| n.clamp(0, 9) as u8)
                .unwrap_or(6);
            Ok(Output::Png { compression: c })
        }
        "webp" => {
            let q = v
                .get("quality")
                .and_then(|x| x.as_u64())
                .map(|n| n.clamp(0, 100) as u8)
                .unwrap_or(80);
            let lossless = v.get("lossless").and_then(|x| x.as_bool()).unwrap_or(false);
            Ok(Output::Webp {
                quality: q,
                lossless,
            })
        }
        "metadata" => Ok(Output::Metadata),
        other => Err(format!("sharp: unsupported output format `{other}`")),
    }
}

// ----- decode / metadata --------------------------------------------------

fn decode_source(source: &Source) -> Result<DynamicImage, String> {
    let bytes = match source {
        Source::Buffer(b) => b.clone(),
        Source::File(p) => std::fs::read(p).map_err(|e| format!("sharp: read {p}: {e}"))?,
    };
    let reader = ImageReader::new(Cursor::new(&bytes))
        .with_guessed_format()
        .map_err(|e| format!("sharp: guess format: {e}"))?;
    reader.decode().map_err(|e| format!("sharp: decode: {e}"))
}

fn metadata_for_source(source: &Source) -> Result<String, String> {
    let bytes = match source {
        Source::Buffer(b) => b.clone(),
        Source::File(p) => std::fs::read(p).map_err(|e| format!("sharp: read {p}: {e}"))?,
    };
    let reader = ImageReader::new(Cursor::new(&bytes))
        .with_guessed_format()
        .map_err(|e| format!("sharp: guess format: {e}"))?;
    let format = reader.format();
    let decoder = reader
        .into_decoder()
        .map_err(|e| format!("sharp: decoder: {e}"))?;
    let (width, height) = decoder.dimensions();
    let color = decoder.color_type();
    let format_name = format.map(format_label).unwrap_or("unknown");
    let channels = match color {
        image::ColorType::L8 | image::ColorType::L16 => 1,
        image::ColorType::La8 | image::ColorType::La16 => 2,
        image::ColorType::Rgb8 | image::ColorType::Rgb16 | image::ColorType::Rgb32F => 3,
        image::ColorType::Rgba8 | image::ColorType::Rgba16 | image::ColorType::Rgba32F => 4,
        _ => 0,
    };
    let has_alpha = matches!(
        color,
        image::ColorType::La8
            | image::ColorType::La16
            | image::ColorType::Rgba8
            | image::ColorType::Rgba16
            | image::ColorType::Rgba32F
    );
    let space = match color {
        image::ColorType::L8
        | image::ColorType::L16
        | image::ColorType::La8
        | image::ColorType::La16 => "b-w",
        _ => "srgb",
    };
    let v = serde_json::json!({
        "width": width,
        "height": height,
        "format": format_name,
        "channels": channels,
        "hasAlpha": has_alpha,
        "space": space,
        "size": bytes.len(),
    });
    serde_json::to_string(&v).map_err(|e| format!("sharp.metadata: serialize: {e}"))
}

fn format_label(f: ImageFormat) -> &'static str {
    match f {
        ImageFormat::Png => "png",
        ImageFormat::Jpeg => "jpeg",
        ImageFormat::WebP => "webp",
        ImageFormat::Gif => "gif",
        ImageFormat::Bmp => "bmp",
        ImageFormat::Tiff => "tiff",
        _ => "unknown",
    }
}

// ----- ops ---------------------------------------------------------------

fn apply_op(img: DynamicImage, op: &Op) -> Result<DynamicImage, String> {
    match op {
        Op::Resize(opts) => apply_resize(img, opts),
        Op::Rotate(deg) => Ok(apply_rotate(img, *deg)),
        Op::Grayscale => Ok(DynamicImage::ImageLuma8(img.to_luma8())),
        Op::Flip => Ok(img.flipv()),
        Op::Flop => Ok(img.fliph()),
        Op::Negate => {
            let mut img = img;
            img.invert();
            Ok(img)
        }
        Op::Extract(e) => {
            let (w, h) = img.dimensions();
            if e.left.saturating_add(e.width) > w || e.top.saturating_add(e.height) > h {
                return Err(format!(
                    "sharp.extract: region {}x{}+{}+{} outside {}x{}",
                    e.width, e.height, e.left, e.top, w, h
                ));
            }
            Ok(img.crop_imm(e.left, e.top, e.width, e.height))
        }
        Op::Blur(sigma) => Ok(img.blur(*sigma)),
        Op::Tint { r, g, b } => Ok(apply_tint(img, *r, *g, *b)),
        Op::Modulate {
            brightness,
            saturation,
            hue,
        } => Ok(apply_modulate(img, *brightness, *saturation, *hue)),
        Op::Sharpen {
            sigma,
            flat,
            jagged,
        } => Ok(apply_sharpen(img, *sigma, *flat, *jagged)),
        Op::Normalize => Ok(apply_normalize(img)),
        Op::Threshold { level, grayscale } => Ok(apply_threshold(img, *level, *grayscale)),
        Op::Composite(layers) => apply_composite(img, layers),
    }
}

/// Multiply each pixel's RGB channels by `(r,g,b) / 255`. Alpha
/// channel is preserved. This is what sharp's `tint(rgb)` does.
fn apply_tint(img: DynamicImage, r: u8, g: u8, b: u8) -> DynamicImage {
    let mut rgba = img.to_rgba8();
    let rf = r as f32 / 255.0;
    let gf = g as f32 / 255.0;
    let bf = b as f32 / 255.0;
    for px in rgba.pixels_mut() {
        px.0[0] = (px.0[0] as f32 * rf).clamp(0.0, 255.0) as u8;
        px.0[1] = (px.0[1] as f32 * gf).clamp(0.0, 255.0) as u8;
        px.0[2] = (px.0[2] as f32 * bf).clamp(0.0, 255.0) as u8;
    }
    DynamicImage::ImageRgba8(rgba)
}

/// HSL-space adjustment via per-pixel RGB→HSL→tweak→RGB.
fn apply_modulate(img: DynamicImage, brightness: f32, saturation: f32, hue: f32) -> DynamicImage {
    let mut rgba = img.to_rgba8();
    for px in rgba.pixels_mut() {
        let (r, g, b) = (
            px.0[0] as f32 / 255.0,
            px.0[1] as f32 / 255.0,
            px.0[2] as f32 / 255.0,
        );
        let (mut h, mut s, mut l) = rgb_to_hsl(r, g, b);
        h = (h + hue / 360.0).rem_euclid(1.0);
        s = (s * saturation).clamp(0.0, 1.0);
        l = (l * brightness).clamp(0.0, 1.0);
        let (r2, g2, b2) = hsl_to_rgb(h, s, l);
        px.0[0] = (r2 * 255.0).clamp(0.0, 255.0) as u8;
        px.0[1] = (g2 * 255.0).clamp(0.0, 255.0) as u8;
        px.0[2] = (b2 * 255.0).clamp(0.0, 255.0) as u8;
    }
    DynamicImage::ImageRgba8(rgba)
}

fn rgb_to_hsl(r: f32, g: f32, b: f32) -> (f32, f32, f32) {
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let l = (max + min) * 0.5;
    let d = max - min;
    if d.abs() < f32::EPSILON {
        return (0.0, 0.0, l);
    }
    let s = if l < 0.5 {
        d / (max + min)
    } else {
        d / (2.0 - max - min)
    };
    let h = if (max - r).abs() < f32::EPSILON {
        ((g - b) / d) + (if g < b { 6.0 } else { 0.0 })
    } else if (max - g).abs() < f32::EPSILON {
        (b - r) / d + 2.0
    } else {
        (r - g) / d + 4.0
    } / 6.0;
    (h, s, l)
}

fn hsl_to_rgb(h: f32, s: f32, l: f32) -> (f32, f32, f32) {
    if s == 0.0 {
        return (l, l, l);
    }
    let q = if l < 0.5 {
        l * (1.0 + s)
    } else {
        l + s - l * s
    };
    let p = 2.0 * l - q;
    let r = hue_to_rgb(p, q, h + 1.0 / 3.0);
    let g = hue_to_rgb(p, q, h);
    let b = hue_to_rgb(p, q, h - 1.0 / 3.0);
    (r, g, b)
}

fn hue_to_rgb(p: f32, q: f32, mut t: f32) -> f32 {
    if t < 0.0 {
        t += 1.0;
    }
    if t > 1.0 {
        t -= 1.0;
    }
    if t < 1.0 / 6.0 {
        return p + (q - p) * 6.0 * t;
    }
    if t < 0.5 {
        return q;
    }
    if t < 2.0 / 3.0 {
        return p + (q - p) * (2.0 / 3.0 - t) * 6.0;
    }
    p
}

/// Unsharp mask: `out = img + amount * (img - blurred)`. We use the
/// `image` crate's blur for the low-pass, then walk pixels.
fn apply_sharpen(img: DynamicImage, sigma: f32, flat: f32, jagged: f32) -> DynamicImage {
    let blurred = img.blur(sigma);
    let mut src = img.to_rgba8();
    let blur_rgba = blurred.to_rgba8();
    // sharp's m1/m2: flat (low-frequency) and jagged (high-frequency)
    // multipliers. We approximate by using a single amount that
    // averages them - matches what most users expect from sharpen().
    let amount = (flat + jagged) * 0.5;
    for (px, bpx) in src.pixels_mut().zip(blur_rgba.pixels()) {
        for c in 0..3 {
            let s = px.0[c] as f32;
            let bl = bpx.0[c] as f32;
            let v = s + amount * (s - bl);
            px.0[c] = v.clamp(0.0, 255.0) as u8;
        }
    }
    DynamicImage::ImageRgba8(src)
}

/// Histogram stretch: find min/max across the RGB channels and
/// scale all pixels so the dynamic range covers [0,255].
fn apply_normalize(img: DynamicImage) -> DynamicImage {
    let mut rgba = img.to_rgba8();
    let (mut lo, mut hi) = (255u8, 0u8);
    for px in rgba.pixels() {
        for c in 0..3 {
            let v = px.0[c];
            if v < lo {
                lo = v;
            }
            if v > hi {
                hi = v;
            }
        }
    }
    if hi <= lo {
        return DynamicImage::ImageRgba8(rgba);
    }
    let range = (hi - lo) as f32;
    for px in rgba.pixels_mut() {
        for c in 0..3 {
            let v = ((px.0[c] - lo) as f32 / range) * 255.0;
            px.0[c] = v.clamp(0.0, 255.0) as u8;
        }
    }
    DynamicImage::ImageRgba8(rgba)
}

/// Threshold by luminance (ITU-R BT.601). Pixels at or above `level`
/// → white; below → black. Optionally collapse to single-channel.
fn apply_threshold(img: DynamicImage, level: u8, grayscale: bool) -> DynamicImage {
    let rgba = img.to_rgba8();
    if grayscale {
        let mut luma = image::GrayImage::new(rgba.width(), rgba.height());
        for (l, src) in luma.pixels_mut().zip(rgba.pixels()) {
            let y =
                (0.299 * src.0[0] as f32 + 0.587 * src.0[1] as f32 + 0.114 * src.0[2] as f32) as u8;
            l.0[0] = if y >= level { 255 } else { 0 };
        }
        DynamicImage::ImageLuma8(luma)
    } else {
        let mut out = rgba;
        for px in out.pixels_mut() {
            let y =
                (0.299 * px.0[0] as f32 + 0.587 * px.0[1] as f32 + 0.114 * px.0[2] as f32) as u8;
            let v = if y >= level { 255 } else { 0 };
            px.0[0] = v;
            px.0[1] = v;
            px.0[2] = v;
        }
        DynamicImage::ImageRgba8(out)
    }
}

/// Alpha-blend each layer over the base image at its (left, top)
/// origin. Layers are decoded from their bytes via `image::load_from_memory`.
fn apply_composite(base: DynamicImage, layers: &[CompositeLayer]) -> Result<DynamicImage, String> {
    let mut out = base.to_rgba8();
    for (i, layer) in layers.iter().enumerate() {
        let layer_img = image::load_from_memory(&layer.bytes)
            .map_err(|e| format!("sharp.composite: layer {i} decode: {e}"))?
            .to_rgba8();
        let (out_w, out_h) = out.dimensions();
        for ly in 0..layer_img.height() {
            let dy = layer.top + ly;
            if dy >= out_h {
                break;
            }
            for lx in 0..layer_img.width() {
                let dx = layer.left + lx;
                if dx >= out_w {
                    break;
                }
                let src = layer_img.get_pixel(lx, ly);
                let dst = out.get_pixel_mut(dx, dy);
                // "over" alpha blend.
                let a = src.0[3] as f32 / 255.0;
                let inv = 1.0 - a;
                for c in 0..3 {
                    dst.0[c] =
                        (src.0[c] as f32 * a + dst.0[c] as f32 * inv).clamp(0.0, 255.0) as u8;
                }
                dst.0[3] = (src.0[3] as f32 + dst.0[3] as f32 * inv).clamp(0.0, 255.0) as u8;
            }
        }
    }
    Ok(DynamicImage::ImageRgba8(out))
}

fn apply_rotate(img: DynamicImage, degrees: i32) -> DynamicImage {
    let normalized = degrees.rem_euclid(360);
    match normalized {
        0 => img,
        90 => img.rotate90(),
        180 => img.rotate180(),
        270 => img.rotate270(),
        _ => unreachable!("parse_op rejects non-multiples of 90"),
    }
}

fn apply_resize(img: DynamicImage, opts: &ResizeOpts) -> Result<DynamicImage, String> {
    let (orig_w, orig_h) = img.dimensions();
    if orig_w == 0 || orig_h == 0 {
        return Err("sharp.resize: source has zero dimensions".into());
    }
    let (target_w, target_h) = compute_resize_dims(orig_w, orig_h, opts);
    if target_w == 0 || target_h == 0 {
        return Err("sharp.resize: computed target has zero dimensions".into());
    }

    // For Cover: resize to cover (≥ both) then crop center to exact.
    let (resize_w, resize_h, crop) = match opts.fit {
        ResizeFit::Cover if opts.width.is_some() && opts.height.is_some() => {
            let (rw, rh) = cover_dims(orig_w, orig_h, target_w, target_h);
            (rw, rh, Some((target_w, target_h)))
        }
        _ => (target_w, target_h, None),
    };

    let alg = match opts.kernel {
        ResizeKernel::Nearest => ResizeAlg::Nearest,
        ResizeKernel::Linear => ResizeAlg::Convolution(fast_image_resize::FilterType::Bilinear),
        ResizeKernel::Cubic => ResizeAlg::Convolution(fast_image_resize::FilterType::CatmullRom),
        ResizeKernel::Mitchell => ResizeAlg::Convolution(fast_image_resize::FilterType::Mitchell),
        ResizeKernel::Lanczos3 => ResizeAlg::Convolution(fast_image_resize::FilterType::Lanczos3),
    };

    // fast_image_resize works on RGB8 / RGBA8; convert as needed.
    let (resized, kept_alpha) = if img.color().has_alpha() {
        let src = img.into_rgba8();
        let (sw, sh) = (src.width(), src.height());
        let src_image = Image::from_vec_u8(sw, sh, src.into_raw(), PixelType::U8x4)
            .map_err(|e| format!("sharp.resize: src wrap: {e}"))?;
        let mut dst = Image::new(resize_w, resize_h, PixelType::U8x4);
        let mut resizer = Resizer::new();
        let opts_local = ResizeOptions::new().resize_alg(alg);
        resizer
            .resize(&src_image, &mut dst, &opts_local)
            .map_err(|e| format!("sharp.resize: {e}"))?;
        let buf =
            image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(resize_w, resize_h, dst.into_vec())
                .ok_or_else(|| "sharp.resize: rgba output build".to_string())?;
        (DynamicImage::ImageRgba8(buf), true)
    } else {
        let src = img.into_rgb8();
        let (sw, sh) = (src.width(), src.height());
        let src_image = Image::from_vec_u8(sw, sh, src.into_raw(), PixelType::U8x3)
            .map_err(|e| format!("sharp.resize: src wrap: {e}"))?;
        let mut dst = Image::new(resize_w, resize_h, PixelType::U8x3);
        let mut resizer = Resizer::new();
        let opts_local = ResizeOptions::new().resize_alg(alg);
        resizer
            .resize(&src_image, &mut dst, &opts_local)
            .map_err(|e| format!("sharp.resize: {e}"))?;
        let buf =
            image::ImageBuffer::<image::Rgb<u8>, _>::from_raw(resize_w, resize_h, dst.into_vec())
                .ok_or_else(|| "sharp.resize: rgb output build".to_string())?;
        (DynamicImage::ImageRgb8(buf), false)
    };

    let final_img = match crop {
        Some((cw, ch)) => {
            let (rw, rh) = resized.dimensions();
            let cx = if rw > cw { (rw - cw) / 2 } else { 0 };
            let cy = if rh > ch { (rh - ch) / 2 } else { 0 };
            resized.crop_imm(cx, cy, cw, ch)
        }
        None => resized,
    };
    let _ = kept_alpha;
    Ok(final_img)
}

/// Compute the actual resize target before any centering crop.
fn compute_resize_dims(orig_w: u32, orig_h: u32, opts: &ResizeOpts) -> (u32, u32) {
    match (opts.width, opts.height, opts.fit) {
        (Some(w), Some(h), ResizeFit::Fill) => (w, h),
        (Some(w), None, _) => {
            let scale = w as f64 / orig_w as f64;
            (w, ((orig_h as f64) * scale).round().max(1.0) as u32)
        }
        (None, Some(h), _) => {
            let scale = h as f64 / orig_h as f64;
            (((orig_w as f64) * scale).round().max(1.0) as u32, h)
        }
        (Some(w), Some(h), fit) => {
            let scale_w = w as f64 / orig_w as f64;
            let scale_h = h as f64 / orig_h as f64;
            let scale = match fit {
                ResizeFit::Contain | ResizeFit::Inside => scale_w.min(scale_h),
                ResizeFit::Outside => scale_w.max(scale_h),
                ResizeFit::Cover => return (w, h), // exact target after cover-crop
                ResizeFit::Fill => unreachable!(),
            };
            // `inside`: never enlarge.
            let scale = if matches!(fit, ResizeFit::Inside) {
                scale.min(1.0)
            } else {
                scale
            };
            (
                ((orig_w as f64) * scale).round().max(1.0) as u32,
                ((orig_h as f64) * scale).round().max(1.0) as u32,
            )
        }
        (None, None, _) => (orig_w, orig_h),
    }
}

/// For Cover: resize to ≥ both target dims (then crop center).
fn cover_dims(orig_w: u32, orig_h: u32, tw: u32, th: u32) -> (u32, u32) {
    let scale_w = tw as f64 / orig_w as f64;
    let scale_h = th as f64 / orig_h as f64;
    let scale = scale_w.max(scale_h);
    (
        ((orig_w as f64) * scale).round().max(tw as f64) as u32,
        ((orig_h as f64) * scale).round().max(th as f64) as u32,
    )
}

// ----- encode -------------------------------------------------------------

fn encode_output(img: &DynamicImage, output: &Output) -> Result<Vec<u8>, String> {
    match output {
        Output::Jpeg { quality } => {
            let mut buf = Vec::new();
            let encoder = JpegEncoder::new_with_quality(&mut buf, *quality);
            // Preserve grayscale input - JPEG natively encodes 1-channel
            // luma, and downstream code that ran `.grayscale()`
            // expects the result to stay grayscale. RGB(A) input
            // flattens to RGB8 (JPEG can't carry alpha).
            match img {
                DynamicImage::ImageLuma8(luma) => {
                    luma.write_with_encoder(encoder)
                        .map_err(|e| format!("sharp.jpeg: encode: {e}"))?;
                }
                _ => {
                    let rgb = img.to_rgb8();
                    rgb.write_with_encoder(encoder)
                        .map_err(|e| format!("sharp.jpeg: encode: {e}"))?;
                }
            }
            Ok(buf)
        }
        Output::Png { compression: _ } => {
            // image's PNG encoder doesn't expose level knobs in 0.25;
            // we accept the parameter but use the default zlib level.
            // Quality knobs are in the same place a future libpng-port
            // would land if we ever care.
            let mut buf = Vec::new();
            let encoder = PngEncoder::new(&mut buf);
            img.write_with_encoder(encoder)
                .map_err(|e| format!("sharp.png: encode: {e}"))?;
            Ok(buf)
        }
        Output::Webp {
            quality: _,
            lossless: _,
        } => {
            // image 0.25's WebPEncoder is lossless-only; we accept
            // both knobs in the API for parity but always emit
            // lossless WebP. A future swap to image-webp's lossy
            // path would honor `quality`.
            let mut buf = Vec::new();
            let encoder = WebPEncoder::new_lossless(&mut buf);
            img.write_with_encoder(encoder)
                .map_err(|e| format!("sharp.webp: encode: {e}"))?;
            Ok(buf)
        }
        Output::Metadata => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, Rgba};

    /// Generate a 32×24 PNG with a red→blue gradient as a fixture.
    fn fixture_png_rgb() -> Vec<u8> {
        let buf = ImageBuffer::from_fn(32, 24, |x, _y| {
            let t = (x as f32 / 31.0 * 255.0) as u8;
            Rgb([255 - t, 0, t])
        });
        let img = DynamicImage::ImageRgb8(buf);
        encode_output(&img, &Output::Png { compression: 6 }).unwrap()
    }

    /// 16×16 RGBA fixture with a checkerboard alpha pattern, useful
    /// for testing alpha preservation across resize/format flips.
    fn fixture_png_rgba() -> Vec<u8> {
        let buf = ImageBuffer::from_fn(16, 16, |x, y| {
            let a = if (x / 4 + y / 4) % 2 == 0 { 255 } else { 0 };
            Rgba([0, 128, 200, a])
        });
        let img = DynamicImage::ImageRgba8(buf);
        encode_output(&img, &Output::Png { compression: 6 }).unwrap()
    }

    fn run_pipeline_rgb(ops: Vec<Op>, output: Output) -> Result<Vec<u8>, String> {
        let p = Pipeline {
            source: Source::Buffer(fixture_png_rgb()),
            ops,
            output,
        };
        let mut img = decode_source(&p.source)?;
        for op in &p.ops {
            img = apply_op(img, op)?;
        }
        encode_output(&img, &p.output)
    }

    // ----- decode + metadata ------------------------------------------

    #[test]
    fn decodes_png_rgb_round_trip() {
        let bytes = fixture_png_rgb();
        let img = decode_source(&Source::Buffer(bytes)).expect("decode");
        assert_eq!(img.dimensions(), (32, 24));
    }

    #[test]
    fn metadata_reports_dims_format_channels() {
        let src_json = serde_json::json!({
            "kind": "buffer",
            "data_b64": base64::engine::general_purpose::STANDARD.encode(fixture_png_rgb()),
        });
        let raw = metadata(&src_json.to_string()).expect("metadata");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["width"], 32);
        assert_eq!(v["height"], 24);
        assert_eq!(v["format"], "png");
        assert_eq!(v["channels"], 3);
        assert_eq!(v["hasAlpha"], false);
    }

    #[test]
    fn metadata_rgba_reports_alpha() {
        let src_json = serde_json::json!({
            "kind": "buffer",
            "data_b64": base64::engine::general_purpose::STANDARD.encode(fixture_png_rgba()),
        });
        let raw = metadata(&src_json.to_string()).expect("metadata");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["width"], 16);
        assert_eq!(v["height"], 16);
        assert_eq!(v["channels"], 4);
        assert_eq!(v["hasAlpha"], true);
    }

    #[test]
    fn metadata_invalid_bytes_errors() {
        let src_json = serde_json::json!({
            "kind": "buffer",
            "data_b64": base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]),
        });
        let r = metadata(&src_json.to_string());
        assert!(r.is_err());
    }

    // ----- resize --------------------------------------------------

    #[test]
    fn resize_exact_dimensions_with_fill() {
        let bytes = run_pipeline_rgb(
            vec![Op::Resize(ResizeOpts {
                width: Some(64),
                height: Some(32),
                fit: ResizeFit::Fill,
                kernel: ResizeKernel::Lanczos3,
            })],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (64, 32));
    }

    #[test]
    fn resize_only_width_preserves_aspect() {
        // 32x24 → width=8 → height = 8 * 24/32 = 6
        let bytes = run_pipeline_rgb(
            vec![Op::Resize(ResizeOpts {
                width: Some(8),
                height: None,
                fit: ResizeFit::Cover,
                kernel: ResizeKernel::Lanczos3,
            })],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (8, 6));
    }

    #[test]
    fn resize_only_height_preserves_aspect() {
        // 32x24 → height=12 → width = 12 * 32/24 = 16
        let bytes = run_pipeline_rgb(
            vec![Op::Resize(ResizeOpts {
                width: None,
                height: Some(12),
                fit: ResizeFit::Cover,
                kernel: ResizeKernel::Lanczos3,
            })],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (16, 12));
    }

    #[test]
    fn resize_contain_fits_within_box() {
        // 32x24 → fit=contain into 8x8 → scale = 8/32 = 0.25 → 8x6
        let bytes = run_pipeline_rgb(
            vec![Op::Resize(ResizeOpts {
                width: Some(8),
                height: Some(8),
                fit: ResizeFit::Contain,
                kernel: ResizeKernel::Lanczos3,
            })],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        let (w, h) = img.dimensions();
        assert!(w <= 8 && h <= 8);
        assert!(w == 8 || h == 8, "at least one dim should reach the box");
    }

    #[test]
    fn resize_cover_crops_to_exact() {
        // Cover with both dims → exact output dimensions.
        let bytes = run_pipeline_rgb(
            vec![Op::Resize(ResizeOpts {
                width: Some(20),
                height: Some(20),
                fit: ResizeFit::Cover,
                kernel: ResizeKernel::Lanczos3,
            })],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (20, 20));
    }

    #[test]
    fn resize_inside_does_not_enlarge() {
        // 32x24 → fit=inside, ask for 100x100. Should stay at 32x24.
        let bytes = run_pipeline_rgb(
            vec![Op::Resize(ResizeOpts {
                width: Some(100),
                height: Some(100),
                fit: ResizeFit::Inside,
                kernel: ResizeKernel::Lanczos3,
            })],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (32, 24));
    }

    #[test]
    fn resize_zero_dim_rejected() {
        let r = run_pipeline_rgb(
            vec![Op::Resize(ResizeOpts {
                width: Some(0),
                height: None,
                fit: ResizeFit::Cover,
                kernel: ResizeKernel::Lanczos3,
            })],
            Output::Png { compression: 6 },
        );
        // The runner detects via apply_resize.
        assert!(r.is_err());
    }

    // ----- per-pixel ops ------------------------------------------

    #[test]
    fn rotate_90_swaps_dimensions() {
        let bytes = run_pipeline_rgb(vec![Op::Rotate(90)], Output::Png { compression: 6 })
            .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        // 32x24 → 24x32 after 90° rotation.
        assert_eq!(img.dimensions(), (24, 32));
    }

    #[test]
    fn rotate_180_keeps_dimensions() {
        let bytes = run_pipeline_rgb(vec![Op::Rotate(180)], Output::Png { compression: 6 })
            .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (32, 24));
    }

    #[test]
    fn rotate_negative_degrees_normalized() {
        // -90° == 270° → swap dimensions.
        let bytes = run_pipeline_rgb(vec![Op::Rotate(-90)], Output::Png { compression: 6 })
            .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (24, 32));
    }

    #[test]
    fn grayscale_drops_color() {
        let bytes = run_pipeline_rgb(vec![Op::Grayscale], Output::Png { compression: 6 })
            .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        // Grayscale image → 1-channel.
        assert_eq!(img.color().channel_count(), 1);
    }

    #[test]
    fn flip_preserves_dimensions() {
        let bytes =
            run_pipeline_rgb(vec![Op::Flip], Output::Png { compression: 6 }).expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (32, 24));
    }

    #[test]
    fn flop_preserves_dimensions() {
        let bytes =
            run_pipeline_rgb(vec![Op::Flop], Output::Png { compression: 6 }).expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (32, 24));
    }

    #[test]
    fn negate_inverts_pixels() {
        let original = run_pipeline_rgb(vec![], Output::Png { compression: 6 }).expect("orig");
        let negated =
            run_pipeline_rgb(vec![Op::Negate], Output::Png { compression: 6 }).expect("negated");
        // Same dimensions, different bytes.
        let orig_img = image::load_from_memory(&original).expect("orig");
        let neg_img = image::load_from_memory(&negated).expect("neg");
        assert_eq!(orig_img.dimensions(), neg_img.dimensions());
        assert_ne!(
            orig_img.into_rgb8().into_raw(),
            neg_img.into_rgb8().into_raw()
        );
    }

    #[test]
    fn extract_returns_specified_region() {
        let bytes = run_pipeline_rgb(
            vec![Op::Extract(Extract {
                left: 4,
                top: 2,
                width: 8,
                height: 6,
            })],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (8, 6));
    }

    #[test]
    fn extract_outside_bounds_errors() {
        let r = run_pipeline_rgb(
            vec![Op::Extract(Extract {
                left: 30,
                top: 0,
                width: 10,
                height: 5,
            })],
            Output::Png { compression: 6 },
        );
        assert!(r.is_err());
    }

    #[test]
    fn blur_keeps_dimensions() {
        let bytes = run_pipeline_rgb(vec![Op::Blur(2.0)], Output::Png { compression: 6 })
            .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (32, 24));
    }

    // ----- format conversion --------------------------------------

    #[test]
    fn png_to_jpeg_round_trip() {
        let bytes = run_pipeline_rgb(vec![], Output::Jpeg { quality: 80 }).expect("pipeline");
        // JPEG magic.
        assert_eq!(&bytes[..3], b"\xff\xd8\xff");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (32, 24));
    }

    #[test]
    fn png_to_webp_round_trip() {
        let bytes = run_pipeline_rgb(
            vec![],
            Output::Webp {
                quality: 80,
                lossless: true,
            },
        )
        .expect("pipeline");
        // RIFF magic at the start, WEBP at offset 8.
        assert_eq!(&bytes[..4], b"RIFF");
        assert_eq!(&bytes[8..12], b"WEBP");
    }

    #[test]
    fn rgba_to_jpeg_drops_alpha() {
        // JPEG can't carry alpha; encoder should flatten without
        // crashing on a 4-channel input.
        let p = Pipeline {
            source: Source::Buffer(fixture_png_rgba()),
            ops: vec![],
            output: Output::Jpeg { quality: 80 },
        };
        let img = decode_source(&p.source).expect("decode");
        let bytes = encode_output(&img, &p.output).expect("encode");
        assert_eq!(&bytes[..3], b"\xff\xd8\xff");
        let decoded = image::load_from_memory(&bytes).expect("decode jpeg");
        assert_eq!(decoded.dimensions(), (16, 16));
    }

    #[test]
    fn jpeg_quality_affects_output_size() {
        let high = run_pipeline_rgb(vec![], Output::Jpeg { quality: 95 }).expect("hi");
        let low = run_pipeline_rgb(vec![], Output::Jpeg { quality: 10 }).expect("lo");
        // Lower quality should produce a smaller (or equal) file. We
        // assert strictly smaller to catch a no-op encoder.
        assert!(
            low.len() < high.len(),
            "low={} high={}",
            low.len(),
            high.len()
        );
    }

    // ----- chained pipelines --------------------------------------

    #[test]
    fn chained_resize_grayscale_jpeg() {
        let bytes = run_pipeline_rgb(
            vec![
                Op::Resize(ResizeOpts {
                    width: Some(16),
                    height: Some(12),
                    fit: ResizeFit::Fill,
                    kernel: ResizeKernel::Lanczos3,
                }),
                Op::Grayscale,
            ],
            Output::Jpeg { quality: 80 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (16, 12));
    }

    #[test]
    fn chained_rotate_extract() {
        let bytes = run_pipeline_rgb(
            vec![
                // 32x24 → rotate90 → 24x32
                Op::Rotate(90),
                // Now extract a region within the rotated bounds.
                Op::Extract(Extract {
                    left: 4,
                    top: 8,
                    width: 16,
                    height: 16,
                }),
            ],
            Output::Png { compression: 6 },
        )
        .expect("pipeline");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (16, 16));
    }

    // ----- parsing -----------------------------------------------

    #[test]
    fn parse_pipeline_minimum_shape() {
        let json = serde_json::json!({
            "source": { "kind": "buffer", "data_b64": "" },
            "ops": [],
            "output": { "format": "png" },
        });
        let p = parse_pipeline(&json.to_string()).expect("parse");
        assert!(matches!(p.source, Source::Buffer(_)));
        assert!(p.ops.is_empty());
        assert!(matches!(p.output, Output::Png { .. }));
    }

    #[test]
    fn parse_pipeline_unknown_op_rejected() {
        let json = serde_json::json!({
            "source": { "kind": "buffer", "data_b64": "" },
            "ops": [{ "op": "voodoo" }],
            "output": { "format": "png" },
        });
        let r = parse_pipeline(&json.to_string());
        assert!(r.is_err());
    }

    #[test]
    fn parse_pipeline_unknown_format_rejected() {
        let json = serde_json::json!({
            "source": { "kind": "buffer", "data_b64": "" },
            "ops": [],
            "output": { "format": "raw" },
        });
        let r = parse_pipeline(&json.to_string());
        assert!(r.is_err());
    }

    #[test]
    fn parse_pipeline_missing_source_rejected() {
        let json = serde_json::json!({
            "ops": [],
            "output": { "format": "png" },
        });
        let r = parse_pipeline(&json.to_string());
        assert!(r.is_err());
    }

    #[test]
    fn parse_resize_arbitrary_rotate_rejected() {
        let json = serde_json::json!({
            "source": { "kind": "buffer", "data_b64": "" },
            "ops": [{ "op": "rotate", "degrees": 45 }],
            "output": { "format": "png" },
        });
        let r = parse_pipeline(&json.to_string());
        assert!(r.is_err());
    }

    // ----- run() entry point public surface -----------------------

    #[test]
    fn run_full_pipeline_via_public_entry() {
        let json = serde_json::json!({
            "source": {
                "kind": "buffer",
                "data_b64": base64::engine::general_purpose::STANDARD.encode(fixture_png_rgb()),
            },
            "ops": [
                { "op": "resize", "width": 16, "height": 16, "fit": "fill" },
                { "op": "grayscale" },
            ],
            "output": { "format": "png" },
        });
        let bytes = run(&json.to_string()).expect("run");
        let img = image::load_from_memory(&bytes).expect("decode");
        assert_eq!(img.dimensions(), (16, 16));
        assert_eq!(img.color().channel_count(), 1);
    }
}
