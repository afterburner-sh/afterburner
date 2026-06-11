// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![allow(non_snake_case)]
//! L3 shadow for `sharp` - end-to-end integration coverage.
//!
//! Each test runs a small JS program through `burn` that exercises
//! the polyfill's surface against in-memory image fixtures generated
//! by the `image` crate. The shadow's Rust runtime + polyfill
//! together cover the operations real `sharp` users hit:
//!
//! * Metadata extraction
//! * Resize (default fit, fit options, kernel options, single-axis)
//! * Format conversion (PNG ↔ JPEG ↔ WebP)
//! * Per-pixel ops (rotate, grayscale, flip/flop, negate, extract,
//!   blur)
//! * Chained pipelines
//! * `toBuffer` / `toFile` / `metadata` terminal operations
//! * Error paths: invalid input, unsupported op params, missing
//!   format, file-write failures, unsupported-method errors

#![cfg(feature = "shadow-sharp")]

use base64::Engine as _;
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb, Rgba};
use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// 32×24 RGB gradient PNG. Encoded once per test invocation.
fn fixture_png_rgb() -> Vec<u8> {
    let buf: ImageBuffer<Rgb<u8>, _> = ImageBuffer::from_fn(32, 24, |x, _y| {
        let t = (x as f32 / 31.0 * 255.0) as u8;
        Rgb([255 - t, 0, t])
    });
    let img = DynamicImage::ImageRgb8(buf);
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .expect("encode png");
    out
}

/// 16×16 RGBA fixture with checker alpha - for alpha-preservation tests.
fn fixture_png_rgba() -> Vec<u8> {
    let buf: ImageBuffer<Rgba<u8>, _> = ImageBuffer::from_fn(16, 16, |x, y| {
        let a = if (x / 4 + y / 4) % 2 == 0 { 255 } else { 0 };
        Rgba([0, 128, 200, a])
    });
    let img = DynamicImage::ImageRgba8(buf);
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .expect("encode png");
    out
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Build a JS program that loads a Buffer fixture from a base64
/// constant and runs the user's pipeline. The pipeline body is
/// inserted verbatim at `// USER`.
fn js_with_fixture(fixture_b64: &str, pipeline_body: &str) -> String {
    format!(
        r#"
            const sharp = require('sharp');
            const {{ Buffer }} = require('buffer');
            const FIXTURE = Buffer.from('{fixture_b64}', 'base64');
            (async () => {{
                try {{
                    {pipeline_body}
                }} catch (e) {{
                    console.error('threw:', e && e.message || e);
                    process.exit(2);
                }}
            }})();
            setTimeout(() => {{ console.error('TIMEOUT'); process.exit(99); }}, 8000);
        "#
    )
}

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", source])
        .output()
        .expect("spawn burn")
}

fn assert_ok(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(marker),
        "missing `{marker}`. stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ----- metadata --------------------------------------------------------

#[test]
#[serial]
fn metadata_reports_dimensions_and_format() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const m = await sharp(FIXTURE).metadata();
            if (m.width !== 32 || m.height !== 24) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            if (m.format !== 'png') { console.error('format:', m.format); process.exit(4); }
            if (m.channels !== 3) { console.error('channels:', m.channels); process.exit(5); }
            if (m.hasAlpha !== false) { console.error('alpha:', m.hasAlpha); process.exit(6); }
            console.log('META_OK ' + m.width + 'x' + m.height + ' ' + m.format);
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "META_OK 32x24 png");
}

#[test]
#[serial]
fn metadata_rgba_reports_alpha_channel() {
    let png = fixture_png_rgba();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const m = await sharp(FIXTURE).metadata();
            if (m.channels !== 4 || m.hasAlpha !== true) {
                console.error('alpha shape:', JSON.stringify(m)); process.exit(3);
            }
            console.log('RGBA_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "RGBA_OK");
}

// ----- resize ---------------------------------------------------------

#[test]
#[serial]
fn resize_exact_dimensions_with_fill() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).resize(64, 32, { fit: 'fill' }).png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 64 || m.height !== 32) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('RESIZE_FILL_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "RESIZE_FILL_OK");
}

#[test]
#[serial]
fn resize_only_width_preserves_aspect() {
    let png = fixture_png_rgb();
    // 32x24 → width=8 → height = 8 * 24/32 = 6
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).resize(8).png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 8 || m.height !== 6) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('RESIZE_WIDTH_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "RESIZE_WIDTH_OK");
}

#[test]
#[serial]
fn resize_with_options_object() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE)
                .resize({ width: 16, height: 12, fit: 'fill', kernel: 'nearest' })
                .png()
                .toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 16 || m.height !== 12) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('RESIZE_OPTS_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "RESIZE_OPTS_OK");
}

#[test]
#[serial]
fn resize_inside_does_not_enlarge() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE)
                .resize({ width: 100, height: 100, fit: 'inside' })
                .png()
                .toBuffer();
            const m = await sharp(out).metadata();
            // Source is 32×24; fit=inside should keep that.
            if (m.width !== 32 || m.height !== 24) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('INSIDE_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "INSIDE_OK");
}

#[test]
#[serial]
fn resize_cover_produces_exact_box() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE)
                .resize({ width: 20, height: 20, fit: 'cover' })
                .png()
                .toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 20 || m.height !== 20) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('COVER_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "COVER_OK");
}

#[test]
#[serial]
fn resize_zero_dim_rejected() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            try {
                const out = await sharp(FIXTURE).resize(0).png().toBuffer();
                console.error('expected reject'); process.exit(3);
            } catch (e) {
                if (!/dimensions must be|positive|> 0/i.test(e.message)) {
                    console.error('wrong msg:', e.message); process.exit(4);
                }
                console.log('ZERO_REJECTED');
                process.exit(0);
            }
        "#,
    );
    assert_ok(&run_inline(&src), "ZERO_REJECTED");
}

// ----- format conversion ----------------------------------------------

#[test]
#[serial]
fn png_to_jpeg_round_trip() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).jpeg({ quality: 80 }).toBuffer();
            // JPEG SOI marker.
            if (out[0] !== 0xff || out[1] !== 0xd8 || out[2] !== 0xff) {
                console.error('not JPEG:', out.slice(0, 4).toString('hex')); process.exit(3);
            }
            const m = await sharp(out).metadata();
            if (m.format !== 'jpeg' || m.width !== 32 || m.height !== 24) {
                console.error('jpeg meta:', JSON.stringify(m)); process.exit(4);
            }
            console.log('JPEG_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "JPEG_OK");
}

#[test]
#[serial]
fn png_to_webp_round_trip() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).webp({ lossless: true }).toBuffer();
            if (out.slice(0, 4).toString('utf8') !== 'RIFF' ||
                out.slice(8, 12).toString('utf8') !== 'WEBP') {
                console.error('not WebP'); process.exit(3);
            }
            console.log('WEBP_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "WEBP_OK");
}

#[test]
#[serial]
fn jpeg_low_quality_smaller_than_high() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const hi = await sharp(FIXTURE).jpeg({ quality: 95 }).toBuffer();
            const lo = await sharp(FIXTURE).jpeg({ quality: 10 }).toBuffer();
            if (lo.length >= hi.length) {
                console.error('lo=', lo.length, 'hi=', hi.length); process.exit(3);
            }
            console.log('QUALITY_OK lo=' + lo.length + ' hi=' + hi.length);
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "QUALITY_OK");
}

#[test]
#[serial]
fn rgba_input_to_jpeg_drops_alpha() {
    let png = fixture_png_rgba();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).jpeg().toBuffer();
            const m = await sharp(out).metadata();
            if (m.hasAlpha !== false) {
                console.error('JPEG retained alpha'); process.exit(3);
            }
            console.log('ALPHA_DROPPED');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "ALPHA_DROPPED");
}

#[test]
#[serial]
fn toFormat_dispatches_by_string() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).toFormat('jpeg', { quality: 60 }).toBuffer();
            if (out[0] !== 0xff || out[1] !== 0xd8) {
                console.error('not JPEG'); process.exit(3);
            }
            console.log('TO_FORMAT_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "TO_FORMAT_OK");
}

// ----- per-pixel ops --------------------------------------------------

#[test]
#[serial]
fn rotate_90_swaps_dimensions() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).rotate(90).png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 24 || m.height !== 32) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('ROTATE_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "ROTATE_OK");
}

#[test]
#[serial]
fn rotate_arbitrary_degrees_rejected() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            try {
                const out = await sharp(FIXTURE).rotate(45).png().toBuffer();
                console.error('expected reject'); process.exit(3);
            } catch (e) {
                if (!/multiples? of 90|0\/90\/180\/270/i.test(e.message)) {
                    console.error('wrong msg:', e.message); process.exit(4);
                }
                console.log('ROTATE_REJECTED');
                process.exit(0);
            }
        "#,
    );
    assert_ok(&run_inline(&src), "ROTATE_REJECTED");
}

#[test]
#[serial]
fn grayscale_drops_to_one_channel() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).grayscale().png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.channels !== 1) {
                console.error('channels:', m.channels); process.exit(3);
            }
            console.log('GRAY_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "GRAY_OK");
}

#[test]
#[serial]
fn greyscale_alias_works() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).greyscale().png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.channels !== 1) {
                console.error('channels:', m.channels); process.exit(3);
            }
            console.log('GREY_ALIAS_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "GREY_ALIAS_OK");
}

#[test]
#[serial]
fn flip_preserves_dims() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).flip().png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 32 || m.height !== 24) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('FLIP_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "FLIP_OK");
}

#[test]
#[serial]
fn flop_preserves_dims() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).flop().png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 32 || m.height !== 24) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('FLOP_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "FLOP_OK");
}

#[test]
#[serial]
fn negate_changes_pixels() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const orig = await sharp(FIXTURE).png().toBuffer();
            const neg  = await sharp(FIXTURE).negate().png().toBuffer();
            // Same dimensions, different bytes.
            const om = await sharp(orig).metadata();
            const nm = await sharp(neg).metadata();
            if (om.width !== nm.width || om.height !== nm.height) {
                console.error('dim mismatch'); process.exit(3);
            }
            if (orig.equals(neg)) {
                console.error('negate produced identical bytes'); process.exit(4);
            }
            console.log('NEGATE_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "NEGATE_OK");
}

#[test]
#[serial]
fn extract_returns_specified_region() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE)
                .extract({ left: 4, top: 2, width: 8, height: 6 })
                .png()
                .toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 8 || m.height !== 6) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('EXTRACT_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "EXTRACT_OK");
}

#[test]
#[serial]
fn extract_outside_bounds_rejects() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            try {
                const out = await sharp(FIXTURE)
                    .extract({ left: 30, top: 0, width: 10, height: 5 })
                    .png()
                    .toBuffer();
                console.error('expected reject'); process.exit(3);
            } catch (e) {
                if (!/outside|extract/i.test(e.message)) {
                    console.error('wrong msg:', e.message); process.exit(4);
                }
                console.log('EXTRACT_OOB_OK');
                process.exit(0);
            }
        "#,
    );
    assert_ok(&run_inline(&src), "EXTRACT_OOB_OK");
}

#[test]
#[serial]
fn blur_keeps_dimensions() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE).blur(2.0).png().toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 32 || m.height !== 24) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('BLUR_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "BLUR_OK");
}

// ----- chained pipelines ----------------------------------------------

#[test]
#[serial]
fn chained_resize_grayscale_jpeg() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE)
                .resize(16, 12, { fit: 'fill' })
                .grayscale()
                .jpeg({ quality: 60 })
                .toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 16 || m.height !== 12 || m.format !== 'jpeg' || m.channels !== 1) {
                console.error('chain meta:', JSON.stringify(m)); process.exit(3);
            }
            console.log('CHAIN_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "CHAIN_OK");
}

#[test]
#[serial]
fn chained_rotate_extract_negate() {
    let png = fixture_png_rgb();
    let src = js_with_fixture(
        &b64(&png),
        r#"
            const out = await sharp(FIXTURE)
                .rotate(90)
                .extract({ left: 4, top: 8, width: 16, height: 16 })
                .negate()
                .png()
                .toBuffer();
            const m = await sharp(out).metadata();
            if (m.width !== 16 || m.height !== 16) {
                console.error('dims:', m.width, m.height); process.exit(3);
            }
            console.log('CHAIN_ROT_OK');
            process.exit(0);
        "#,
    );
    assert_ok(&run_inline(&src), "CHAIN_ROT_OK");
}

// ----- toFile ---------------------------------------------------------

#[test]
#[serial]
fn to_file_writes_real_image_to_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("burn-shadow-out.png");
    let path_str = out_path.to_string_lossy().into_owned();

    let png = fixture_png_rgb();
    let src = format!(
        r#"
            const sharp = require('sharp');
            const {{ Buffer }} = require('buffer');
            const fs = require('fs');
            const FIXTURE = Buffer.from('{fixture}', 'base64');
            (async () => {{
                try {{
                    const info = await sharp(FIXTURE)
                        .resize(8, 6, {{ fit: 'fill' }})
                        .png()
                        .toFile({path:?});
                    if (info.format !== 'png' || info.width !== 8 || info.height !== 6) {{
                        console.error('info:', JSON.stringify(info)); process.exit(3);
                    }}
                    const onDisk = fs.readFileSync({path:?});
                    if (onDisk.length !== info.size) {{
                        console.error('size mismatch'); process.exit(4);
                    }}
                    const m = await sharp(onDisk).metadata();
                    if (m.width !== 8 || m.height !== 6) {{
                        console.error('reread:', JSON.stringify(m)); process.exit(5);
                    }}
                    console.log('TO_FILE_OK size=' + info.size);
                    process.exit(0);
                }} catch (e) {{
                    console.error('threw:', e.message); process.exit(2);
                }}
            }})();
            setTimeout(() => {{ console.error('TIMEOUT'); process.exit(99); }}, 8000);
        "#,
        fixture = b64(&png),
        path = path_str
    );
    assert_ok(&run_inline(&src), "TO_FILE_OK");
    assert!(out_path.exists(), "output file missing");
}

// ----- error paths ----------------------------------------------------

#[test]
#[serial]
fn invalid_image_bytes_reject() {
    let src = r#"
        const sharp = require('sharp');
        const { Buffer } = require('buffer');
        (async () => {
            try {
                const m = await sharp(Buffer.from([1, 2, 3, 4])).metadata();
                console.error('expected reject'); process.exit(3);
            } catch (e) {
                if (e.code !== 'ERR_SHADOW_SHARP') {
                    console.error('wrong code:', e.code); process.exit(4);
                }
                console.log('INVALID_OK');
                process.exit(0);
            }
        })();
        setTimeout(() => process.exit(99), 30000);
    "#;
    assert_ok(&run_inline(src), "INVALID_OK");
}

#[test]
#[serial]
fn input_must_be_buffer_or_path() {
    let src = r#"
        const sharp = require('sharp');
        try {
            sharp(12345); // numeric - invalid
            console.error('expected throw'); process.exit(3);
        } catch (e) {
            if (!/Buffer|Uint8Array|path/i.test(e.message)) {
                console.error('wrong msg:', e.message); process.exit(4);
            }
            console.log('INPUT_TYPE_OK');
            process.exit(0);
        }
    "#;
    assert_ok(&run_inline(src), "INPUT_TYPE_OK");
}

#[test]
#[serial]
fn composite_queues_and_round_trips_through_pipeline() {
    // `composite(layers)` queues the op and is part of the
    // chainable surface; the rust shadow executes it on the
    // pipeline run. Empty `layers` is a no-op overlay set -
    // toBuffer() resolves with the unchanged base image.
    let src = r#"
        const sharp = require('sharp');
        const { Buffer } = require('buffer');
        const png = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==',
            'base64'
        );
        (async () => {
            try {
                const chain = sharp(png).composite([]);
                if (typeof chain.toBuffer !== 'function') {
                    console.error('composite did not return chainable');
                    process.exit(2);
                }
                const out = await chain.toBuffer();
                if (!Buffer.isBuffer(out) || out.length === 0) {
                    console.error('toBuffer empty / non-buffer:', typeof out, out && out.length);
                    process.exit(3);
                }
                console.log('COMPOSITE_OK');
                process.exit(0);
            } catch (e) {
                console.error('threw:', e && e.message);
                process.exit(4);
            }
        })();
    "#;
    assert_ok(&run_inline(src), "COMPOSITE_OK");
}

#[test]
#[serial]
fn module_exposes_constants_and_format_table() {
    let src = r#"
        const sharp = require('sharp');
        const checks = [
            typeof sharp === 'function',
            typeof sharp.cache === 'function',
            typeof sharp.format === 'object',
            !!sharp.format.png,
            !!sharp.format.jpeg,
            !!sharp.format.webp,
        ];
        if (checks.every(Boolean)) console.log('SHAPE_OK');
        else { console.error('checks:', checks); process.exit(2); }
    "#;
    assert_ok(&run_inline(src), "SHAPE_OK");
}

// ----- file path source ------------------------------------------------

#[test]
#[serial]
fn loading_from_file_path_works() {
    let dir = tempfile::tempdir().expect("tempdir");
    let in_path = dir.path().join("burn-shadow-in.png");
    let png = fixture_png_rgb();
    std::fs::write(&in_path, &png).expect("write fixture");
    let path_str = in_path.to_string_lossy().into_owned();

    let src = format!(
        r#"
            const sharp = require('sharp');
            (async () => {{
                try {{
                    const m = await sharp({path:?}).metadata();
                    if (m.width !== 32 || m.height !== 24) {{
                        console.error('dims:', m.width, m.height); process.exit(3);
                    }}
                    console.log('FILE_INPUT_OK');
                    process.exit(0);
                }} catch (e) {{
                    console.error('threw:', e.message); process.exit(2);
                }}
            }})();
            setTimeout(() => process.exit(99), 30000);
        "#,
        path = path_str
    );
    assert_ok(&run_inline(&src), "FILE_INPUT_OK");
}
