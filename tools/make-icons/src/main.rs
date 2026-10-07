//! Render brand PNGs plus favicon.ico from the SVG geometry.
//! Run from the repo root: `cargo run -p ssh-sentinel-icons`.
//! Writes frontend/public/: logo-512.png, apple-touch-icon.png (180),
//! favicon-32.png, favicon-16.png, favicon.ico (16/32/48 as PNG payloads).

use image::{ImageBuffer, ImageEncoder, Rgba, RgbaImage};

const TILE_A: [u8; 3] = [22, 35, 58];
const TILE_B: [u8; 3] = [10, 15, 28];
const RING: [u8; 3] = [44, 63, 88];
const SHIELD_A: [u8; 3] = [255, 123, 114];
const SHIELD_B: [u8; 3] = [194, 28, 52];
const PULSE: [u8; 3] = [63, 185, 80];
const KEY: [u8; 3] = [165, 214, 255];

const SHIELD: [(f32, f32); 10] = [
    (128.0, 36.0), (192.0, 60.0), (192.0, 128.0), (186.0, 160.0), (168.0, 186.0),
    (128.0, 220.0), (88.0, 186.0), (70.0, 160.0), (64.0, 128.0), (64.0, 60.0),
];
const PULSE_PTS: [(f32, f32); 6] = [
    (86.0, 128.0), (108.0, 128.0), (119.0, 102.0),
    (137.0, 154.0), (149.0, 128.0), (170.0, 128.0),
];

type Px = Rgba<u8>;

fn rgb(c: [u8; 3]) -> Px {
    Rgba([c[0], c[1], c[2], 255])
}

fn in_rounded(x: f32, y: f32, x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> bool {
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    let cx = x.clamp(x0 + r, x1 - r);
    let cy = y.clamp(y0 + r, y1 - r);
    let dx = x - cx;
    let dy = y - cy;
    dx * dx + dy * dy <= r * r
}

fn disk(img: &mut RgbaImage, cx: f32, cy: f32, rad: f32, c: Px) {
    let (w, h) = (img.width() as i32, img.height() as i32);
    let r = rad.ceil() as i32;
    for yy in (cy as i32 - r)..=(cy as i32 + r) {
        for xx in (cx as i32 - r)..=(cx as i32 + r) {
            if xx < 0 || yy < 0 || xx >= w || yy >= h {
                continue;
            }
            let dx = xx as f32 + 0.5 - cx;
            let dy = yy as f32 + 0.5 - cy;
            if dx * dx + dy * dy <= rad * rad {
                img.put_pixel(xx as u32, yy as u32, c);
            }
        }
    }
}

fn polyline(img: &mut RgbaImage, pts: &[(f32, f32)], width: f32, c: Px) {
    for w in pts.windows(2) {
        let (x0, y0) = w[0];
        let (x1, y1) = w[1];
        let len = ((x1 - x0).powi(2) + (y1 - y0).powi(2)).sqrt().max(0.001);
        let steps = (len * 2.0).ceil() as i32;
        for i in 0..=steps {
            let t = i as f32 / steps as f32;
            disk(img, x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, width / 2.0, c);
        }
    }
}

fn polygon(img: &mut RgbaImage, pts: &[(f32, f32)], c: Px) {
    // Even-odd scanline fill.
    let (w, h) = (img.width() as i32, img.height() as i32);
    let n = pts.len();
    for yy in 0..h {
        let y = yy as f32 + 0.5;
        let mut xs = vec![];
        for i in 0..n {
            let (x0, y0) = pts[i];
            let (x1, y1) = pts[(i + 1) % n];
            if (y0 <= y && y < y1) || (y1 <= y && y < y0) {
                xs.push(x0 + (y - y0) * (x1 - x0) / (y1 - y0));
            }
        }
        xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        for pair in xs.chunks(2) {
            if pair.len() < 2 {
                break;
            }
            for xx in (pair[0].ceil() as i32)..=(pair[1].floor() as i32) {
                if xx >= 0 && xx < w {
                    img.put_pixel(xx as u32, yy as u32, c);
                }
            }
        }
    }
}

fn render(s: u32, with_key: bool) -> RgbaImage {
    let k = s as f32 / 256.0;
    let mut img: RgbaImage = ImageBuffer::new(s, s);
    let x0 = 4.0 * k;
    let r = 60.0 * k;
    let x1 = 252.0 * k;
    for yy in 0..s {
        let t = yy as f32 / (s - 1).max(1) as f32;
        let base = Rgba([
            (TILE_A[0] as f32 * (1.0 - t) + TILE_B[0] as f32 * t) as u8,
            (TILE_A[1] as f32 * (1.0 - t) + TILE_B[1] as f32 * t) as u8,
            (TILE_A[2] as f32 * (1.0 - t) + TILE_B[2] as f32 * t) as u8,
            255,
        ]);
        for xx in 0..s {
            let x = xx as f32 + 0.5;
            let y = yy as f32 + 0.5;
            if in_rounded(x, y, x0, x0, x1, x1, r) {
                img.put_pixel(xx, yy, base);
            }
        }
    }
    // Ring outline: border pixels of the mask.
    let width = (4.0 * k).max(1.0);
    let mut edge = vec![];
    for yy in 0..s {
        for xx in 0..s {
            let x = xx as f32 + 0.5;
            let y = yy as f32 + 0.5;
            if !in_rounded(x, y, x0, x0, x1, x1, r) {
                continue;
            }
            let mut inner = true;
            let mut yy2 = yy.saturating_sub(width.ceil() as u32);
            while yy2 <= (yy + width.ceil() as u32).min(s - 1) {
                let mut xx2 = xx.saturating_sub(width.ceil() as u32);
                while xx2 <= (xx + width.ceil() as u32).min(s - 1) {
                    let dx = xx2 as f32 + 0.5 - x;
                    let dy = yy2 as f32 + 0.5 - y;
                    if dx * dx + dy * dy > width * width
                        || !in_rounded(xx2 as f32 + 0.5, yy2 as f32 + 0.5, x0, x0, x1, x1, r)
                    {
                        inner = false;
                        break;
                    }
                    xx2 += 1;
                }
                if !inner {
                    break;
                }
                yy2 += 1;
            }
            if !inner {
                edge.push((xx, yy));
            }
        }
    }
    for (xx, yy) in edge {
        img.put_pixel(xx, yy, rgb(RING));
    }
    // Shield: base pass plus highlight pass over the top arc.
    let sc = |p: (f32, f32)| (p.0 * k, p.1 * k);
    let shield_all: Vec<(f32, f32)> = SHIELD.iter().map(|p| sc(*p)).collect();
    let mut closed = shield_all.clone();
    closed.push(shield_all[0]);
    polyline(&mut img, &closed, (20.0 * k).max(2.0), rgb(SHIELD_B));
    polyline(&mut img, &shield_all[..4], (20.0 * k).max(2.0), rgb(SHIELD_A));
    // Pulse line.
    let pulse: Vec<(f32, f32)> = PULSE_PTS.iter().map(|p| sc(*p)).collect();
    polyline(&mut img, &pulse, (16.0 * k).max(2.0), rgb(PULSE));
    // Keyhole.
    if with_key {
        disk(&mut img, 128.0 * k, 168.0 * k, 11.0 * k, rgb(KEY));
        polygon(
            &mut img,
            &[(123.0 * k, 176.0 * k), (133.0 * k, 176.0 * k), (137.0 * k, 196.0 * k), (119.0 * k, 196.0 * k)],
            rgb(KEY),
        );
    }
    img
}

fn png_bytes(img: &RgbaImage) -> Vec<u8> {
    let mut buf = vec![];
    image::codecs::png::PngEncoder::new(&mut buf)
        .write_image(img.as_raw(), img.width(), img.height(), image::ExtendedColorType::Rgba8)
        .expect("png encode");
    buf
}

fn write_ico(path: &str, sizes: &[RgbaImage]) {
    // ICO container with PNG payloads.
    let mut out = vec![];
    out.extend([0u8, 0, 1, 0]);
    out.extend((sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + sizes.len() * 16;
    let mut payloads = vec![];
    for img in sizes {
        let png = png_bytes(img);
        let w = if img.width() >= 256 { 0 } else { img.width() as u8 };
        let h = if img.height() >= 256 { 0 } else { img.height() as u8 };
        out.push(w);
        out.push(h);
        out.push(0);
        out.push(0);
        out.extend([1u8, 0]);
        out.extend(32u16.to_le_bytes());
        out.extend((png.len() as u32).to_le_bytes());
        out.extend((offset as u32).to_le_bytes());
        offset += png.len();
        payloads.push(png);
    }
    for p in payloads {
        out.extend(p);
    }
    std::fs::write(path, out).expect("write ico");
}

fn main() {
    let out = "frontend/public";
    std::fs::create_dir_all(out).expect("out dir");
    let big = render(512, true);
    big.save(format!("{}/logo-512.png", out)).expect("logo");
    let touch = image::imageops::resize(&render(512, false), 180, 180, image::imageops::FilterType::Lanczos3);
    touch.save(format!("{}/apple-touch-icon.png", out)).expect("touch");
    let small = render(256, false);
    image::imageops::resize(&small, 32, 32, image::imageops::FilterType::Lanczos3)
        .save(format!("{}/favicon-32.png", out))
        .expect("f32");
    image::imageops::resize(&small, 16, 16, image::imageops::FilterType::Lanczos3)
        .save(format!("{}/favicon-16.png", out))
        .expect("f16");
    let i48 = image::imageops::resize(&small, 48, 48, image::imageops::FilterType::Lanczos3);
    let i32 = image::imageops::resize(&small, 32, 32, image::imageops::FilterType::Lanczos3);
    let i16 = image::imageops::resize(&small, 16, 16, image::imageops::FilterType::Lanczos3);
    write_ico(&format!("{}/favicon.ico", out), &[i16, i32, i48]);
    println!("icons written to {}", out);
}
