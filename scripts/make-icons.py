#!/usr/bin/env python3
"""Render brand PNGs from the SVG geometry (favicon + logo).

Run: python3 scripts/make-icons.py
Writes frontend/public/: logo-512.png, apple-touch-icon.png (180),
favicon-32.png, favicon-16.png, favicon.ico (16/32/48). Needs Pillow.
Source of truth for shapes: public/logo.svg, public/favicon.svg.
"""
import os

from PIL import Image, ImageDraw, ImageOps

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "frontend", "public")

TILE_A = (22, 35, 58)
TILE_B = (10, 15, 28)
RING = (44, 63, 88)
SHIELD_A = (255, 123, 114)
SHIELD_B = (194, 28, 52)
PULSE = (63, 185, 80)
KEY = (165, 214, 255)

SHIELD = [(128, 36), (192, 60), (192, 128), (186, 160), (168, 186),
          (128, 220), (88, 186), (70, 160), (64, 128), (64, 60)]
PULSE_PTS = [(86, 128), (108, 128), (119, 102), (137, 154), (149, 128), (170, 128)]


def base(s):
    # smooth vertical gradient tile with rounded corners (RGBA)
    grad = ImageOps.colorize(
        Image.linear_gradient("L").resize((1, 256)).resize((s, s)),
        black=TILE_A, white=TILE_B)
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [4 * s / 256, 4 * s / 256, 252 * s / 256, 252 * s / 256],
        radius=60 * s / 256, fill=255)
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(grad.convert("RGBA"), (0, 0), mask)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle(
        [4 * s / 256, 4 * s / 256, 252 * s / 256, 252 * s / 256],
        radius=60 * s / 256, outline=RING + (255,),
        width=max(1, int(4 * s / 256)))
    return img, d


def shield(draw, s):
    k = s / 256
    pts = [(x * k, y * k) for x, y in SHIELD]
    w = max(2, int(20 * k))
    draw.line(pts + [pts[0]], fill=SHIELD_B, width=w, joint="curve")
    # highlight pass over the top arc for the gradient feel
    draw.line(pts[:4], fill=SHIELD_A, width=w, joint="curve")


def pulse(draw, s):
    k = s / 256
    pts = [(x * k, y * k) for x, y in PULSE_PTS]
    draw.line(pts, fill=PULSE, width=max(2, int(16 * k)), joint="curve")


def keyhole(draw, s):
    k = s / 256
    r = 11 * k
    draw.ellipse([128 * k - r, 168 * k - r, 128 * k + r, 168 * k + r], fill=KEY)
    draw.polygon([(123 * k, 176 * k), (133 * k, 176 * k),
                  (137 * k, 196 * k), (119 * k, 196 * k)], fill=KEY)


def render(s, with_key):
    img, d = base(s)
    shield(d, s)
    pulse(d, s)
    if with_key:
        keyhole(d, s)
    return img


def main():
    os.makedirs(OUT, exist_ok=True)
    big = render(512, True)
    big.save(os.path.join(OUT, "logo-512.png"))
    render(512, False).resize((180, 180), Image.LANCZOS).save(
        os.path.join(OUT, "apple-touch-icon.png"))
    small = render(256, False)
    small.resize((32, 32), Image.LANCZOS).save(os.path.join(OUT, "favicon-32.png"))
    small.resize((16, 16), Image.LANCZOS).save(os.path.join(OUT, "favicon-16.png"))
    small.save(os.path.join(OUT, "favicon.ico"), sizes=[(16, 16), (32, 32), (48, 48)])
    print("icons written to", OUT)


if __name__ == "__main__":
    main()
