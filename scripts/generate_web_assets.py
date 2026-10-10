"""Generate production-ready web assets for CipherGuard:
- favicon.ico (multi-resolution ICO: 16x16, 32x32, 48x48, 64x64)
- apple-touch-icon.png (180x180)
- icon-192.png (192x192) & icon-512.png (512x512) for PWA webmanifest
- og-image.png (1200x630 high-resolution social card)

All assets use the Wire Ribbon mark:
Teal observed block + thin dark key-boundary seam bar + violet hatched inferred block.
"""

import os
from PIL import Image, ImageDraw, ImageFont

STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "cipherguard", "api", "static")
IMG_DIR = os.path.join(STATIC_DIR, "img")
os.makedirs(IMG_DIR, exist_ok=True)


def draw_wire_ribbon_icon(size=180):
    """Draw the authentic CipherGuard Wire Ribbon mark.

    Proportions match the 16x16 hand-written SVG grid:
    - Left: Teal block (observed cleartext wire parameters)
    - Center: Thin dark ink bar (cryptographic key boundary seam)
    - Right: Violet block with crisp diagonal hatch lines (inferred ciphertext)
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    # Proportional padding aligned to the 16x16 grid (1px X, 2px Y per 16 units)
    pad_x = size * (1.0 / 16.0)
    pad_y = size * (2.0 / 16.0)
    w = size - 2.0 * pad_x
    h = size - 2.0 * pad_y
    x0, y0 = pad_x, pad_y
    x1, y1 = x0 + w, y0 + h
    radius = max(2, int(round(size * (2.0 / 16.0))))

    # Exact seam and block dimensions
    seam_w = max(2, int(round(w * (2.0 / 14.0))))
    cx = size / 2.0
    seam_x0 = cx - seam_w / 2.0
    seam_x1 = cx + seam_w / 2.0

    # Color tokens matching CipherGuard theme
    teal = (27, 110, 140, 255)  # #1b6e8c (observed)
    ink = (20, 33, 43, 255)  # #14212b (dark seam bar)
    violet = (109, 78, 156, 255)  # #6d4e9c (inferred ciphertext)
    hatch_color = (216, 199, 240, 255)  # #d8c7f0 (light violet hatch stripes)

    # 1. Outer rounded container mask for smooth corner radius
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=255)

    # 2. Base content layers
    content = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    cdraw = ImageDraw.Draw(content)

    # Left: Teal block
    cdraw.rectangle([x0, y0, seam_x0, y1], fill=teal)

    # Right: Violet block
    cdraw.rectangle([seam_x1, y0, x1, y1], fill=violet)

    # 3. Violet block diagonal hatching (strictly clipped to right block)
    r_mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(r_mask).rectangle([seam_x1, y0, x1, y1], fill=255)

    hatch_img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    hdraw = ImageDraw.Draw(hatch_img)
    hw = max(1, int(round(size * (1.1 / 16.0))))
    spacing = max(3, int(round(size * (3.5 / 16.0))))

    # Draw diagonal lines at -45 deg slope across the right half
    for offset in range(-int(h * 1.5), int((x1 - seam_x1) + h * 1.5), spacing):
        p0 = (seam_x1 + offset, y1)
        p1 = (seam_x1 + offset + h, y0)
        hdraw.line([p0, p1], fill=hatch_color, width=hw)

    content.paste(hatch_img, (0, 0), r_mask)

    # 4. Center: Thin dark key-boundary seam bar
    cdraw.rectangle([seam_x0, y0, seam_x1, y1], fill=ink)

    # Composite content into rounded mask
    img.paste(content, (0, 0), mask)

    # 5. Subtle crisp perimeter border for high contrast in light & dark chrome
    border_w = max(1, int(round(size * (0.8 / 16.0))))
    ImageDraw.Draw(img).rounded_rectangle(
        [x0, y0, x1, y1],
        radius=radius,
        outline=(20, 33, 43, 90),
        width=border_w,
    )

    return img


# Backwards compatibility alias
draw_shield_icon = draw_wire_ribbon_icon


def generate_all():
    print("Generating CipherGuard web assets...")

    # 1. Apple touch icon (180x180)
    icon_180 = draw_wire_ribbon_icon(180)
    icon_180.save(os.path.join(IMG_DIR, "apple-touch-icon.png"), "PNG", optimize=True)
    print("  [OK] apple-touch-icon.png (180x180)")

    # 2. PWA icons (192x192 & 512x512)
    icon_192 = draw_wire_ribbon_icon(192)
    icon_192.save(os.path.join(IMG_DIR, "icon-192.png"), "PNG", optimize=True)
    icon_512 = draw_wire_ribbon_icon(512)
    icon_512.save(os.path.join(IMG_DIR, "icon-512.png"), "PNG", optimize=True)
    print("  [OK] icon-192.png & icon-512.png")

    # 3. Favicon.ico with multi-resolution bitmaps (16, 32, 48, 64)
    icon_180.save(
        os.path.join(STATIC_DIR, "favicon.ico"),
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64)],
    )
    print("  [OK] favicon.ico (16, 32, 48, 64)")

    # 4. Open Graph Card (1200x630)
    og = Image.new("RGB", (1200, 630), (15, 23, 42))
    og_draw = ImageDraw.Draw(og)

    # Subtle tech grid background
    for x in range(0, 1200, 40):
        og_draw.line([(x, 0), (x, 630)], fill=(24, 34, 48), width=1)
    for y in range(0, 630, 40):
        og_draw.line([(0, y), (1200, y)], fill=(24, 34, 48), width=1)

    # Accent boundary lines (Teal on top, Violet on bottom)
    og_draw.line([(0, 4), (1200, 4)], fill=(27, 110, 140), width=4)
    og_draw.line([(0, 626), (1200, 626)], fill=(109, 78, 156), width=4)

    # Place Wire Ribbon Mark on left
    ribbon_big = draw_wire_ribbon_icon(280)
    og.paste(ribbon_big, (80, 175), ribbon_big)

    # Typography
    try:
        font_title = ImageFont.truetype("arial.ttf", 68)
        font_sub = ImageFont.truetype("arial.ttf", 30)
        font_meta = ImageFont.truetype("arial.ttf", 20)
    except Exception:
        font_title = ImageFont.load_default()
        font_sub = ImageFont.load_default()
        font_meta = ImageFont.load_default()

    # Pill badge
    og_draw.rounded_rectangle([400, 140, 780, 178], radius=6, fill=(27, 45, 60), outline=(27, 110, 140), width=1)
    og_draw.text((415, 149), "NTRO SIH26160 • OFFENSIVE & DEFENSIVE SUITE", fill=(110, 190, 220), font=font_meta)

    # Main Title
    og_draw.text((400, 198), "CipherGuard", fill=(255, 255, 255), font=font_title)

    # Subtitle
    og_draw.text(
        (400, 285), "Passive IPsec Protocol & Live Wi-Fi Security Analyzer", fill=(148, 163, 184), font=font_sub
    )

    # Wire Ribbon Concept Caption
    og_draw.text(
        (400, 330),
        "Zero-Payload Wire Inspection: Observed Cleartext ↔ Cryptographic Seam ↔ Inferred Ciphertext",
        fill=(100, 130, 155),
        font=font_meta,
    )

    # Feature Badges
    badges = [
        ("🛡️ Zero-Payload Framing Inspection", (27, 110, 140)),
        ("🚨 Rogue AP & Evil Twin Hunter", (239, 68, 68)),
        ("⚡ NIST SP 800-77 & MITRE Compliance", (56, 189, 248)),
        ("🔐 Post-Quantum Cryptography Defense", (109, 78, 156)),
    ]

    bx = 400
    by = 375
    for i, (text, color) in enumerate(badges):
        col = i % 2
        row = i // 2
        x = bx + col * 370
        y = by + row * 55
        og_draw.rounded_rectangle([x, y, x + 350, y + 42], radius=6, fill=(24, 34, 48), outline=color, width=1)
        og_draw.text((x + 14, y + 10), text, fill=(241, 245, 249), font=font_meta)

    # Footer
    og_draw.text(
        (400, 540), "Self-Contained • Sovereign Cyber Security • Air-Gapped Ready", fill=(100, 116, 139), font=font_meta
    )

    og_path = os.path.join(IMG_DIR, "og-image.png")
    og.save(og_path, "PNG", optimize=True)
    print(f"  [OK] og-image.png ({og_path})")
    print("All web assets generated successfully!")


if __name__ == "__main__":
    generate_all()
