"""Generate production-ready web assets for CipherGuard:
- favicon.ico
- apple-touch-icon.png (180x180)
- og-image.png (1200x630 high-res social card)
"""

import os
from PIL import Image, ImageDraw, ImageFont

STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "cipherguard", "api", "static")
IMG_DIR = os.path.join(STATIC_DIR, "img")
os.makedirs(IMG_DIR, exist_ok=True)


def draw_shield_icon(size=180):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    pad = size * 0.08
    w = size - 2 * pad
    h = size - 2 * pad
    cx = size / 2

    # Draw shield polygon
    pts = [
        (cx, pad),
        (size - pad, pad + h * 0.22),
        (size - pad, pad + h * 0.55),
        (cx, size - pad),
        (pad, pad + h * 0.55),
        (pad, pad + h * 0.22),
    ]
    # Background shield
    draw.polygon(pts, fill=(15, 23, 42, 255), outline=(56, 189, 248, 255), width=max(2, int(size * 0.04)))

    # Inner lock / tech shapes
    lw = w * 0.35
    lh = h * 0.3
    lx0 = cx - lw / 2
    ly0 = pad + h * 0.45
    draw.rectangle(
        [lx0, ly0, lx0 + lw, ly0 + lh],
        fill=(2, 132, 199, 255),
        outline=(224, 242, 254, 255),
        width=max(1, int(size * 0.02)),
    )

    # Lock shackle
    shackle_pad = lw * 0.2
    sw = lw - 2 * shackle_pad
    draw.arc(
        [lx0 + shackle_pad, ly0 - sw * 0.9, lx0 + lw - shackle_pad, ly0 + sw * 0.4],
        180,
        0,
        fill=(224, 242, 254, 255),
        width=max(2, int(size * 0.035)),
    )

    # Keyhole
    draw.ellipse([cx - size * 0.03, ly0 + lh * 0.3, cx + size * 0.03, ly0 + lh * 0.5], fill=(15, 23, 42, 255))
    draw.rectangle([cx - size * 0.015, ly0 + lh * 0.45, cx + size * 0.015, ly0 + lh * 0.75], fill=(15, 23, 42, 255))

    # Wi-Fi arcs at top
    draw.arc(
        [cx - w * 0.25, pad + h * 0.15, cx + w * 0.25, pad + h * 0.45],
        200,
        340,
        fill=(56, 189, 248, 255),
        width=max(2, int(size * 0.03)),
    )
    draw.arc(
        [cx - w * 0.15, pad + h * 0.23, cx + w * 0.15, pad + h * 0.45],
        200,
        340,
        fill=(56, 189, 248, 255),
        width=max(2, int(size * 0.025)),
    )

    return img


# 1. Favicon.ico and apple-touch-icon.png
icon_180 = draw_shield_icon(180)
icon_180.save(os.path.join(IMG_DIR, "apple-touch-icon.png"), "PNG", optimize=True)

icon_32 = draw_shield_icon(32)
icon_16 = draw_shield_icon(16)
icon_48 = draw_shield_icon(48)
icon_180.save(
    os.path.join(STATIC_DIR, "favicon.ico"),
    format="ICO",
    sizes=[(16, 16), (32, 32), (48, 48), (64, 64)],
)

# 2. Open Graph Card (1200x630)
og = Image.new("RGB", (1200, 630), (15, 23, 42))
og_draw = ImageDraw.Draw(og)

# Background subtle tech grid lines
for x in range(0, 1200, 40):
    og_draw.line([(x, 0), (x, 630)], fill=(30, 41, 59), width=1)
for y in range(0, 630, 40):
    og_draw.line([(0, y), (1200, y)], fill=(30, 41, 59), width=1)

# Glowing accent lines
og_draw.line([(0, 626), (1200, 626)], fill=(56, 189, 248), width=4)
og_draw.line([(0, 4), (1200, 4)], fill=(16, 185, 129), width=4)

# Place shield icon on left
shield_big = draw_shield_icon(280)
og.paste(shield_big, (80, 175), shield_big)

# Draw Title & Typography
try:
    font_title = ImageFont.truetype("arial.ttf", 68)
    font_sub = ImageFont.truetype("arial.ttf", 32)
    font_tag = ImageFont.truetype("arial.ttf", 22)
    font_meta = ImageFont.truetype("arial.ttf", 20)
except Exception:
    font_title = ImageFont.load_default()
    font_sub = ImageFont.load_default()
    font_tag = ImageFont.load_default()
    font_meta = ImageFont.load_default()

# Pill badge
og_draw.rounded_rectangle([400, 150, 770, 188], radius=6, fill=(30, 58, 85), outline=(56, 189, 248), width=1)
og_draw.text((415, 158), "NTRO SIH26160 • OFFENSIVE & DEFENSIVE SUITE", fill=(125, 211, 252), font=font_meta)

# Main Title
og_draw.text((400, 210), "CipherGuard", fill=(255, 255, 255), font=font_title)

# Subtitle
og_draw.text((400, 300), "Passive IPsec Protocol & Live Wi-Fi Security Analyzer", fill=(148, 163, 184), font=font_sub)

# Feature Badges
badges = [
    ("🛡️ Zero-Payload Framing Inspection", (16, 185, 129)),
    ("🚨 Rogue AP & Evil Twin Hunter", (239, 68, 68)),
    ("⚡ NIST SP 800-77 & MITRE Compliance", (56, 189, 248)),
    ("🔐 Post-Quantum Cryptography Defense", (168, 85, 247)),
]

bx = 400
by = 370
for i, (text, color) in enumerate(badges):
    col = i % 2
    row = i // 2
    x = bx + col * 370
    y = by + row * 55
    og_draw.rounded_rectangle([x, y, x + 350, y + 42], radius=6, fill=(30, 41, 59), outline=color, width=1)
    og_draw.text((x + 14, y + 10), text, fill=(241, 245, 249), font=font_meta)

# Footer bar
og_draw.text(
    (400, 540), "Self-Contained • Sovereign Cyber Security • Air-Gapped Ready", fill=(100, 116, 139), font=font_meta
)

# Save compressed optimized image
og_path = os.path.join(IMG_DIR, "og-image.png")
og.save(og_path, "PNG", optimize=True)
print(f"Successfully generated: {og_path}")
