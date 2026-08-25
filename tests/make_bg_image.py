#!/usr/bin/env python3
"""Generate a small PNG background image for signature-appearance tests.

Creates a WxH RGB image with a light-blue fill, darker border, and diagonal
hatch lines - big enough to be clearly visible behind signature text.
Pure stdlib (zlib + struct), no PIL required.
"""
import struct, sys, zlib

def png_chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data +
            struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

def build(w=140, h=64):
    rows = bytearray()
    for y in range(h):
        rows.append(0)  # filter: none
        for x in range(w):
            border = x < 3 or y < 3 or x >= w - 3 or y >= h - 3
            hatch = (x + y) % 12 == 0
            if border:
                r, g, b = 20, 60, 120        # dark blue frame
            elif hatch:
                r, g, b = 190, 210, 240      # light hatch line
            else:
                r, g, b = 235, 242, 252      # near-white fill
            rows += bytes((r, g, b))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    out = (b"\x89PNG\r\n\x1a\n"
           + png_chunk(b"IHDR", ihdr)
           + png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
           + png_chunk(b"IEND", b""))
    sys.stdout.buffer.write(out)

if __name__ == "__main__":
    w = int(sys.argv[1]) if len(sys.argv) > 1 else 140
    h = int(sys.argv[2]) if len(sys.argv) > 2 else 64
    build(w, h)
