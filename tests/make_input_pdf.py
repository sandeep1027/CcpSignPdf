#!/usr/bin/env python3
"""Generate a simple N-page PDF used as signing input for the test suite.

Usage: make_input_pdf.py [num_pages]   (default 3)
"""
import sys

def build(n_pages=3):
    page_stream = b"BT /F1 24 Tf 72 720 Td (Test PDF) Tj ET\n"
    objs = {}
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join("%d 0 R" % p for p in range(4, 4 + n_pages))
    objs[2] = ("<< /Type /Pages /Kids [%s] /Count %d >>"
               % (kids, n_pages)).encode()
    objs[3] = (b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for i in range(n_pages):
        stream = (
            "BT /F1 24 Tf 72 720 Td (Test PDF - Page %d of %d) Tj ET\n"
            % (i + 1, n_pages)).encode()
        objs[4 + i] = (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Resources << /Font << /F1 3 0 R >> >> "
            "/Contents %d 0 R >>" % (4 + n_pages + i)).encode()
        objs[4 + n_pages + i] = (b"<< /Length " + str(len(stream)).encode() +
                                 b" >>\nstream\n" + stream + b"endstream")

    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objs):
        offsets[num] = len(out)
        out += ("%d 0 obj\n" % num).encode() + objs[num] + b"\nendobj\n"
    xref = len(out)
    n = max(objs) + 1
    out += b"xref\n0 " + str(n).encode() + b"\n0000000000 65535 f \n"
    for num in sorted(objs):
        out += ("%010d 00000 n \n" % offsets[num]).encode()
    out += (b"trailer\n<< /Size " + str(n).encode() +
            b" /Root 1 0 R >>\nstartxref\n" + str(xref).encode() +
            b"\n%%EOF\n")
    sys.stdout.buffer.write(bytes(out))

pages = int(sys.argv[1]) if len(sys.argv) > 1 else 3
build(pages)
