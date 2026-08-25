#!/usr/bin/env python3
"""Decode the visible-signature appearance text of a signed PDF.

Walks the first /FT/Sig widget's normal-appearance form XObject, extracts all
Tj text-showing operators, and maps the subset glyph codes back to Unicode
through the font's ToUnicode CMap. Prints one output line per Tj operator.
"""
import re
import sys
import zlib


def main(path):
    d = open(path, 'rb').read()

    # 1. find the signature widget's appearance form object number
    form = None
    for m in re.finditer(rb'(\d+) 0 obj\s*<<(.*?)>>\s*endobj', d, re.S):
        body = m.group(2).replace(b' ', b'')
        if b'/Subtype/Widget' in body and b'/FT/Sig' in body:
            ap = re.search(rb'/AP<</N(\d+)0R', body)
            if ap:
                form = ap.group(1).decode()
    if form is None:
        sys.exit("no signature widget with an appearance stream found")

    # 2. decode its content stream
    fm = re.search((form + r' 0 obj\s*<<(.*?)>>\s*stream\r?\n(.*?)endstream').encode(), d, re.S)
    if not fm:
        sys.exit("appearance form not found")
    content = zlib.decompress(fm.group(2)).decode('latin1')

    # 3. locate the font resource (FtNN -> object) used by the form
    fdict = fm.group(1).decode('latin1')
    font_ref = re.search(r'/Font<</Ft\d+ (\d+) 0 R', fdict.replace(' ', '')) \
        or re.search(r'/Ft(\d+) (\d+) 0 R', fdict)
    font_obj = font_ref.group(1) if font_ref else None

    # 4. pull ToUnicode CMap from that font object and build the code map
    mapping = {}
    if font_obj:
        tmo = re.search((font_obj + r' 0 obj\s*<<(.*?)>>\s*endobj').encode(), d, re.S)
        if tmo:
            tu = re.search(rb'/ToUnicode\s+(\d+)\s+0\s+R', tmo.group(1))
            if tu:
                tmo2 = re.search(
                    (tu.group(1).decode() + r' 0 obj\s*<<.*?>>\s*stream\r?\n(.*?)endstream').encode(),
                    d, re.S)
                if tmo2:
                    cmap = zlib.decompress(tmo2.group(1)).decode('latin1')
                    for s, t in re.findall(r'<([0-9A-Fa-f]{2})>\s*<([0-9A-Fa-f]{4})>', cmap):
                        mapping[int(s, 16)] = chr(int(t, 16))

    # 5. decode every Tj line
    for hexs in re.findall(r'<([0-9A-Fa-f]+)>\s*Tj', content):
        width = 4 if any(len(h) > 3 for h in [hexs]) and len(hexs) % 4 == 0 and False else 2
        print(''.join(mapping.get(int(hexs[i:i + width], 16), '?')
                      for i in range(0, len(hexs), width)))


if __name__ == "__main__":
    main(sys.argv[1])
