#!/usr/bin/env python3
"""Inspect the signature appearance of a visible-sign PDF: image + text."""
import re, sys, zlib

d = open(sys.argv[1], 'rb').read()

# locate the signature widget's normal appearance (form XObject)
form = None
for m in re.finditer(rb'(\d+) 0 obj\s*<<(.*?)>>\s*endobj', d, re.S):
    body = m.group(2)
    if b'/Subtype/Widget' in body or b'/Subtype /Widget' in body:
        if b'/FT/Sig' in body.replace(b' ', b''):
            ap = re.search(rb'/AP<</N (\d+) 0 R', body)
            if ap:
                form = ap.group(1).decode()
if form is None:
    # widget may live in an incremental update without 'endobj' anchor match
    for m in re.finditer(rb'/AP<</N (\d+) 0 R', d):
        form = m.group(1).decode()
print('appearance form object:', form)

m = re.search((form + r' 0 obj\s*<<(.*?)>>\s*stream\r?\n(.*?)endstream').encode(), d, re.S)
if not m:
    print('form stream NOT FOUND'); sys.exit(1)
print('form dict :', ' '.join(m.group(1).decode('latin1').split())[:220])
content = zlib.decompress(m.group(2))
print('--- decoded content ---')
print(content.decode('latin1'))
has_do = b' Do' in content
has_tj = b'Tj' in content
imgs = [i.decode() for i in re.findall(rb'(\d+) 0 obj\s*<<[^>]*?/Subtype/Image', d)]
print(f'image drawn (Do op): {has_do}, text drawn (Tj): {has_tj}, Image XObjects: {imgs}')
