# CcpSignPdf

A command-line PDF digital-signing tool written in C++17, modeled on the
feature set and workflow of [JSignPdf](https://jsignpdf.eu/docs). No GUI — CLI only.

## License

CcpSignPdf is released under the [MIT License](LICENSE).

```
Copyright (c) 2026 CcpSignPdf Authors
```

You are free to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the software, provided the copyright notice and this
permission notice are included in all copies or substantial portions.

### Third-party components

| Component | License | Usage |
|-----------|---------|-------|
| PoDoFo     | LGPL-2.0-or-later / MPL-2.0 | PDF parsing & signing |
| OpenSSL    | Apache-2.0  | PKCS#12, CMS, RFC 3161, OCSP/CRL |
| libcurl    | MIT-like (curl license) | HTTP for TSA/OCSP/CRL |
| libp11 (optional) | LGPL-2.1-or-later | PKCS#11 hardware tokens |

If you distribute binaries, include the LICENSE file and the licenses of the
bundled/third-party components above.


It signs PDFs with a PKCS#12 keystore or a PKCS#11 hardware token, can draw a
visible signature (optionally stamped on every page), attach an RFC 3161
timestamp, embed OCSP/CRL revocation material for long-term validation, apply a
certification (DocMDP) level, encrypt the output, and verify existing signatures.

## Features

| JSignPdf concept              | CcpSignPdf equivalent                                          |
|-------------------------------|----------------------------------------------------------------|
| Keystore (PKCS#12)            | `--keystore file.p12 --pass secret`                            |
| Hardware token (PKCS#11)      | `--ks-type PKCS11 --keystore /path/to/module.so --pass PIN`    |
| Key alias / label             | `--alias <name>`                                               |
| Separate key password         | `--key-pass <pw>`                                              |
| Reason / Location / Contact   | `--reason "..." --location "..." --contact "..."`              |
| Signer name                   | `--name "Jane Doe"`                                            |
| Hash algorithm                | `--hash SHA1\|SHA256\|SHA384\|SHA512\|RIPEMD160` (default SHA256) |
| Certification level (DocMDP)  | `--cert-level 0..3`                                            |
| Visible signature             | `--visible --page N --rect llx lly urx ury`                    |
| Visible on every page         | `--all-pages` (one shared appearance stamped on all pages)     |
| Render mode                   | `--render DESCRIPTION_ONLY\|GRAPHIC_AND_DESCRIPTION\|SIGNAME_AND_DESCRIPTION` |
| Custom layer text             | `--l2-text "..." --l4-text "..." --font-size N --bg-image img` |
| Timestamp (TSA)               | `--tsa-url https://... [--tsa-user --tsa-pass]`                |
| TSA policy / digest           | `--tsa-policy <oid> --tsa-hash <algo>`                         |
| Long-term validation          | `--ocsp` and/or `--crl` (embeds a `/DSS` dictionary)           |
| Output naming (-d/-op/-os)    | `--out-dir <dir> --out-prefix <s> --out-suffix <s>`            |
| Append (keep prior revisions) | `--append` (PoDoFo signing is always incremental)              |
| Output encryption             | `--encrypt --owner-pass ... --user-pass ... --no-print ...`    |
| Quiet mode                    | `--quiet`                                                      |
| Signature type                | `adbe.pkcs7.detached` CMS                                      |
| Verify                        | `ccpsignpdf verify --in signed.pdf [--trusted <dir>]`          |

## Architecture

```
src/
  main.cpp             Entry point, exit codes, libcurl init
  cli.{hpp,cpp}        Argument parsing + usage (all JSignPdf-style flags)
  options.hpp          SignOptions / VerifyOptions structs + enums
  keystore.{hpp,cpp}   PKCS#12 loading via OpenSSL; PKCS#11 via libp11
  crypto_util.{hpp,cpp}  HashAlgo -> EVP_MD mapping and algorithm names
  cms.{hpp,cpp}        Detached PKCS#7/CMS builder; embeds the TSA token as
                       an id-aa-timeStampToken unsigned attribute
  timestamp.{hpp,cpp}  RFC 3161 request (OpenSSL TS_REQ) over libcurl
  ltv.{hpp,cpp}        OCSP/CRL fetching + /DSS (Certs/OCSPs/CRLs) embedding
  signer.{hpp,cpp}     PoDoFo integration: reserves /Contents, builds the
                       signature field + visible appearance (shared across
                       pages), DocMDP, output encryption, drives SignDocument
  verifier.{hpp,cpp}   Extracts ByteRange/Contents, verifies CMS with OpenSSL
```

The signature bytes are produced by a custom `PoDoFo::PdfSigner` subclass
(`ExternalCmsSigner`) so we control the CMS structure and can attach the
timestamp — something PoDoFo's stock `PdfSignerCms` does not do on its own.

### How `--all-pages` stays fast

A PDF has exactly one cryptographic signature. `--all-pages` builds the visible
appearance form (text, border, optional image) **once** as a single XObject,
then references that same object from a lightweight `/Stamp` annotation on every
page other than the signed one. There is no per-page redraw or image re-decode,
so cost grows by one small annotation per page rather than by re-rendering. The
page named by `--page` carries the real signature widget; the rest are
visual-only stamps of the same graphic.

## Dependencies

- **PoDoFo >= 0.10** (PDF parsing, incremental signing) — provides the
  `podofo::podofo` CMake target.
- **OpenSSL >= 1.1.1** (PKCS#12, CMS/PKCS#7, RFC 3161, OCSP, CRL).
- **libcurl** (HTTP for TSA POST, OCSP POST, CRL GET).
- **libp11** (optional) — only needed for PKCS#11 hardware-token support,
  enabled with `-DENABLE_PKCS11=ON`.
- **CMake >= 3.16**, a C++17 compiler.

### Installing dependencies

Debian/Ubuntu:
```bash
sudo apt install libpodofo-dev libssl-dev libcurl4-openssl-dev cmake g++
# optional, for --ks-type PKCS11:
sudo apt install libp11-dev
```

macOS (Homebrew):
```bash
brew install podofo openssl@3 curl cmake
# optional, for PKCS#11:
brew install libp11
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
# binary: build/ccpsignpdf
```

Enable PKCS#11 hardware-token support (requires libp11):
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_PKCS11=ON
cmake --build build -j
```

## Standalone / portable binary

The default build dynamically links PoDoFo, OpenSSL, and libcurl, so the binary
needs those shared libraries at runtime. To ship a binary that runs on machines
without them:

```bash
chmod +x build-portable.sh
./build-portable.sh
# -> build-portable/ccpsignpdf
# ldd should show only glibc-family libraries (libc, libm, libdl, libpthread, …)
```

That script builds a minimal static libcurl and a static PoDoFo 0.10 into
`.deps/`, then compiles `ccpsignpdf` with `-DBUILD_STATIC=ON`. PoDoFo, OpenSSL,
libcurl, libstdc++ and libgcc are linked in; glibc stays dynamic so TSA/OCSP/CRL
hostname lookups via NSS still work.

The binary runs on Linux with glibc **≥ the glibc of the machine you built on**
(Ubuntu 22.04 ⇒ glibc 2.35). It does not need PoDoFo, OpenSSL, or libcurl
installed on the target.

Equivalent manual configure (after the deps in `.deps/prefix` exist):

```bash
cmake -S . -B build-portable -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC=ON \
  -DCMAKE_PREFIX_PATH="$PWD/.deps/prefix" \
  -Dpodofo_DIR="$PWD/.deps/prefix/share/podofo"
cmake --build build-portable -j
```

On MSVC, `-DBUILD_STATIC=ON` switches to the static CRT (no VC++ redistributable).
Add `-DFULLY_STATIC=ON` to also link glibc via `-static` — that **breaks DNS/NSS**,
so TSA/OCSP/CRL fetches by hostname may fail. For a fully static binary that still
does networking, build against **musl** (Alpine) instead.

Notes:
- PKCS#11 always loads the token driver (`opensc-pkcs11.so`) dynamically at
  runtime by design, regardless of how ccpsignpdf itself is linked.

## Usage

Create a test keystore (self-signed, for trying it out):
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=Test Signer"
openssl pkcs12 -export -inkey key.pem -in cert.pem -out signer.p12 -passout pass:secret
```

Sign (invisible):
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --keystore signer.p12 --pass secret \
  --reason "Approved" --location "Berlin"
```

Sign with a visible box on page 1:
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --keystore signer.p12 --pass secret \
  --visible --page 1 --rect 36 36 236 108 \
  --render SIGNAME_AND_DESCRIPTION \
  --reason "Approved" --name "Jane Doe"
```

Show the visible appearance on every page (real signature on `--page`):
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --keystore signer.p12 --pass secret \
  --all-pages --page 1 --rect 36 36 236 108 \
  --name "Jane Doe" --reason "Approved"
```

Sign with a stronger digest and a timestamp:
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --keystore signer.p12 --pass secret \
  --hash SHA512 \
  --tsa-url http://timestamp.digicert.com
```

Sign with long-term validation (embed OCSP + CRL into /DSS):
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --keystore signer.p12 --pass secret \
  --tsa-url http://timestamp.digicert.com --ocsp --crl
```

Certify the document (no changes allowed after signing):
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --keystore signer.p12 --pass secret --cert-level 1
```

Sign with a hardware token (PKCS#11, built with -DENABLE_PKCS11=ON):
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --ks-type PKCS11 --keystore /usr/lib/opensc-pkcs11.so --pass 123456 \
  --alias "My Signing Key"
```

JSignPdf-style output naming (dir/prefix/suffix instead of explicit --out):
```bash
ccpsignpdf sign --in input.pdf \
  --keystore signer.p12 --pass secret \
  --out-dir ./out --out-prefix "" --out-suffix _signed
# -> ./out/input_signed.pdf
```

Encrypt the output PDF:
```bash
ccpsignpdf sign --in input.pdf --out signed.pdf \
  --keystore signer.p12 --pass secret \
  --encrypt --owner-pass ownerpw --user-pass userpw --no-copy
```

Verify:
```bash
ccpsignpdf verify --in signed.pdf
# add chain validation against a directory of trusted PEM CA certs:
ccpsignpdf verify --in signed.pdf --trusted /etc/ssl/certs
```

Verify exit codes: `0` all valid, `2` at least one signature invalid, `1` error.

## Notes & limitations

- `--all-pages` places a visible stamp on every page, but the document still
  has a single cryptographic signature (on the `--page` page). The stamps on
  other pages are appearance-only annotations, not separate signatures.
- PoDoFo's low-level signing/appearance APIs shifted across 0.10.x point
  releases. The code targets the 0.10 API; if your PoDoFo differs, the calls in
  `signer.cpp` (field creation, `PdfPainter`, `SetAppearanceStream`,
  `CreateAnnot<PdfAnnotationStamp>`, `SetEncrypted`) are the most likely spots
  to need a minor adjustment.
- **Experimental / version-sensitive** features: certification level (DocMDP
  via a hand-built `/Perms` dictionary), output encryption combined with
  signing, and the `/DSS` LTV embedding. These use lower-level PoDoFo/OpenSSL
  constructs that vary by build; verify the output in your PDF reader.
- LTV support embeds a document-level `/DSS` dictionary (Certs/OCSPs/CRLs)
  before signing so it is covered by the signature's ByteRange. It does not yet
  add a per-signature `/VRI` entry or a PAdES-LTA archival document timestamp.
- The `/Contents` placeholder reserves 64 KiB; increase `kReservedSignatureSize`
  in `signer.cpp` if you use very large certificate chains plus timestamps.
- OCSP/CRL and TSA calls require network access at signing time.
- This tool has **not** been compiled in the environment it was generated in —
  build it locally with the dependencies above and report any API mismatches.
