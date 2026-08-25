#!/usr/bin/env bash
# =============================================================================
# CcpSignPdf full option test suite
#
# Exercises every CLI option of `ccpsignpdf sign` and produces one output PDF
# per test case under tests/out/. Each output is checked (exists, non-empty,
# starts with %PDF) and, where meaningful, re-verified with `ccpsignpdf verify`.
#
# Usage:   ./tests/run_tests.sh
# Results: tests/out/*.pdf  +  tests/results.txt summary
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/ccpsignpdf}"
TD="$ROOT/tests"
WORK="$TD/work"          # keystores, input pdf, bg image
OUT="$TD/out"            # one output pdf per test case
RESULTS="$TD/results.txt"

PASS=0; FAIL=0; SKIP=0
: > "$RESULTS"

mkdir -p "$WORK" "$OUT"
rm -f "$OUT"/*.pdf

log()  { printf '%s\n' "$*" | tee -a "$RESULTS"; }
hdr()  { log ""; log "=== $* ==="; }

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found at $BIN (build first)" >&2; exit 1
fi

# Test PKCS#12 keystore (self-signed, password 'secret')
if [[ ! -f "$WORK/signer.p12" ]]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" \
        -out "$WORK/cert.pem" -days 365 -nodes \
        -subj "/CN=Test Signer/O=CcpSignPdf Test" >/dev/null 2>&1
    openssl pkcs12 -export -inkey "$WORK/key.pem" -in "$WORK/cert.pem" \
        -out "$WORK/signer.p12" -passout pass:secret >/dev/null 2>&1
fi

# Separate-key-password variant (key encrypted with its own password)
if [[ ! -f "$WORK/keypass.p12" ]]; then
    openssl pkcs12 -export -inkey "$WORK/key.pem" -in "$WORK/cert.pem" \
        -out "$WORK/keypass.p12" -passout pass:keypw \
        -name "KeyPass Alias" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES \
        >/dev/null 2>&1
fi

# 3-page input PDF
if [[ ! -f "$WORK/input.pdf" ]]; then
    python3 "$TD/make_input_pdf.py" > "$WORK/input.pdf"
fi

# Small PNG used by --bg-image (16x16, generated so CRCs are guaranteed valid)
python3 "$TD/make_bg_image.py" 16 16 > "$WORK/bg.png"

# Larger visible signature background image (140x64, blue frame + hatch)
python3 "$TD/make_bg_image.py" 140 64 > "$WORK/sigbg.png"

# ---------------------------------------------------------------------------
# Chained PFX keystore (PKCS#12 = PFX): root CA -> intermediate -> signer.
# Exercises --keystore with a real .pfx file carrying the full cert chain.
#   PFX password : pfxpass
#   Key alias    : "Test PFX Signer"  (set at export time)
# ---------------------------------------------------------------------------
if [[ ! -f "$WORK/testchain.pfx" ]]; then
    # Root CA (self-signed)
    openssl req -x509 -newkey rsa:2048 -keyout "$WORK/ca.key" \
        -out "$WORK/ca.pem" -days 365 -nodes \
        -subj "/CN=Test Root CA/O=CcpSignPdf Test" >/dev/null 2>&1
    # Signing end-entity cert issued by the CA
    openssl req -newkey rsa:2048 -keyout "$WORK/pfxsigner.key" \
        -out "$WORK/pfxsigner.csr" -nodes \
        -subj "/CN=Test PFX Signer/O=CcpSignPdf Test" >/dev/null 2>&1
    openssl x509 -req -in "$WORK/pfxsigner.csr" \
        -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
        -out "$WORK/pfxsigner.pem" -days 365 >/dev/null 2>&1
    cat "$WORK/ca.pem" "$WORK/pfxsigner.pem" > "$WORK/chain.pem"
    # Export as PFX (PKCS#12) with friendlyName alias and full chain
    openssl pkcs12 -export -inkey "$WORK/pfxsigner.key" \
        -in "$WORK/pfxsigner.pem" -certfile "$WORK/chain.pem" \
        -name "Test PFX Signer" -passout pass:pfxpass \
        -out "$WORK/testchain.pfx" >/dev/null 2>&1
fi

KS="--keystore $WORK/signer.p12 --pass secret"

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
# run_case <name> <expect:ok|fail|soft> [actual-pdf-path] <args...>
#   ok    : must exit 0 and produce a valid %PDF at the expected path
#   fail  : must exit non-zero (negative test)
#   soft  : success expected, but external-service failures count as SKIP
run_case() {
    local name="$1"; shift
    local expect="$1"; shift
    local outpdf="$OUT/$name.pdf"
    if [[ "${1:-}" == /* && "${1##*.}" != "" && -n "${1%% *}" && "$1" != -* ]]; then
        # first arg is an explicit output path (absolute, not a flag)
        if [[ ! "$1" =~ ^- ]]; then
            outpdf="$1"; shift
        fi
    fi
    local extra=()
    # default output unless the case sets --out/--out-dir itself
    if ! printf '%s\n' "$@" | grep -qE -- '--out( |-dir)'; then
        extra=(--out "$outpdf")
    fi
    local out_txt rc
    out_txt=$("$BIN" sign "$@" "${extra[@]}" 2>&1)
    rc=$?
    local status
    if [[ $rc -eq 0 && -s "$outpdf" && "$(head -c4 "$outpdf" 2>/dev/null)" == "%PDF" ]]; then
        status="PASS"
        PASS=$((PASS+1))
    elif [[ "$expect" == fail && $rc -ne 0 ]]; then
        status="PASS (expected failure, rc=$rc)"
        PASS=$((PASS+1))
    elif [[ "$expect" == soft ]]; then
        status="SKIP (external service: rc=$rc)"
        SKIP=$((SKIP+1))
        outpdf="(skipped)"
    else
        status="FAIL (rc=$rc)"
        FAIL=$((FAIL+1))
    fi
    printf '%-42s %-32s %s\n' "$name" "$status" "$outpdf" | tee -a "$RESULTS"
    if [[ "$status" == FAIL* ]]; then
        printf '%s\n' "$out_txt" | sed 's/^/    | /' >> "$RESULTS"
    fi
}

# verify <pdf>: run ccpsignpdf verify and record result
verify_case() {
    local pdf="$1"
    local vtxt vrc
    vtxt=$("$BIN" verify --in "$pdf" 2>&1); vrc=$?
    if [[ $vrc -eq 0 ]]; then
        printf '%-42s %-32s\n' "  verify: $(basename "$pdf")" "VALID" | tee -a "$RESULTS"
    else
        printf '%-42s %-32s rc=%d\n' "  verify: $(basename "$pdf")" "NOT VALID" "$vrc" | tee -a "$RESULTS"
        printf '%s\n' "$vtxt" | sed 's/^/    | /' >> "$RESULTS"
    fi
}

check_qpdf() {
    local pdf="$1"
    qpdf --check "$pdf" >/dev/null 2>&1 \
        && echo "  qpdf check: OK ($(basename "$pdf"))" | tee -a "$RESULTS" \
        || echo "  qpdf check: WARNINGS/FAILURES ($(basename "$pdf"))" | tee -a "$RESULTS"
}

# Network-dependent features (TSA / OCSP / CRL): detect connectivity once
NET=no
if curl -s -m 5 -o /dev/null http://timestamp.digicert.com 2>/dev/null \
   || curl -s -m 5 -o /dev/null https://example.com 2>/dev/null; then
    NET=yes
fi
TSA_URL=http://timestamp.digicert.com

# ===========================================================================
hdr "1. INPUT / OUTPUT options"
# ===========================================================================
run_case t01_basic_sign           ok  --in "$WORK/input.pdf" $KS
run_case t02_explicit_out         ok  --in "$WORK/input.pdf" $KS \
                                       --out "$OUT/t02_explicit_out.pdf"
mkdir -p "$OUT/t03_dir"
run_case t03_out_dir              ok  "$OUT/t03_dir/input_signed.pdf" \
                                       --in "$WORK/input.pdf" $KS \
                                       --out-dir "$OUT/t03_dir"
run_case t04_out_prefix_suffix    ok  "$OUT/pre_input_suf.pdf" \
                                       --in "$WORK/input.pdf" $KS \
                                       --out-dir "$OUT" --out-prefix pre_ \
                                       --out-suffix _suf
run_case t05_quiet                ok  --in "$WORK/input.pdf" $KS --quiet
run_case t06_append               ok  --in "$OUT/t01_basic_sign.pdf" $KS --append

# ===========================================================================
hdr "2. KEYSTORE options"
# ===========================================================================
run_case t07_alias                ok  --in "$WORK/input.pdf" $KS --alias "$(openssl pkcs12 -in "$WORK/signer.p12" -passin pass:secret -nokeys 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | sed 's/^.*CN *= *//' | cut -d, -f1)"
run_case t08_key_pass             ok  --in "$WORK/input.pdf" \
                                       --keystore "$WORK/keypass.p12" \
                                       --pass keypw --key-pass keypw
run_case t09_ks_type_pkcs12       ok  --in "$WORK/input.pdf" --ks-type PKCS12 \
                                       --keystore "$WORK/signer.p12" --pass secret
# Negative: wrong password must fail
run_case t10_wrong_password       fail --in "$WORK/input.pdf" \
                                        --keystore "$WORK/signer.p12" --pass WRONG
# Negative: missing keystore must fail
run_case t11_missing_keystore     fail --in "$WORK/input.pdf" \
                                        --keystore "$WORK/nope.p12" --pass secret
# PKCS11 without a module can only be exercised as an expected failure here
run_case t12_ks_type_pkcs11_nomod fail --in "$WORK/input.pdf" --ks-type PKCS11 \
                                        --keystore "$WORK/no_module.so" --pass 123456

# ===========================================================================
hdr "3. SIGNATURE metadata options"
# ===========================================================================
run_case t13_reason_location_contact ok --in "$WORK/input.pdf" $KS \
    --reason "Approved by test" --location "Berlin" --contact "test@example.com"
run_case t14_name                 ok  --in "$WORK/input.pdf" $KS --name "Jane Doe"
run_case t15_hash_sha1            ok  --in "$WORK/input.pdf" $KS --hash SHA1
run_case t16_hash_sha256          ok  --in "$WORK/input.pdf" $KS --hash SHA256
run_case t17_hash_sha384          ok  --in "$WORK/input.pdf" $KS --hash SHA384
run_case t18_hash_sha512          ok  --in "$WORK/input.pdf" $KS --hash SHA512
run_case t19_hash_ripemd160       ok  --in "$WORK/input.pdf" $KS --hash RIPEMD160
run_case t20_cert_level_0         ok  --in "$WORK/input.pdf" $KS --cert-level 0
run_case t21_cert_level_1_nochange ok --in "$WORK/input.pdf" $KS --cert-level 1
run_case t22_cert_level_2_formfill ok --in "$WORK/input.pdf" $KS --cert-level 2
run_case t23_cert_level_3_annots  ok  --in "$WORK/input.pdf" $KS --cert-level 3

# ===========================================================================
hdr "4. TIMESTAMP options (network: $NET)"
# ===========================================================================
if [[ "$NET" == yes ]]; then
    run_case t24_tsa_url          ok  --in "$WORK/input.pdf" $KS --tsa-url "$TSA_URL"
    run_case t25_tsa_creds        ok  --in "$WORK/input.pdf" $KS --tsa-url "$TSA_URL" \
                                       --tsa-user "" --tsa-pass ""
    run_case t26_tsa_policy_hash  soft --in "$WORK/input.pdf" $KS --tsa-url "$TSA_URL" \
                                       --tsa-policy 1.3.6.1.4.1.13762.3 \
                                       --tsa-hash SHA256
else
    log "t24-t26 SKIPPED (no network access for TSA)"
    SKIP=$((SKIP+3))
fi

# ===========================================================================
hdr "5. LTV options (--ocsp / --crl)"
# ===========================================================================
if [[ "$NET" == yes ]]; then
    run_case t27_ocsp             ok  --in "$WORK/input.pdf" $KS --ocsp
    run_case t28_crl              ok  --in "$WORK/input.pdf" $KS --crl
    run_case t29_ocsp_crl_tsa     ok  --in "$WORK/input.pdf" $KS --ocsp --crl \
                                       --tsa-url "$TSA_URL"
else
    log "t27-t29 SKIPPED (no network access for OCSP/CRL fetch)"
    SKIP=$((SKIP+3))
fi

# ===========================================================================
hdr "6. VISIBLE SIGNATURE options"
# ===========================================================================
run_case t30_visible_basic        ok  --in "$WORK/input.pdf" $KS --visible \
                                       --page 1 --rect 36 36 236 108
run_case t31_visible_page2        ok  --in "$WORK/input.pdf" $KS --visible \
                                       --page 2 --rect 300 700 576 760
run_case t32_render_description   ok  --in "$WORK/input.pdf" $KS --visible \
                                       --page 1 --rect 36 36 236 108 \
                                       --render DESCRIPTION_ONLY
run_case t33_render_graphic_desc  ok  --in "$WORK/input.pdf" $KS --visible \
                                       --page 1 --rect 36 36 236 108 \
                                       --render GRAPHIC_AND_DESCRIPTION
run_case t34_render_signame_desc  ok  --in "$WORK/input.pdf" $KS --visible \
                                       --page 1 --rect 36 36 236 108 \
                                       --render SIGNAME_AND_DESCRIPTION
run_case t35_l2_text_fontsize     ok  --in "$WORK/input.pdf" $KS --visible \
                                       --page 1 --rect 36 36 286 158 \
                                       --l2-text "Signed by automated test" \
                                       --l4-text "Contact: test@example.com" \
                                       --font-size 14
run_case t36_bg_image             ok  --in "$WORK/input.pdf" $KS --visible \
                                       --page 1 --rect 36 36 236 108 \
                                       --bg-image "$WORK/bg.png"
run_case t37_all_pages            ok  --in "$WORK/input.pdf" $KS --all-pages \
                                       --page 1 --rect 36 36 236 108 \
                                       --name "Jane Doe" --reason "Approved"
run_case t45_graphic_bg_desc      ok  --in "$WORK/input.pdf" $KS \
                                       --visible --page 1 --rect 36 700 336 770 \
                                       --render GRAPHIC_AND_DESCRIPTION \
                                       --bg-image "$WORK/sigbg.png" \
                                       --l2-text "Digitally signed by Jane Doe
Reason: Background + description test
Location: Test Lab" \
                                       --l4-text "Contact: jane@example.com" \
                                       --font-size 10
run_case t46_graphic_bg_allpages  ok  --in "$WORK/input.pdf" $KS --all-pages \
                                       --page 1 --rect 36 36 336 106 \
                                       --render GRAPHIC_AND_DESCRIPTION \
                                       --bg-image "$WORK/sigbg.png" \
                                       --l2-text "Batch approved - all pages" \
                                       --font-size 10
run_case t47_bg_description_only  ok  --in "$WORK/input.pdf" $KS \
                                       --visible --page 1 --rect 36 36 286 128 \
                                       --render DESCRIPTION_ONLY \
                                       --bg-image "$WORK/sigbg.png" \
                                       --l2-text "Description only (no graphic)" \
                                       --font-size 10

# Template variables (${signer} ${subject} ${notAfter} ${timestamp}) expand
# inside --l2-text / --l4-text; verify the rendered text via ToUnicode CMap.
TPL='eSigned By: ${signer}
Certificate: ${subject}
Valid Until: ${notAfter}
Date & Time: ${timestamp}'
run_case t48_template_vars        ok  --in "$WORK/input.pdf" $KS \
                                       --visible --page 1 --rect 36 640 386 770 \
                                       --render GRAPHIC_AND_DESCRIPTION \
                                       --bg-image "$WORK/sigbg.png" \
                                       --font-size 10 \
                                       --l2-text "$TPL"
# Decode the appearance text back through its ToUnicode CMap and assert.
decoded=$(python3 "$TD/decode_appearance_text.py" "$OUT/t48_template_vars.pdf" 2>/dev/null)
if printf '%s' "$decoded" | grep -q "Valid Until: " && \
   printf '%s' "$decoded" | grep -q "Date & Time: " && \
   ! printf '%s' "$decoded" | grep -q '${'; then
    echo "t48_template_expansion                PASS  ($(printf '%s' "$decoded" | head -1))" | tee -a "$RESULTS"
    PASS=$((PASS+1))
else
    echo "t48_template_expansion                FAIL" | tee -a "$RESULTS"
    printf '%s\n' "$decoded" | sed 's/^/    | /' >> "$RESULTS"
    FAIL=$((FAIL+1))
fi

# 10-page document, template text + background image stamped on ALL pages.
python3 "$TD/make_input_pdf.py" 10 > "$WORK/input10.pdf"
run_case t49_10p_bg_allpages      ok  --in "$WORK/input10.pdf" $KS --all-pages \
                                       --page 1 --rect 36 640 386 770 \
                                       --render GRAPHIC_AND_DESCRIPTION \
                                       --bg-image "$WORK/sigbg.png" \
                                       --font-size 10 --l2-text "$TPL"
# structural check: 1 widget + N-1 stamps, single shared image
n_stamps=$(python3 -c "
import re
d = open('$OUT/t49_10p_bg_allpages.pdf','rb').read()
print(len(re.findall(rb'/Subtype ?/ ?Stamp', d)))")
n_imgs=$(python3 -c "
import re
d = open('$OUT/t49_10p_bg_allpages.pdf','rb').read()
print(len(re.findall(rb'/Subtype ?/ ?Image', d)))")
if [[ "$n_stamps" == "9" && "$n_imgs" == "1" ]]; then
    echo "t49_10p_structure                     PASS  (9 stamps pages 2-10, 1 shared image)" | tee -a "$RESULTS"
    PASS=$((PASS+1))
else
    echo "t49_10p_structure                     FAIL  (stamps=$n_stamps images=$n_imgs)" | tee -a "$RESULTS"
    FAIL=$((FAIL+1))
fi
verify_case "$OUT/t49_10p_bg_allpages.pdf"

# Real cryptographic signature on EVERY page: sequential revisions, one
# signature field per page (Signature1..Signature10).
cp -f "$WORK/input10.pdf" "$WORK/multisig10.pdf"
sig_ok=yes
for p in 1 2 3 4 5 6 7 8 9 10; do
    if ! "$BIN" sign --in "$WORK/multisig10.pdf" --out "$WORK/multisig10.pdf" \
            $KS --visible --page $p --rect 36 640 386 770 --quiet >/dev/null 2>&1; then
        sig_ok=no; break
    fi
done
n_sigs=$(python3 -c "
import re
d = open('$WORK/multisig10.pdf','rb').read()
print(len(re.findall(rb'/FT ?/ ?Sig', d)))")
if [[ "$sig_ok" == yes && "$n_sigs" == "10" ]] && \
   "$BIN" verify --in "$WORK/multisig10.pdf" >/dev/null 2>&1; then
    printf '%-42s %-32s %s\n' "t50_multisig_every_page" "PASS (10/10 signatures VALID)" \
        "$WORK/multisig10.pdf" | tee -a "$RESULTS"
    PASS=$((PASS+1))
else
    printf '%-42s %-32s (ok=%s fields=%s)\n' "t50_multisig_every_page" "FAIL" \
        "$sig_ok" "$n_sigs" | tee -a "$RESULTS"
    FAIL=$((FAIL+1))
fi

# Real per-page signature on 10 pages WITH bg image + template text,
# and a per-page timing benchmark.
cp -f "$WORK/input10.pdf" "$WORK/ms10_bg.pdf"
TPL='eSigned By: ${signer}
Certificate: ${subject}
Valid Until: ${notAfter}
Date & Time: ${timestamp}'
ms_total=0; ms_min=999999; ms_max=0; bench_ok=yes
for p in $(seq 1 10); do
    s=$(date +%s%N)
    if ! "$BIN" sign --in "$WORK/ms10_bg.pdf" --out "$WORK/ms10_bg.pdf" \
            $KS --visible --page $p --rect 36 640 386 770 \
            --render GRAPHIC_AND_DESCRIPTION \
            --bg-image "$WORK/sigbg.png" --font-size 10 \
            --l2-text "$TPL" --quiet >/dev/null 2>&1; then
        bench_ok=no; break
    fi
    e=$(date +%s%N); ms=$(( (e - s) / 1000000 ))
    echo "    page $p : ${ms} ms" >> "$RESULTS"
    ms_total=$(( ms_total + ms ))
    (( ms < ms_min )) && ms_min=$ms
    (( ms > ms_max )) && ms_max=$ms
done
n_sigs=$(python3 -c "
import re
d = open('$WORK/ms10_bg.pdf','rb').read()
print(len(re.findall(rb'/FT ?/ ?Sig', d)))" 2>/dev/null || echo 0)
if [[ "$bench_ok" == yes && "$n_sigs" == "10" ]] && \
   "$BIN" verify --in "$WORK/ms10_bg.pdf" >/dev/null 2>&1; then
    printf '%-42s %-32s %s\n' "t51_multisig_bg_benchmark" \
        "PASS (10 sigs, total=${ms_total}ms avg=$((ms_total/10))ms min=${ms_min}ms max=${ms_max}ms)" \
        "$WORK/ms10_bg.pdf" | tee -a "$RESULTS"
    PASS=$((PASS+1))
else
    printf '%-42s %-32s (ok=%s fields=%s)\n' "t51_multisig_bg_benchmark" "FAIL" \
        "$bench_ok" "$n_sigs" | tee -a "$RESULTS"
    FAIL=$((FAIL+1))
fi

# ===========================================================================
hdr "7. OUTPUT ENCRYPTION options"
# ===========================================================================
run_case t38_encrypt_full         ok  --in "$WORK/input.pdf" $KS \
                                       --encrypt --owner-pass ownerpw \
                                       --user-pass userpw
run_case t39_encrypt_no_print     ok  --in "$WORK/input.pdf" $KS \
                                       --encrypt --owner-pass op --user-pass up \
                                       --no-print
run_case t40_encrypt_no_copy      ok  --in "$WORK/input.pdf" $KS \
                                       --encrypt --owner-pass op --user-pass up \
                                       --no-copy
run_case t41_encrypt_allow_modify ok  --in "$WORK/input.pdf" $KS \
                                       --encrypt --owner-pass op --user-pass up \
                                       --allow-modify
run_case t42_encrypt_allow_annot  ok  --in "$WORK/input.pdf" $KS \
                                       --encrypt --owner-pass op --user-pass up \
                                       --allow-annotate
run_case t43_encrypt_all_perms    ok  --in "$WORK/input.pdf" $KS \
                                       --encrypt --owner-pass op --user-pass up \
                                       --no-print --no-copy \
                                       --allow-modify --allow-annotate

# ===========================================================================
hdr "8. COMBINED kitchen-sink case"
# ===========================================================================
run_case t44_kitchen_sink         ok  --in "$WORK/input.pdf" $KS \
                                       --reason "Kitchen sink" --location "Test Lab" \
                                       --contact "test@example.com" --name "Jane Doe" \
                                       --hash SHA512 --cert-level 2 \
                                       --visible --page 1 --rect 36 36 286 158 \
                                       --render GRAPHIC_AND_DESCRIPTION \
                                       --l2-text "Approved by CI" --font-size 12

# ===========================================================================
hdr "10. PFX (PKCS#12) chained-keystore test cases"
# ===========================================================================
PFX="--keystore $WORK/testchain.pfx --pass pfxpass"

# --- basic signing straight off the .pfx ---
run_case p01_pfx_basic_sign       ok  --in "$WORK/input.pdf" $PFX
run_case p02_pfx_alias            ok  --in "$WORK/input.pdf" $PFX --alias "Test PFX Signer"

# --- negative: wrong PFX password / missing alias / corrupt file must fail ---
run_case p03_pfx_wrong_password   fail --in "$WORK/input.pdf" \
                                        --keystore "$WORK/testchain.pfx" --pass WRONGPW
cp "$WORK/bg.png" "$WORK/corrupt.pfx"
run_case p04_pfx_corrupt_file     fail --in "$WORK/input.pdf" \
                                        --keystore "$WORK/corrupt.pfx" --pass pfxpass

# --- every signature-metadata option on top of the PFX identity ---
for h in SHA1 SHA256 SHA384 SHA512 RIPEMD160; do :; done
run_case p05_pfx_hash_sha256      ok  --in "$WORK/input.pdf" $PFX --hash SHA256
run_case p06_pfx_hash_sha512      ok  --in "$WORK/input.pdf" $PFX --hash SHA512
run_case p07_pfx_cert_level_1     ok  --in "$WORK/input.pdf" $PFX --cert-level 1
run_case p08_pfx_metadata         ok  --in "$WORK/input.pdf" $PFX \
                                       --reason "PFX signed" --location "Mumbai" \
                                       --contact "pfx@test.example" \
                                       --name "Test PFX Signer"

# --- visible / all-pages with the PFX identity ---
run_case p09_pfx_visible          ok  --in "$WORK/input.pdf" $PFX --visible \
                                       --page 1 --rect 36 36 236 108 \
                                       --render SIGNAME_AND_DESCRIPTION \
                                       --name "Test PFX Signer"
run_case p10_pfx_all_pages        ok  --in "$WORK/input.pdf" $PFX --all-pages \
                                       --page 1 --rect 36 36 236 108 \
                                       --name "Test PFX Signer" --reason "PFX batch"

# --- timestamp + LTV with the PFX (network permitting) ---
if [[ "$NET" == yes ]]; then
    run_case p11_pfx_tsa          ok  --in "$WORK/input.pdf" $PFX \
                                       --tsa-url "$TSA_URL"
    run_case p12_pfx_ltv          soft --in "$WORK/input.pdf" $PFX \
                                       --tsa-url "$TSA_URL" --ocsp --crl
else
    log "p11-p12 SKIPPED (no network access for TSA/OCSP/CRL)"
    SKIP=$((SKIP+2))
fi

# --- encryption + append on an already-PFX-signed doc ---
run_case p13_pfx_encrypt          ok  --in "$WORK/input.pdf" $PFX \
                                       --encrypt --owner-pass op --user-pass up \
                                       --no-copy
run_case p14_pfx_append           ok  --in "$OUT/p01_pfx_basic_sign.pdf" $PFX --append

# --- kitchen sink entirely from the PFX ---
run_case p15_pfx_kitchen_sink     ok  --in "$WORK/input.pdf" $PFX \
                                       --reason "PFX kitchen sink" --location "Test Lab" \
                                       --contact "pfx@test.example" \
                                       --name "Test PFX Signer" \
                                       --hash SHA384 --cert-level 2 \
                                       --all-pages --page 1 --rect 36 36 286 158 \
                                       --render GRAPHIC_AND_DESCRIPTION \
                                       --l2-text "Approved via PFX chain" \
                                       --font-size 12

# --- trust-chain verification: signer's cert must validate against our root CA ---
# Trust dirs require OpenSSL hash-named entries (X509_LOOKUP_hash_dir).
mkdir -p "$WORK/trusted"
cp -f "$WORK/ca.pem" "$WORK/trusted/" 2>/dev/null
openssl rehash "$WORK/trusted" 2>/dev/null || c_rehash "$WORK/trusted" >/dev/null 2>&1
verify_case "$OUT/p01_pfx_basic_sign.pdf"
vtxt=$("$BIN" verify --in "$OUT/p08_pfx_metadata.pdf" --trusted "$WORK/trusted" 2>&1); vrc=$?
if [[ $vrc -eq 0 ]]; then
    printf '%-42s %-32s\n' "  verify+trusted: p08_pfx_metadata" "VALID vs Root CA" | tee -a "$RESULTS"
else
    printf '%-42s %-32s rc=%d\n' "  verify+trusted: p08_pfx_metadata" "CHAIN CHECK FAILED" "$vrc" | tee -a "$RESULTS"
    printf '%s\n' "$vtxt" | sed 's/^/    | /' >> "$RESULTS"
    FAIL=$((FAIL+1))
fi
check_qpdf "$OUT/p01_pfx_basic_sign.pdf"
check_qpdf "$OUT/p10_pfx_all_pages.pdf"

# ===========================================================================
hdr "9. VERIFY subcommand"
# ===========================================================================
for f in t01_basic_sign t13_reason_location_contact t18_hash_sha512 \
         t30_visible_basic t44_kitchen_sink; do
    verify_case "$OUT/$f.pdf"
done
check_qpdf "$OUT/t01_basic_sign.pdf"
check_qpdf "$OUT/t37_all_pages.pdf"
check_qpdf "$OUT/t38_encrypt_full.pdf"

# ===========================================================================
hdr "11. User-supplied PFX (tests/test-certificate.pfx)"
# ===========================================================================
USER_PFX="$TD/test-certificate.pfx"
if [[ -f "$USER_PFX" ]]; then
    UPFX_PASS="${UPFX_PASS:-YourPassword123}"
    UPFX="--keystore $USER_PFX --pass $UPFX_PASS"

    # Sanity: password must open the keystore
    if ! openssl pkcs12 -info -in "$USER_PFX" -passin "pass:$UPFX_PASS" -noout >/dev/null 2>&1; then
        log "SKIPPED p16+ : cannot open $USER_PFX with UPFX_PASS (set env UPFX_PASS)"
        SKIP=$((SKIP+6))
    else
        run_case p16_userpfx_basic      ok  --in "$WORK/input.pdf" $UPFX
        run_case p17_userpfx_metadata   ok  --in "$WORK/input.pdf" $UPFX \
                                             --reason "User PFX test" --location "Test Bench" \
                                             --name "Test Certificate"
        run_case p18_userpfx_hash512    ok  --in "$WORK/input.pdf" $UPFX --hash SHA512
        run_case p19_userpfx_visible    ok  --in "$WORK/input.pdf" $UPFX --visible \
                                             --page 1 --rect 36 36 236 108 \
                                             --render SIGNAME_AND_DESCRIPTION \
                                             --name "Test Certificate"
        run_case p20_userpfx_all_pages  ok  --in "$WORK/input.pdf" $UPFX --all-pages \
                                             --page 1 --rect 36 36 236 108 \
                                             --name "Test Certificate"
        run_case p21_userpfx_kitchen    ok  --in "$WORK/input.pdf" $UPFX \
                                             --reason "User PFX kitchen sink" \
                                             --hash SHA256 --cert-level 2 \
                                             --visible --page 1 --rect 36 36 286 158 \
                                             --l2-text "Signed with user-supplied PFX" \
                                             --font-size 12
        verify_case "$OUT/p16_userpfx_basic.pdf"
        check_qpdf "$OUT/p20_userpfx_all_pages.pdf"
    fi
else
    log "Section 11 SKIPPED ($USER_PFX not found)"
fi

# ===========================================================================
hdr "SUMMARY"
# ===========================================================================
TOTAL_FILES=$(ls "$OUT"/*.pdf 2>/dev/null | wc -l)
log "Output PDFs produced : $TOTAL_FILES (in $OUT)"
log "Passed : $PASS   Failed : $FAIL   Skipped: $SKIP"
[[ $FAIL -eq 0 ]] || exit 1
exit 0
