#!/usr/bin/env bash
# =============================================================================
# CcpSignPdf multi-page signing benchmark
#
# Generates N-page PDFs (N = 1, 10, 50, 100, 500, 1000) and times:
#   mode 1: invisible signature          (baseline)
#   mode 2: visible on one page          (--visible)
#   mode 3: visible stamped on ALL pages (--all-pages)
# plus verify time for the all-pages result.
#
# Usage: ./tests/benchmark.sh [page-sizes...]   (default: 1 10 50 100 500 1000)
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/ccpsignpdf}"
TD="$ROOT/tests"
BENCH="$TD/bench"
SIZES=("$@")

[[ ${#SIZES[@]} -eq 0 ]] && SIZES=(1 10 50 100 500 1000)

if [[ ! -x "$BIN" ]]; then echo "ERROR: build first ($BIN)" >&2; exit 1; fi

KS="--keystore $TD/work/signer.p12 --pass secret"
mkdir -p "$BENCH"

# timing helper -> elapsed ms (integer)
timeit() {
    local s e rc
    s=$(date +%s%N)
    "$@" >/dev/null 2>&1
    rc=$?
    e=$(date +%s%N)
    if [[ $rc -ne 0 ]]; then echo "ERR(rc=$rc)"; return; fi
    echo "$(( (e - s) / 1000000 ))ms"
}

fmt_size() { # human readable bytes
    local b=$1
    if   (( b >= 1048576 )); then echo "$((b / 1048576)).$(((b % 1048576) * 10 / 1048576)) MB"
    elif (( b >= 1024 ));    then echo "$((b / 1024)) KB"
    else                          echo "${b} B"; fi
}

hdr=$(printf "%-8s %-10s %-12s %-14s %-14s %-14s %-12s\n" \
      "pages" "in-size" "sign-out" "invisible" "visible" "all-pages" "verify")
echo "$hdr"
echo "$hdr" > "$BENCH/results.txt"
echo "---------" >> "$BENCH/results.txt"

for np in "${SIZES[@]}"; do
    in_pdf="$BENCH/in_${np}p.pdf"
    python3 "$TD/make_input_pdf.py" "$np" > "$in_pdf"
    insz=$(stat -c%s "$in_pdf")

    t_inv="skip"; t_vis="skip"; t_all="skip"; t_ver="skip"
    out_sz="-"

    t_inv=$(timeit "$BIN" sign --in "$in_pdf" --out "$BENCH/${np}p_inv.pdf" $KS)
    if [[ -f "$BENCH/${np}p_inv.pdf" ]]; then out_sz=$(stat -c%s "$BENCH/${np}p_inv.pdf"); fi

    t_vis=$(timeit "$BIN" sign --in "$in_pdf" --out "$BENCH/${np}p_vis.pdf" $KS \
                --visible --page 1 --rect 36 36 236 108)

    t_all=$(timeit "$BIN" sign --in "$in_pdf" --out "$BENCH/${np}p_all.pdf" $KS \
                --all-pages --page 1 --rect 36 36 236 108)

    if [[ -f "$BENCH/${np}p_all.pdf" ]]; then
        t_ver=$(timeit "$BIN" verify --in "$BENCH/${np}p_all.pdf")
        allsz=$(stat -c%s "$BENCH/${np}p_all.pdf"); out_sz="$out_sz / $(fmt_size "$allsz")"
    fi

    line=$(printf "%-8s %-10s %-12s %-14s %-14s %-14s %-12s\n" \
           "$np" "$(fmt_size "$insz")" "$out_sz" "$t_inv" "$t_vis" "$t_all" "$t_ver")
    echo "$line"
    echo "$line" >> "$BENCH/results.txt"
done

echo ""
echo "Per-page cost of --all-pages (stamp annotations only):"
python3 - "$BENCH" <<'EOF'
import sys, os, re
bench = sys.argv[1]
sizes = []
for f in sorted(os.listdir(bench)):
    m = re.match(r'(\d+)p_(inv|all)\.pdf$', f)
    if m:
        sizes.append((int(m.group(1)), m.group(2), os.path.getsize(os.path.join(bench, f))))
inv = {n: s for n, k, s in sizes if k == 'inv'}
all_ = {n: s for n, k, s in sizes if k == 'all'}
prev_overhead = None
for n in sorted(inv):
    if n in all_:
        oh = all_[n] - inv[n]
        per = oh / n if n else 0
        growth = f"+{oh/n:.0f} B/page" if n else "-"
        print(f"  {n:>5} pages : invisible={inv[n]:>8} B  all-pages={all_[n]:>8} B  overhead={oh:>8} B ({growth})")
EOF
