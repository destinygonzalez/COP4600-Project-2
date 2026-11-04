#!/usr/bin/env bash
# ============================================================================
# run_tests.sh - Person C's test harness for COP 4600 Project 2
#
# Proves the things Person C owns:
#   0. UNIT         - c_sync.c alone, plus ThreadSanitizer and ASan/UBSan builds
#   1. CORRECTNESS  - output diffs clean against expected output on every test
#                     case, and against the untouched baseline
#   2. STRESS       - repeated runs, including oversubscribed CPUs, give
#                     identical output; edge-case inputs do not crash
#   3. SPEEDUP      - baseline vs optimized time and the rubric points it earns
#   4. THREAD CAP   - samples the live thread count; must stay <= 12
#
# Layout it expects (pass the two directories if yours differ):
#   <repo>/
#     src/                 your optimized project  (make -> ./project2)
#     baseline/src/        an UNTOUCHED copy of the starter, for timing
#
# Make the baseline once, BEFORE editing hash.c, and do not commit it:
#     mkdir -p baseline && cp -R src baseline/src
#
# Test cases: data/hashes.txt -> data/expected.txt, plus any extra pairs named
#     data/<name>.txt -> data/<name>.expected
#
# Usage:   ./run_tests.sh [opt_src_dir] [baseline_src_dir]
# Options (environment variables):
#     STRESS_RUNS=10    repeated-run count
#     MIN_SPEEDUP=4.3   speedup below this fails the run
#     SKIP_SPEEDUP=1    skip timing (quick checks while developing)
#
# Target env: Ubuntu 22.04 / gcc 11 (same as Gradescope). Also runs on macOS,
# but only a Linux result counts for warnings and speedup.
# ============================================================================
set -u
export LC_ALL=C     # bash's `time` must print 1.23, never 1,23

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OPT_SRC="${1:-src}"
BASE_SRC="${2:-baseline/src}"
MAX_THREADS=12
STRESS_RUNS="${STRESS_RUNS:-10}"
MIN_SPEEDUP="${MIN_SPEEDUP:-4.3}"
SKIP_SPEEDUP="${SKIP_SPEEDUP:-0}"
PASSWORDS="$OPT_SRC/data/common-passwords.txt"
HASHES="$OPT_SRC/data/hashes.txt"
BIN="$OPT_SRC/project2"
BASE_BIN="$BASE_SRC/project2"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\n\033[1m%s\033[0m\n' "$*"; }

fail=0
flunk() { red "$*"; fail=1; }

# Scratch files live outside the project so a run never dirties the repo.
TMP=$(mktemp -d "${TMPDIR:-/tmp}/run_tests.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT

# The only place that knows the command-line order of the frozen main.c:
# run_project <binary> <passwords> <hashes> <output>
run_project() { "$1" "$2" "$3" "$4" >/dev/null 2>&1; }

# Compares two files; on a difference prints the first lines and flunks.
same_or_flunk() {  # $1 = got, $2 = want, $3 = label
    if cmp -s "$1" "$2"; then
        green "$3: identical"
    else
        flunk "$3: DIFFERS (< got, > want) - check the tie-break / output format"
        diff "$1" "$2" | head -20
    fi
}

have_baseline=0
[ -d "$BASE_SRC" ] && have_baseline=1

# ---------------------------------------------------------------------------
# 0. UNIT TESTS on c_sync.c  (skipped if it is not next to this script)
# ---------------------------------------------------------------------------
bold "== Unit tests (c_sync.c) =="
CC_BIN="${CC:-gcc}"
unit() {  # $1 = label, remaining args = extra compiler flags
    local label="$1"; shift
    if ! "$CC_BIN" -Wall -Wextra -Werror -g -DC_SYNC_STANDALONE -pthread "$@" \
            "$SCRIPT_DIR/c_sync.c" -o "$TMP/unit" 2>"$TMP/unit.err"; then
        if grep -qi "sanitize\|libtsan\|libasan\|unsupported" "$TMP/unit.err"; then
            echo "$label: sanitizer not available here, skipped"
        else
            flunk "$label: does not compile cleanly"; cat "$TMP/unit.err"
        fi
        return
    fi
    if "$TMP/unit" >"$TMP/unit.out" 2>&1; then
        green "$label: passed"
    elif grep -q "ThreadSanitizer CHECK failed\|LeakSanitizer has encountered a fatal error" "$TMP/unit.out"; then
        # The tool never ran, so this is neither a pass nor a found bug.
        echo "$label: NOT VERIFIED - sanitizer cannot start here" \
             "(in Docker, add --security-opt seccomp=unconfined)"
    else
        flunk "$label: FAILED"; tail -30 "$TMP/unit.out"
    fi
}
if [ -f "$SCRIPT_DIR/c_sync.c" ]; then
    unit "plain build"
    unit "ThreadSanitizer" -fsanitize=thread
    unit "ASan + UBSan" -fsanitize=address,undefined -fno-sanitize-recover=all
else
    echo "(no c_sync.c next to this script - skipped)"
fi

# ---------------------------------------------------------------------------
# 1. BUILD + CORRECTNESS
# ---------------------------------------------------------------------------
bold "== Build =="
make -C "$OPT_SRC" clean >/dev/null 2>&1
if ! make -C "$OPT_SRC" >/dev/null 2>"$TMP/build_warnings.txt"; then
    red "build FAILED"; cat "$TMP/build_warnings.txt"; exit 1
fi
if [ -s "$TMP/build_warnings.txt" ]; then
    flunk "WARNINGS present (-3 pts each on the rubric):"
    cat "$TMP/build_warnings.txt"
else
    green "built with no warnings"
fi
[ -x "$BIN" ] || { red "build produced no $BIN"; exit 1; }

if [ "$have_baseline" -eq 1 ] && ! make -C "$BASE_SRC" >/dev/null 2>"$TMP/base_build.txt"; then
    flunk "baseline build FAILED - ignoring the baseline"
    cat "$TMP/base_build.txt"
    have_baseline=0
fi

bold "== make test =="
if make -C "$OPT_SRC" test; then
    green "make test passed"
else
    flunk "make test FAILED"
fi

bold "== Correctness on every test case =="
[ -f "$PASSWORDS" ] || { red "missing $PASSWORDS"; exit 1; }

check_case() {  # $1 = hash file, $2 = expected file
    local name out
    name=$(basename "$1")
    out="$TMP/case.out"
    rm -f "$out"     # a crash must not be able to pass on a stale file
    if ! run_project "$BIN" "$PASSWORDS" "$1" "$out" || [ ! -f "$out" ]; then
        flunk "$name: program crashed or exited non-zero"
        return
    fi
    if [ -f "$2" ]; then
        same_or_flunk "$out" "$2" "$name vs $(basename "$2")"
    else
        echo "$name: (no $(basename "$2") to diff against)"
    fi
    if [ "$have_baseline" -eq 1 ]; then
        rm -f "$TMP/case.base"
        if run_project "$BASE_BIN" "$PASSWORDS" "$1" "$TMP/case.base"; then
            same_or_flunk "$out" "$TMP/case.base" "$name vs baseline"
        else
            flunk "$name: baseline crashed - cannot compare"
        fi
    fi
}

n_cases=0
if [ -f "$HASHES" ]; then
    check_case "$HASHES" "$OPT_SRC/data/expected.txt"
    n_cases=$((n_cases + 1))
fi
for want in "$OPT_SRC"/data/*.expected; do
    [ -f "$want" ] || continue
    hashes="${want%.expected}.txt"
    if [ -f "$hashes" ]; then
        check_case "$hashes" "$want"
        n_cases=$((n_cases + 1))
    else
        flunk "$(basename "$want") has no matching $(basename "$hashes")"
    fi
done
[ "$n_cases" -gt 0 ] || flunk "no test cases found in $OPT_SRC/data"

# ---------------------------------------------------------------------------
# 2. STRESS  (a race shows up as output that changes between runs)
# ---------------------------------------------------------------------------
bold "== Repeatability ($STRESS_RUNS runs, then 3 at once to oversubscribe the CPUs) =="
if [ -f "$HASHES" ]; then
    run_project "$BIN" "$PASSWORDS" "$HASHES" "$TMP/ref.out" || flunk "reference run failed"
    bad=0
    i=1
    while [ "$i" -le "$STRESS_RUNS" ]; do
        rm -f "$TMP/r.out"
        if ! run_project "$BIN" "$PASSWORDS" "$HASHES" "$TMP/r.out" ||
           ! cmp -s "$TMP/r.out" "$TMP/ref.out"; then
            bad=$((bad + 1))
        fi
        i=$((i + 1))
    done
    pids=""
    for i in 1 2 3; do
        run_project "$BIN" "$PASSWORDS" "$HASHES" "$TMP/p$i.out" &
        pids="$pids $!"
    done
    for p in $pids; do
        wait "$p" || bad=$((bad + 1))
    done
    for i in 1 2 3; do
        cmp -s "$TMP/p$i.out" "$TMP/ref.out" || bad=$((bad + 1))
    done
    if [ "$bad" -eq 0 ]; then
        green "all $((STRESS_RUNS + 3)) runs identical"
    else
        flunk "$bad run(s) crashed or changed output - likely a race"
    fi
fi

# Inputs chosen to break the range split and the empty-file paths. With a
# baseline each is compared to it; otherwise only crash + line count is checked.
bold "== Edge-case inputs =="
first_hash=$(head -n 1 "$HASHES" 2>/dev/null)
first_pw=$(head -n 1 "$PASSWORDS")
: > "$TMP/none.txt"
printf '%s\n' "$first_pw" > "$TMP/one_pw.txt"
head -n 3 "$PASSWORDS" > "$TMP/three_pw.txt"        # fewer passwords than threads
head -n 500 "$PASSWORDS" > "$TMP/dup_a.txt"
cat "$TMP/dup_a.txt" "$TMP/dup_a.txt" > "$TMP/dup_pw.txt"  # every password twice
printf '%s\n' "$first_hash" > "$TMP/one_hash.txt"
printf '%s\n%s\n%s\n' "$first_hash" "$first_hash" "$first_hash" > "$TMP/dup_hash.txt"
printf '%032d\n' 0 > "$TMP/miss_hash.txt"           # well-formed, cracks to nothing

edge() {  # $1 = label, $2 = password file, $3 = hash file
    local out="$TMP/edge.out" want
    rm -f "$out"
    if ! run_project "$BIN" "$2" "$3" "$out" || [ ! -f "$out" ]; then
        flunk "$1: crashed or exited non-zero"
        return
    fi
    want=$(wc -l < "$3")
    if [ "$(wc -l < "$out")" -ne "$want" ]; then
        flunk "$1: expected $want output lines"
        return
    fi
    if [ "$have_baseline" -eq 1 ]; then
        rm -f "$TMP/edge.base"
        if run_project "$BASE_BIN" "$2" "$3" "$TMP/edge.base"; then
            same_or_flunk "$out" "$TMP/edge.base" "$1 vs baseline"
            return
        fi
        echo "$1: baseline itself fails on this input; optimized one survives"
        return
    fi
    green "$1: ok"
}
edge "empty hash file"       "$PASSWORDS"       "$TMP/none.txt"
edge "empty password file"   "$TMP/none.txt"    "$TMP/one_hash.txt"
edge "single password"       "$TMP/one_pw.txt"  "$TMP/one_hash.txt"
edge "3 passwords"           "$TMP/three_pw.txt" "$TMP/one_hash.txt"
edge "duplicate passwords"   "$TMP/dup_pw.txt"  "$TMP/one_hash.txt"
edge "duplicate hashes"      "$PASSWORDS"       "$TMP/dup_hash.txt"
edge "hash with no match"    "$TMP/dup_pw.txt"  "$TMP/miss_hash.txt"

# ---------------------------------------------------------------------------
# 3. SPEEDUP  (baseline vs optimized, best of 3 runs each)
# ---------------------------------------------------------------------------
bold "== Speedup =="
timeit() {  # $1 = binary -> echoes best wall-clock seconds of 3 runs; 1 on failure
    local best="" t
    for _ in 1 2 3; do
        # Uses bash's built-in time: /usr/bin/time is absent on stock Ubuntu
        # and has no -f option on macOS.
        t=$( { TIMEFORMAT=%R; time run_project "$1" "$PASSWORDS" "$HASHES" "$TMP/t.out"; } 2>&1 ) || return 1
        if [ -z "$best" ] || awk -v a="$t" -v b="$best" 'BEGIN{exit !(a < b)}'; then
            best="$t"
        fi
    done
    echo "$best"
}

if [ "$SKIP_SPEEDUP" = "1" ]; then
    echo "(skipped: SKIP_SPEEDUP=1)"
elif [ "$have_baseline" -eq 0 ]; then
    flunk "no baseline at $BASE_SRC, so no speedup number: mkdir -p baseline && cp -R src baseline/src"
elif ! BT=$(timeit "$BASE_BIN"); then
    flunk "baseline run failed during timing"
elif ! OT=$(timeit "$BIN"); then
    flunk "optimized run failed during timing"
else
    echo "baseline : ${BT}s"
    echo "optimized: ${OT}s"
    awk -v b="$BT" -v o="$OT" 'BEGIN{
        if (o<=0){print "optimized time ~0, rerun on a bigger input"; exit}
        f=b/o;
        # rubric interpolation: 1x->0, 2.1x->16.7, 3.2x->33.3, 4.3x->50
        if      (f<=1.0) pts=0;
        else if (f<=2.1) pts=16.7*(f-1.0)/(2.1-1.0);
        else if (f<=3.2) pts=16.7+(33.3-16.7)*(f-2.1)/(3.2-2.1);
        else if (f<=4.3) pts=33.3+(50-33.3)*(f-3.2)/(4.3-3.2);
        else            pts=50;
        printf "speedup  : %.2fx  ->  ~%.1f / 50 speed points\n", f, pts;
    }'
    if awk -v b="$BT" -v o="$OT" -v m="$MIN_SPEEDUP" 'BEGIN{exit !(o>0 && b/o >= m)}'; then
        green "meets the ${MIN_SPEEDUP}x target"
    else
        flunk "below the ${MIN_SPEEDUP}x target"
    fi
fi

# ---------------------------------------------------------------------------
# 4. THREAD CAP  (samples while the program runs)
# ---------------------------------------------------------------------------
bold "== Thread count (<= $MAX_THREADS) =="
count_threads() {
    if [ -d "/proc/$1/task" ]; then
        ls "/proc/$1/task" 2>/dev/null | wc -l
    else
        ps -M -p "$1" 2>/dev/null | awk 'NR>1{n++} END{print n+0}'   # macOS
    fi
}
# Started directly: backgrounding run_project would make $! a one-thread subshell.
"$BIN" "$PASSWORDS" "$HASHES" "$TMP/th.out" >/dev/null 2>&1 &
PID=$!
peak=0
while kill -0 "$PID" 2>/dev/null; do
    n=$(count_threads "$PID")
    [ "${n:-0}" -gt "$peak" ] && peak=$n
done
wait "$PID" || flunk "program failed during the thread check"
echo "peak threads (incl. main): $peak"
if [ "$peak" -gt "$MAX_THREADS" ]; then
    flunk "OVER LIMIT - submission would be invalid"
elif [ "$peak" -le 1 ]; then
    # Never report a pass when the sampler saw no workers.
    flunk "INCONCLUSIVE - no worker threads seen (run too short, or not threaded)"
else
    green "within the $MAX_THREADS-thread limit"
fi

echo
if [ "$fail" -eq 0 ]; then
    green "ALL CHECKS PASSED"
else
    red "SOME CHECKS FAILED (see above)"
fi
exit "$fail"
