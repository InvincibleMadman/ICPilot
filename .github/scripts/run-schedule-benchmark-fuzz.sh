#!/usr/bin/env bash
set -euo pipefail

: "${RISKINS_WORKBASE:?missing RISKINS_WORKBASE}"
: "${AFL_ROOT:?missing AFL_ROOT}"
: "${IEC_TARGET:?missing IEC_TARGET}"
: "${IEC_WORKDIR:?missing IEC_WORKDIR}"
: "${IEC_SEEDS:?missing IEC_SEEDS}"
: "${MODBUS_TARGET:?missing MODBUS_TARGET}"
: "${MODBUS_WORKDIR:?missing MODBUS_WORKDIR}"
: "${MODBUS_SEEDS:?missing MODBUS_SEEDS}"
: "${PREENY_DIR:?missing PREENY_DIR}"

export AFL_PATH="${AFL_PATH:-$AFL_ROOT}"
export PATH="$AFL_ROOT:$PATH"

FUZZ_SECONDS="${FUZZ_SECONDS:-1800}"
BASE_SCHEDULE="${BASE_SCHEDULE:-explore}"
TEST_SCHEDULE="${TEST_SCHEDULE:-linucb}"
RUN_PROTOCOLS="${RUN_PROTOCOLS:-both}"

PREENY_SO="${PREENY_DIR}/${PREENY_SOCKET_SO:-desock.so}"

OUT_ROOT="${RISKINS_WORKBASE}/schedule-fuzz-out"
RUNTIME_ROOT="${RISKINS_WORKBASE}/schedule-runtime"

test -x "$AFL_ROOT/afl-fuzz"
test -f "$PREENY_SO"
test -x "$IEC_TARGET"
test -x "$MODBUS_TARGET"

case "$RUN_PROTOCOLS" in
  both|iec61850|modbus)
    ;;
  *)
    echo "[!] invalid RUN_PROTOCOLS=$RUN_PROTOCOLS, expected: both | iec61850 | modbus" >&2
    exit 2
    ;;
esac

rm -rf "$OUT_ROOT" "$RUNTIME_ROOT"
mkdir -p "$OUT_ROOT" "$RUNTIME_ROOT"

echo "[*] schedule benchmark configuration"
echo "    FUZZ_SECONDS=$FUZZ_SECONDS"
echo "    BASE_SCHEDULE=$BASE_SCHEDULE"
echo "    TEST_SCHEDULE=$TEST_SCHEDULE"
echo "    RUN_PROTOCOLS=$RUN_PROTOCOLS"
echo "    OUT_ROOT=$OUT_ROOT"
echo "    RUNTIME_ROOT=$RUNTIME_ROOT"
echo "    AFL_ROOT=$AFL_ROOT"
echo "    PREENY_SO=$PREENY_SO"

declare -a pids=()
declare -a names=()

launch_case() {
  local case_name="$1"
  local proto="$2"
  local variant="$3"      # baseline | candidate
  local schedule="$4"
  local risk_mode="$5"    # risk-off | risk-on
  local target="$6"
  local seeds="$7"
  local workdir="$8"

  local runtime_dir="$RUNTIME_ROOT/runtime-$case_name"
  local target_name
  target_name="$(basename "$target")"

  mkdir -p "$OUT_ROOT/$case_name"
  rm -rf "$runtime_dir"
  mkdir -p "$runtime_dir"

  cp -a "$workdir"/. "$runtime_dir"/

  if [[ ! -x "$runtime_dir/$target_name" ]]; then
    chmod +x "$runtime_dir/$target_name" || true
  fi

  cat >"$OUT_ROOT/$case_name.meta" <<EOF_META
case=$case_name
proto=$proto
variant=$variant
schedule=$schedule
risk_mode=$risk_mode
target=$target
seeds=$seeds
workdir=$workdir
fuzz_seconds=$FUZZ_SECONDS
EOF_META

  echo "[*] launching $case_name"
  echo "    proto=$proto"
  echo "    variant=$variant"
  echo "    schedule=$schedule"
  echo "    risk_mode=$risk_mode"

  (
    cd "$runtime_dir"

    common_env=(
      "AFL_PATH=$AFL_PATH"
      "LD_PRELOAD=$PREENY_SO"
      "AFL_SKIP_CPUFREQ=${AFL_SKIP_CPUFREQ:-1}"
      "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-1}"
      "AFL_NO_UI=${AFL_NO_UI:-1}"
      "AFL_NO_AFFINITY=${AFL_NO_AFFINITY:-1}"
      "AFL_QUIET=${AFL_QUIET:-1}"
    )

    if [[ "$risk_mode" == "risk-off" ]]; then
      common_env+=(
        "AFL_DISABLE_RISK=1"
        "AFL_DISABLE_RISK_SCHED=1"
      )
    fi

    env "${common_env[@]}" \
      "$AFL_ROOT/afl-fuzz" \
        -p "$schedule" \
        -V "$FUZZ_SECONDS" \
        -m none \
        -t 2000+ \
        -i "$seeds" \
        -o "$OUT_ROOT/$case_name" \
        -- "./$target_name"
  ) >"$OUT_ROOT/$case_name.console.log" 2>&1 &

  pids+=("$!")
  names+=("$case_name")
}

launch_protocol() {
  local proto="$1"

  case "$proto" in
    iec61850)
      launch_case \
        "iec61850-baseline" \
        "iec61850" \
        "baseline" \
        "$BASE_SCHEDULE" \
        "risk-off" \
        "$IEC_TARGET" \
        "$IEC_SEEDS" \
        "$IEC_WORKDIR"

      launch_case \
        "iec61850-candidate" \
        "iec61850" \
        "candidate" \
        "$TEST_SCHEDULE" \
        "risk-on" \
        "$IEC_TARGET" \
        "$IEC_SEEDS" \
        "$IEC_WORKDIR"
      ;;

    modbus)
      launch_case \
        "modbus-baseline" \
        "modbus" \
        "baseline" \
        "$BASE_SCHEDULE" \
        "risk-off" \
        "$MODBUS_TARGET" \
        "$MODBUS_SEEDS" \
        "$MODBUS_WORKDIR"

      launch_case \
        "modbus-candidate" \
        "modbus" \
        "candidate" \
        "$TEST_SCHEDULE" \
        "risk-on" \
        "$MODBUS_TARGET" \
        "$MODBUS_SEEDS" \
        "$MODBUS_WORKDIR"
      ;;

    *)
      echo "[!] unknown protocol: $proto" >&2
      exit 2
      ;;
  esac
}

if [[ "$RUN_PROTOCOLS" == "both" || "$RUN_PROTOCOLS" == "iec61850" ]]; then
  launch_protocol "iec61850"
fi

if [[ "$RUN_PROTOCOLS" == "both" || "$RUN_PROTOCOLS" == "modbus" ]]; then
  launch_protocol "modbus"
fi

status=0

for i in "${!pids[@]}"; do
  name="${names[$i]}"
  if ! wait "${pids[$i]}"; then
    echo "[!] campaign failed: $name" >&2
    echo "[!] last 120 lines of $name.console.log:" >&2
    tail -n 120 "$OUT_ROOT/$name.console.log" >&2 || true
    status=1
  else
    echo "[+] campaign finished: $name"
  fi
done

echo "[*] generated files:"
find "$OUT_ROOT" -maxdepth 3 -type f | sort || true

exit "$status"