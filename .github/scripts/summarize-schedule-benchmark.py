#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path
from typing import Any


def read_meta(meta_path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not meta_path.is_file():
        return data

    for line in meta_path.read_text(errors="ignore").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()

    return data


def read_fuzzer_stats(case_dir: Path) -> dict[str, str]:
    candidates = [
        case_dir / "default" / "fuzzer_stats",
        case_dir / "fuzzer_stats",
    ]

    stats_path = next((p for p in candidates if p.is_file()), None)
    if not stats_path:
        return {}

    data: dict[str, str] = {}

    for line in stats_path.read_text(errors="ignore").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()

    return data


def parse_final_console(log_path: Path) -> dict[str, Any]:
    if not log_path.is_file():
        return {}

    text = log_path.read_text(errors="ignore")

    # AFL++ -V 结束时常见统计输出：
    # Statistics: N new corpus items found, X% coverage achieved, C crashes saved, T timeouts saved
    match = re.search(
        r"Statistics:\s+(\d+)\s+new corpus items found,\s+"
        r"([0-9.]+)%\s+coverage achieved,\s+"
        r"(\d+)\s+crashes saved,\s+"
        r"(\d+)\s+timeouts saved",
        text,
    )

    if not match:
        return {}

    return {
        "new_items": int(match.group(1)),
        "console_coverage": float(match.group(2)),
        "console_crashes": int(match.group(3)),
        "console_timeouts": int(match.group(4)),
    }


def count_unique_files(dir_path: Path) -> tuple[int, int]:
    if not dir_path.is_dir():
        return 0, 0

    files = [
        p
        for p in dir_path.iterdir()
        if p.is_file() and p.name != "README.txt"
    ]

    digests: set[str] = set()

    for path in files:
        try:
            digests.add(hashlib.sha256(path.read_bytes()).hexdigest())
        except OSError:
            pass

    return len(files), len(digests)


def count_queue_files(case_dir: Path) -> int:
    candidates = [
        case_dir / "default" / "queue",
        case_dir / "queue",
    ]

    queue_dir = next((p for p in candidates if p.is_dir()), None)
    if not queue_dir:
        return 0

    return len([p for p in queue_dir.iterdir() if p.is_file()])


def to_int(stats: dict[str, str], key: str, default: int = 0) -> int:
    raw = str(stats.get(key, default)).strip()
    try:
        return int(raw)
    except ValueError:
        return default


def to_float(stats: dict[str, str], key: str, default: float = 0.0) -> float:
    raw = str(stats.get(key, default)).strip().rstrip("%")
    try:
        return float(raw)
    except ValueError:
        return default


def sign_int(value: int) -> str:
    return f"{value:+d}"


def sign_float(value: float, digits: int = 2) -> str:
    return f"{value:+.{digits}f}"


def collect_case(out_root: Path, meta_path: Path) -> dict[str, Any]:
    meta = read_meta(meta_path)
    case_name = meta.get("case", meta_path.stem)

    case_dir = out_root / case_name
    stats = read_fuzzer_stats(case_dir)
    console = parse_final_console(out_root / f"{case_name}.console.log")

    crashes_dir = case_dir / "default" / "crashes"
    hangs_dir = case_dir / "default" / "hangs"

    crash_files, unique_crashes = count_unique_files(crashes_dir)
    hang_files, unique_hangs = count_unique_files(hangs_dir)

    return {
        "case": case_name,
        "proto": meta.get("proto", "unknown"),
        "variant": meta.get("variant", "unknown"),
        "schedule": meta.get("schedule", "unknown"),
        "risk_mode": meta.get("risk_mode", "unknown"),
        "fuzz_seconds": meta.get("fuzz_seconds", ""),
        "execs_done": to_int(stats, "execs_done"),
        "execs_per_sec": to_float(stats, "execs_per_sec"),
        "cycles_done": to_int(stats, "cycles_done"),
        "corpus_count": to_int(stats, "corpus_count"),
        "queue_files": count_queue_files(case_dir),
        "new_items": int(console.get("new_items", 0)),
        "max_depth": to_int(stats, "max_depth"),
        "pending_total": to_int(stats, "pending_total"),
        "bitmap_cvg": to_float(stats, "bitmap_cvg"),
        "edges_found": to_int(stats, "edges_found"),
        "total_edges": to_int(stats, "total_edges"),
        "stability": to_float(stats, "stability"),
        "var_byte_count": to_int(stats, "var_byte_count"),
        "saved_crashes": to_int(stats, "saved_crashes"),
        "saved_hangs": to_int(stats, "saved_hangs"),
        "crash_files": crash_files,
        "unique_crashes": unique_crashes,
        "hang_files": hang_files,
        "unique_hangs": unique_hangs,
        "console_timeouts": int(console.get("console_timeouts", 0)),
    }


def render_summary(rows: list[dict[str, Any]]) -> str:
    lines: list[str] = []

    base_schedule = next(
        (r["schedule"] for r in rows if r["variant"] == "baseline"),
        "unknown",
    )
    test_schedule = next(
        (r["schedule"] for r in rows if r["variant"] == "candidate"),
        "unknown",
    )

    lines.append("## Schedule benchmark fuzz summary")
    lines.append("")
    lines.append(f"- Baseline schedule: `{base_schedule}`")
    lines.append(f"- Candidate schedule: `{test_schedule}`")
    lines.append("- Baseline mode disables risk feedback scheduling via `AFL_DISABLE_RISK=1` and `AFL_DISABLE_RISK_SCHED=1`.")
    lines.append("- Candidate mode keeps risk feedback enabled and uses the candidate schedule.")
    lines.append("")

    lines.append("### Raw case metrics")
    lines.append("")
    lines.append(
        "| Case | Protocol | Variant | Schedule | Risk | Exec/s | Execs | Cycles | Corpus | Queue files | New items | Edges | Bitmap % | Max depth | Crashes | Hangs | Pending | Stability |"
    )
    lines.append(
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )

    for r in rows:
        lines.append(
            f"| {r['case']} "
            f"| {r['proto']} "
            f"| {r['variant']} "
            f"| `{r['schedule']}` "
            f"| {r['risk_mode']} "
            f"| {r['execs_per_sec']:.2f} "
            f"| {r['execs_done']} "
            f"| {r['cycles_done']} "
            f"| {r['corpus_count']} "
            f"| {r['queue_files']} "
            f"| {r['new_items']} "
            f"| {r['edges_found']} "
            f"| {r['bitmap_cvg']:.2f} "
            f"| {r['max_depth']} "
            f"| {r['saved_crashes']} / uniq {r['unique_crashes']} "
            f"| {r['saved_hangs']} / uniq {r['unique_hangs']} "
            f"| {r['pending_total']} "
            f"| {r['stability']:.2f}% |"
        )

    lines.append("")
    lines.append("### Candidate - baseline deltas")
    lines.append("")
    lines.append(
        "| Protocol | Δ Exec/s | Δ Execs | Δ Corpus | Δ Queue files | Δ New items | Δ Edges | Δ Bitmap pp | Δ Max depth | Δ Crashes | Δ Hangs | Δ Pending |"
    )
    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )

    protocols = sorted({r["proto"] for r in rows if r["proto"] != "unknown"})

    for proto in protocols:
        baseline = next(
            (r for r in rows if r["proto"] == proto and r["variant"] == "baseline"),
            None,
        )
        candidate = next(
            (r for r in rows if r["proto"] == proto and r["variant"] == "candidate"),
            None,
        )

        if not baseline or not candidate:
            continue

        lines.append(
            f"| {proto} "
            f"| {sign_float(candidate['execs_per_sec'] - baseline['execs_per_sec'])} "
            f"| {sign_int(candidate['execs_done'] - baseline['execs_done'])} "
            f"| {sign_int(candidate['corpus_count'] - baseline['corpus_count'])} "
            f"| {sign_int(candidate['queue_files'] - baseline['queue_files'])} "
            f"| {sign_int(candidate['new_items'] - baseline['new_items'])} "
            f"| {sign_int(candidate['edges_found'] - baseline['edges_found'])} "
            f"| {sign_float(candidate['bitmap_cvg'] - baseline['bitmap_cvg'])} "
            f"| {sign_int(candidate['max_depth'] - baseline['max_depth'])} "
            f"| {sign_int(candidate['saved_crashes'] - baseline['saved_crashes'])} "
            f"| {sign_int(candidate['saved_hangs'] - baseline['saved_hangs'])} "
            f"| {sign_int(candidate['pending_total'] - baseline['pending_total'])} |"
        )

    lines.append("")
    lines.append("### Reading guide")
    lines.append("")
    lines.append("- `Exec/s` 下降但 `Max depth`、`Crashes/Hangs`、`New items` 上升，可能说明 candidate 更偏向深层或风险路径探索。")
    lines.append("- `Edges` 和 `Bitmap %` 更高只能说明覆盖反馈更好，不一定等价于风险路径更好。")
    lines.append("- `Pending` 较高通常说明队列仍有较多待处理项，短时间 benchmark 里可以看作探索压力尚未消化。")
    lines.append("- 单次 GitHub Actions 结果只能做趋势判断，建议后续至少跑 3 次以上，或者把 `fuzz_seconds` 拉到 3600/10800。")

    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) >= 2:
        out_root = Path(sys.argv[1])
    else:
        workbase = os.environ.get("RISKINS_WORKBASE")
        if not workbase:
            print("missing output root argument or RISKINS_WORKBASE", file=sys.stderr)
            return 2
        out_root = Path(workbase) / "schedule-fuzz-out"

    if not out_root.is_dir():
        print(f"output root not found: {out_root}", file=sys.stderr)
        return 1

    meta_paths = sorted(out_root.glob("*.meta"))

    if not meta_paths:
        print(f"no .meta files found under: {out_root}", file=sys.stderr)
        return 1

    rows = [collect_case(out_root, meta_path) for meta_path in meta_paths]
    rows.sort(key=lambda r: (r["proto"], r["variant"]))

    summary = render_summary(rows)

    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fp:
            fp.write(summary)
            fp.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())