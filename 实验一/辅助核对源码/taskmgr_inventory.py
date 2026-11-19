"""Capture the current highest-thread-count processes or a chosen PID set."""
import argparse
import csv
from datetime import datetime
from pathlib import Path
import psutil


def snapshot(pids, output):
    rows = []
    processes = [psutil.Process(pid) for pid in pids] if pids else psutil.process_iter()
    for proc in processes:
        try:
            with proc.oneshot():
                rows.append(dict(pid=proc.pid, ppid=proc.ppid(), name=proc.name(),
                                 threads=proc.num_threads(), working_set=proc.memory_info().rss,
                                 sample_time=datetime.now().astimezone().isoformat(timespec="milliseconds")))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not rows:
        raise RuntimeError("No readable process records")
    rows.sort(key=lambda row: (-row["threads"], row["pid"]))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for row in rows[:5]:
        print(row)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pids", nargs="+", type=int, help="PID values from the current enumeration")
    parser.add_argument("--out", type=Path, default=Path("selected_processes.csv"))
    args = parser.parse_args()
    snapshot(args.pids, args.out)
