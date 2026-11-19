"""Python CPU workload and timestamped samples for Task Manager comparison."""
import argparse
import csv
from datetime import datetime
from pathlib import Path
import subprocess
import sys
from time import perf_counter, sleep

import psutil


def workload(seconds):
    deadline = perf_counter() + seconds
    value = 1
    while perf_counter() < deadline:
        value = (value * 1664525 + 1013904223) & 0xffffffff


def sample(out, seconds):
    out.mkdir(parents=True, exist_ok=True)
    child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                              "--worker", str(seconds)], creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        target = psutil.Process(child.pid)
        print(f"Python parent PID {target.ppid()} -> workload PID {target.pid}", flush=True)
        fields = ["sample_time", "pid", "ppid", "image", "threads", "cpu_percent",
                  "working_set", "delta_s"]
        with (out / "taskmgr_cpu_trace.csv").open("w", encoding="utf-8-sig",
                                                  newline="", buffering=1) as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            before = perf_counter()
            times = target.cpu_times()
            before_cpu = times.user + times.system
            while child.poll() is None:
                sleep(1)
                try:
                    with target.oneshot():
                        now = perf_counter()
                        times = target.cpu_times()
                        rss = target.memory_info().rss
                        threads = target.num_threads()
                        name = target.name()
                        ppid = target.ppid()
                except psutil.NoSuchProcess:
                    break
                cpu = times.user + times.system
                delta = now - before
                row = dict(sample_time=datetime.now().astimezone().isoformat(timespec="milliseconds"),
                           pid=child.pid, ppid=ppid, image=name, threads=threads,
                           cpu_percent=round((cpu-before_cpu)*100/(delta*psutil.cpu_count()),4),
                           working_set=rss, delta_s=round(delta,6))
                writer.writerow(row)
                before, before_cpu = now, cpu
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("数据"))
    parser.add_argument("--seconds", type=float, default=90)
    parser.add_argument("--worker", type=float, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker is not None:
        workload(args.worker)
        return
    if args.seconds < 5:
        parser.error("--seconds must be at least 5")
    sample(args.out, args.seconds)


if __name__ == "__main__":
    main()
