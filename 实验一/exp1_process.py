"""Windows process observation. All control operations target our own child."""
import argparse
import csv
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread
from time import perf_counter, sleep

import psutil

MIB = 1024 ** 2
CORES = os.cpu_count() or 1
K32 = C.WinDLL("kernel32", use_last_error=True)


def winfunc(name, result, *arguments):
    function = getattr(K32, name)
    function.argtypes = arguments
    function.restype = result
    return function


close_handle = winfunc("CloseHandle", W.BOOL, W.HANDLE)
open_thread = winfunc("OpenThread", W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
suspend_thread = winfunc("SuspendThread", W.DWORD, W.HANDLE)
resume_thread = winfunc("ResumeThread", W.DWORD, W.HANDLE)
open_process = winfunc("OpenProcess", W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
process_times = winfunc("GetProcessTimes", W.BOOL, W.HANDLE,
                        *[C.POINTER(W.FILETIME)] * 4)


def wall_stamp():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def save_csv(path, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def cpu_share(older, newer, elapsed):
    return max(0, newer - older) * 100 / (elapsed * CORES)


def inventory(directory):
    attrs = ["pid", "ppid", "name", "status", "num_threads", "memory_info",
             "cpu_times", "create_time"]

    def snapshot():
        if hasattr(psutil.process_iter, "cache_clear"):
            psutil.process_iter.cache_clear()
        observed = {}
        for proc in psutil.process_iter(attrs=attrs):
            observed[proc.pid] = (perf_counter(), proc.info)
        return observed

    first = snapshot()
    sleep(0.5)
    second = snapshot()
    rows = []
    stamp = wall_stamp()
    for pid, (now, item) in sorted(second.items()):
        before, prior = first.get(pid, (None, {}))
        times = item["cpu_times"]
        previous = prior.get("cpu_times")
        percent = None
        if (times and previous and item["create_time"] is not None and
                item["create_time"] == prior["create_time"]):
            percent = round(cpu_share(previous.user + previous.system,
                                      times.user + times.system, now - before), 3)
        mem = item["memory_info"]
        rows.append(dict(pid=pid, ppid=item["ppid"], name=item["name"],
                         status=item["status"], threads=item["num_threads"],
                         cpu_percent=percent, working_set=mem.rss if mem else None,
                         observed_at=stamp))
    save_csv(directory / "process_inventory.csv", rows)
    ranked = sorted((row for row in rows if (row["threads"] or 0) > 1),
                    key=lambda row: (-row["threads"], row["pid"]))[:5]
    save_csv(directory / "process_top5.csv", ranked)
    print(f"Inventory {stamp} | total processes: {len(rows)} | logical CPUs: {CORES}")
    for row in ranked:
        print(" PID {pid:>6}  {name:<26} threads={threads:>3}  {status:<10} "
              "CPU={cpu_percent!s:>6}%  WS={working_set!s} B".format(**row))


def worker(duration, idle):
    def phase(label):
        print(f"{label} {perf_counter():.9f}", flush=True)

    phase("first_code")
    deadline = perf_counter() + duration
    value = 1
    if idle:
        phase("child_waiting")
        sleep(duration)
        return
    start_wait = perf_counter() + 0.20
    while perf_counter() < start_wait:
        value = (value * 1664525 + 1013904223) & 0xffffffff
    phase("child_waiting")
    sleep(1.0)
    phase("child_running")
    while perf_counter() < deadline:
        value = (value * 1664525 + 1013904223) & 0xffffffff


def change_threads(handles, operation):
    succeeded, errors = [], []
    for tid, handle in handles.items():
        previous = operation(handle)
        if previous == 0xffffffff:
            errors.append(f"{tid}: {C.WinError(C.get_last_error())}")
        else:
            succeeded.append((tid, previous))
    return succeeded, errors


def suspend_all(proc, handles):
    errors = []
    for thread in proc.threads():
        handle = open_thread(0x0002, False, thread.id)  # THREAD_SUSPEND_RESUME
        if handle:
            handles[thread.id] = handle
        else:
            errors.append(f"{thread.id}: {C.WinError(C.get_last_error())}")
    if errors:
        return [], errors
    succeeded, errors = change_threads(handles, suspend_thread)
    if errors:
        _, rollback_errors = change_threads({tid: handles[tid] for tid, _ in succeeded},
                                            resume_thread)
        errors.extend(rollback_errors)
    return succeeded, errors


def final_times(handle):
    created, exited, kernel, user = [W.FILETIME() for _ in range(4)]
    if not process_times(handle, C.byref(created), C.byref(exited),
                         C.byref(kernel), C.byref(user)):
        raise C.WinError(C.get_last_error())

    def seconds(stamp):
        return ((stamp.dwHighDateTime << 32) | stamp.dwLowDateTime) / 1e7

    return seconds(user), seconds(kernel)


def capture(directory, points, interval, mode):
    events, messages, rows = [], [], []
    origin = perf_counter()
    clock = wall_stamp()

    def event(label, at=None, duration=None, detail=""):
        elapsed = (perf_counter() if at is None else at) - origin
        events.append(dict(event=label, timestamp=round(elapsed, 9),
                           op_ms=round(duration * 1000, 6) if duration is not None else "",
                           detail=detail))

    with (directory / "run_log.txt").open("w", encoding="utf-8", buffering=1) as log:
        def output(line):
            print(line, flush=True)
            print(line, file=log, flush=True)

        event("create_begin", origin)
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--worker",
             str(max(8, points * interval + 2)), "idle" if mode == "crosscheck" else "mixed"],
            stdout=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        created = perf_counter()
        event("created", created, created - origin, f"pid={child.pid}")
        handle = None
        thread_handles = {}
        reader = None
        try:
            handle = open_process(0x1000, False, child.pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                raise C.WinError(C.get_last_error())
            proc = psutil.Process(child.pid)
            ppid = proc.ppid()
            if ppid != os.getpid():
                raise RuntimeError(f"PPID mismatch: {ppid}")
            name = proc.name()
            output(f"Run {clock} | {mode} | parent {ppid} -> child {child.pid} ({name})")
            output(f"Interval {interval:.3f} s | logical CPUs {CORES} | working set in bytes")
            output(" #     t(s)  status        CPU(%)    WS(MiB)    user(ms)  kernel(ms)")

            def read_phases():
                for line in child.stdout:
                    label, stamp = line.split()
                    messages.append((label, float(stamp)))

            reader = Thread(target=read_phases)
            reader.start()
            suspended = False
            control_failed = False
            previous = None
            with (directory / "process_trace.csv").open(
                    "w", encoding="utf-8-sig", newline="", buffering=1) as stream:
                writer = None
                for index in range(points + (mode == "controlled")):
                    target = created + index * interval
                    sleep(max(0, target - perf_counter()))
                    alive = child.poll() is None
                    if alive and mode == "controlled" and not control_failed:
                        if index == points // 3 or index == points // 3 + 3:
                            action = "suspend" if not suspended else "resume"
                            start = perf_counter()
                            try:
                                counts, errors = (change_threads(thread_handles, resume_thread)
                                                  if suspended else suspend_all(proc, thread_handles))
                            except (OSError, psutil.Error) as exc:
                                counts, errors = [], [str(exc)]
                            detail = (f"OK={len(counts)}, failed={len(errors)}, "
                                      f"TID:previous={counts}")
                            if errors:
                                control_failed = True
                                event(action + "_failed", duration=perf_counter() - start,
                                      detail=f"{detail}; {errors}")
                            else:
                                suspended = not suspended
                                event("suspended" if suspended else "resumed",
                                      duration=perf_counter() - start,
                                      detail=detail)
                    if alive and mode == "controlled" and index == points:
                        start = perf_counter()
                        try:
                            child.terminate()
                            child.wait(timeout=4)
                        except (OSError, subprocess.TimeoutExpired) as exc:
                            event("terminate_failed", detail=str(exc))
                        else:
                            alive = False
                            event("terminated", duration=perf_counter() - start,
                                  detail=f"exit_code={child.returncode}")
                    try:
                        start = perf_counter()
                        if not alive:
                            raise psutil.NoSuchProcess(child.pid)
                        with proc.oneshot():
                            raw_status = proc.status()
                            times = proc.cpu_times()
                            ws = proc.memory_info().rss
                        user, kernel = times.user, times.system
                        labels = {label for label, _ in messages}
                        if suspended:
                            status = "suspended"
                        elif "child_waiting" in labels and "child_running" not in labels:
                            status = "waiting"
                        else:
                            status = "running"
                    except psutil.NoSuchProcess:
                        child.wait(timeout=4)
                        user, kernel = final_times(handle)
                        raw_status, status, ws = "", "terminated", 0
                        if not any(item["event"] == "terminated" for item in events):
                            event("terminated", detail=f"exit_code={child.returncode}")
                    end = perf_counter()
                    moment = (start + end) / 2
                    note = "created" if index == 0 else ""
                    if status != "terminated" and index == points // 3 + 3 and mode == "controlled":
                        note = "resume" if not control_failed else "control error"
                    share = cpu_share(previous[1], user + kernel, moment - previous[0]) if previous else 0
                    previous = (moment, user + kernel)
                    row = dict(idx=index + 1, pid=child.pid, ppid=ppid, name=name, status=status,
                               cpu_percent=round(share, 4), working_set=ws,
                               user_ms=round(user * 1000), kernel_ms=round(kernel * 1000),
                               timestamp=round(moment - origin, 6), wall_time=wall_stamp(),
                               os_status=raw_status, snapshot_ms=round((end - start) * 1000, 4),
                               note=note)
                    if writer is None:
                        writer = csv.DictWriter(stream, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                    rows.append(row)
                    output(f"{index + 1:2}  {row['timestamp']:7.3f}  {status:11} "
                           f"{share:8.4f} {ws / MIB:10.2f}  {row['user_ms']:9} {row['kernel_ms']:10} "
                           f"{note}")
                    if status == "terminated":
                        break
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=4)
            if reader:
                reader.join(timeout=2)
            child.stdout.close()
            if handle:
                close_handle(handle)
            for thread_handle in thread_handles.values():
                close_handle(thread_handle)
        for label, stamp in messages:
            event(label, stamp)
        events.sort(key=lambda item: item["timestamp"])
        save_csv(directory / "process_events.csv", events)
        for item in events:
            output(f"  {item['timestamp']:8.4f} s  {item['event']:<16} "
                   f"{item['op_ms']!s:>10} ms  {item['detail']}")
    return rows, events


def plot_trace(directory, rows, events):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, cpu = plt.subplots(figsize=(9.5, 4.4), layout="constrained")
    mem = cpu.twinx()
    t = [row["timestamp"] for row in rows]
    cpu.plot(t, [row["cpu_percent"] for row in rows], "o-", color="#155595", label="CPU")
    mem.plot(t, [row["working_set"] / MIB for row in rows], "s-", color="#147657", label="Working set")
    for item in events:
        label = item["event"]
        if label in {"created", "child_waiting", "child_running", "suspended", "resumed", "terminated"}:
            mark = item["timestamp"]
            cpu.axvline(mark, color="#666666", linestyle=":", linewidth=0.9)
            cpu.annotate(label.replace("child_", ""), (mark, 0.98), xycoords=("data", "axes fraction"),
                         xytext=(3, -2), textcoords="offset points", rotation=90, va="top", fontsize=8)
    cpu.set(xlabel="Seconds since Popen began", ylabel="CPU (% of machine)",
            title=f"Child PID {rows[0]['pid']}  |  CPU and working set")
    cpu.set_ylim(0, max(0.1, max(row["cpu_percent"] for row in rows) * 1.42))
    mem.set_ylabel("Working set (MiB)")
    cpu.grid(axis="y", alpha=0.2)
    cpu.legend(loc="lower center")
    mem.legend(loc="upper center")
    fig.savefig(directory / "process_trace.png", dpi=175)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--points", type=int, default=12, help="number of periodic live samples")
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--out", type=Path, default=Path("."))
    parser.add_argument("--mode", choices=("controlled", "baseline", "crosscheck"), default="controlled")
    parser.add_argument("--skip-inventory", action="store_true")
    parser.add_argument("--worker", nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        worker(float(args.worker[0]), args.worker[1] == "idle")
        return
    if args.points < 10 or not 0.1 <= args.interval <= 10:
        parser.error("use at least 10 points and an interval of 0.1 to 10 seconds")
    args.out.mkdir(parents=True, exist_ok=True)
    if not args.skip_inventory:
        inventory(args.out)
    rows, events = capture(args.out, args.points, args.interval, args.mode)
    if args.mode == "controlled":
        plot_trace(args.out, rows, events)


if __name__ == "__main__":
    main()
