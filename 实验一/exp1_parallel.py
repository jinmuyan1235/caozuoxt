"""Repeat serial and multi-process prime counting three times on Windows."""
import argparse
from math import isqrt
import multiprocessing as mp
from pathlib import Path
from statistics import median
from time import perf_counter, process_time

from exp1_process import CORES, save_csv, wall_stamp


def count_primes(bounds):
    start = process_time()
    low, high = bounds
    total = int(low <= 2 < high)
    for number in range(max(3, low | 1), high, 2):
        limit = isqrt(number)
        for divisor in range(3, limit + 1, 2):
            if number % divisor == 0:
                break
        else:
            total += 1
    return total, process_time() - start


def run(directory, limit, plan):
    ranges = [(i, min(limit + 1, i + 25000)) for i in range(0, limit + 1, 25000)]
    rows = []
    variants = [1, 2, 4, 8]
    for trial in range(1, 4):
        # Rotate execution order to reduce a systematic warm-up advantage.
        offset = trial - 1
        for workers in variants[offset:] + variants[:offset]:
            stamp = wall_stamp()
            start = perf_counter()
            if workers == 1:
                result = list(map(count_primes, ranges))
            else:
                pool = mp.get_context("spawn").Pool(workers)
                try:
                    result = pool.map(count_primes, ranges, chunksize=1)
                    pool.close()
                except BaseException:
                    pool.terminate()
                    raise
                finally:
                    pool.join()
            elapsed = perf_counter() - start
            primes = sum(item[0] for item in result)
            cpu = sum(item[1] for item in result)
            if rows and primes != rows[0]["primes"]:
                raise RuntimeError("serial / parallel results disagree")
            row = dict(trial=trial, workers=workers, limit=limit, chunks=len(ranges),
                       primes=primes, elapsed_s=round(elapsed, 6), compute_cpu_s=round(cpu, 6),
                       cpu_percent=round(cpu * 100 / (elapsed * CORES), 4),
                       power_plan=plan, wall_time=stamp)
            rows.append(row)
            print(row, flush=True)
    save_csv(directory / "parallel_trials.csv", rows)
    summary = []
    for workers in variants:
        group = [row for row in rows if row["workers"] == workers]
        result = dict(workers=workers, elapsed_s=median(row["elapsed_s"] for row in group),
                      cpu_percent=median(row["cpu_percent"] for row in group))
        baseline = summary[0]["elapsed_s"] if summary else result["elapsed_s"]
        result["speedup"] = round(baseline / result["elapsed_s"], 4)
        summary.append(result)
    save_csv(directory / "parallel_medians.csv", summary)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 3, figsize=(11, 3.5), layout="constrained")
    for ax, (key, title) in zip(axes, [("elapsed_s", "Wall time (s)"),
                                       ("cpu_percent", "Compute CPU (% of machine)"),
                                       ("speedup", "Speedup relative to serial")]):
        ax.plot(variants, [row[key] for row in summary], "o-", color="#155595")
        ax.set(xlabel="Workers (1 = serial)", ylabel=title, xticks=variants)
        ax.grid(alpha=0.25)
    fig.savefig(directory / "parallel.png", dpi=175)


if __name__ == "__main__":
    mp.freeze_support()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("."))
    parser.add_argument("--limit", type=int, default=1000000)
    parser.add_argument("--plan", default="unknown")
    args = parser.parse_args()
    if args.limit < 2:
        parser.error("limit must be at least 2")
    args.out.mkdir(parents=True, exist_ok=True)
    run(args.out, args.limit, args.plan)
