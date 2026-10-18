#!/usr/bin/env python3
"""Alternate two modules against one native nginx and validate every response.

Run this comparison only on Linux/amd64. CPU accounting excludes time the workers
spend descheduled. HTTP latency/throughput include client work, scheduling and network overhead.
No existing nginx configuration or listener is modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import statistics
import subprocess
import tempfile
import time


def cpu_set(value):
    try:
        result = set()
        for item in value.split(","):
            bounds = [int(part) for part in item.split("-")]
            if len(bounds) == 1:
                bounds.append(bounds[0])
            if len(bounds) != 2 or not 0 <= bounds[0] <= bounds[1]:
                raise ValueError
            result.update(range(bounds[0], bounds[1] + 1))
        return result
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected CPUs such as 0,2-4") from error


def pinned(command, cpus):
    if cpus is None:
        return command
    return ["taskset", "--cpu-list", ",".join(str(cpu) for cpu in sorted(cpus)), *command]


def validate_affinity(args, parser):
    if (args.server_cpus is None) != (args.client_cpus is None):
        parser.error("provide both --server-cpus and --client-cpus")
    if args.server_cpus is None:
        return
    if not shutil.which("taskset"):
        parser.error("CPU placement requires taskset")
    available = os.sched_getaffinity(0)
    for cpus in [args.server_cpus, args.client_cpus]:
        if not cpus or not cpus <= available:
            parser.error(f"CPU sets must be nonempty subsets of {sorted(available)}")
    siblings = set()
    for cpu in args.server_cpus:
        topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
        siblings.update(cpu_set(topology.read_text().strip()))
    if siblings & args.client_cpus:
        parser.error("server and client must use separate physical cores, including SMT siblings")


def cpu_seconds(pids):
    ticks = 0
    for pid in pids:
        # comm is parenthesized and can contain spaces; utime/stime are 14/15.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks += int(fields[11]) + int(fields[12])
    return ticks / os.sysconf("SC_CLK_TCK")


def measure(args, module, label, round_number, mode):
    import resource

    with tempfile.TemporaryDirectory(prefix="pow-perf-") as temporary:
        root = Path(temporary)
        (root / "logs").mkdir()
        (root / "key").write_text("isolated-performance-secret-32-bytes")
        (root / "index.html").write_text("upstream-content")
        (root / "healthz").write_text("ok")
        shutil.copyfile(module, root / "module.so")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = root / "nginx.conf"
        config.write_text(f"""load_module {root}/module.so;
worker_processes {args.workers};
pid {root}/nginx.pid;
error_log {root}/error.log warn;
events {{ worker_connections 1024; }}
http {{ access_log off;
 pow_gate_hmac_key_file {root}/key;
 pow_gate_cookie_secure off;
 pow_gate_difficulty 2000;
 server {{ listen 127.0.0.1:{port};
  location / {{ pow_gate on; root {root}; try_files /index.html =404; }}
  location = /healthz {{ pow_gate off; root {root}; }}
 }}
}}
""")
        subprocess.run(pinned([str(args.nginx), "-p", temporary + "/", "-c", str(config)],
                              args.server_cpus), check=True)
        for _ in range(500):
            if (root / "nginx.pid").exists() and (root / "nginx.pid").read_text().strip().isdigit():
                break
            time.sleep(0.01)
        else:
            raise RuntimeError("nginx did not write its pid file")
        master = int((root / "nginx.pid").read_text())
        try:
            children = Path(f"/proc/{master}/task/{master}/children")
            for _ in range(100):
                pids = children.read_text().split()
                if len(pids) == args.workers:
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError("nginx workers did not start")
            affinities = [sorted(os.sched_getaffinity(int(pid))) for pid in pids]
            if args.server_cpus is not None and any(set(cpus) != args.server_cpus for cpus in affinities):
                raise RuntimeError(f"nginx worker CPU placement differs: {affinities}")
            host_load_before = os.getloadavg()
            cpu_before = cpu_seconds(pids)
            usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
            result = subprocess.run(pinned([str(args.client)], args.client_cpus),
                check=True, text=True, capture_output=True,
                env={**os.environ, "BASE_URL": f"http://127.0.0.1:{port}",
                     "PERF_DURATION": str(args.seconds), "PERF_CONCURRENCY": str(args.concurrency),
                     "PERF_MODES": mode, "PERF_JSON": "1"})
            usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            client_cpu = ((usage_after.ru_utime + usage_after.ru_stime)
                          - (usage_before.ru_utime + usage_before.ru_stime))
            cpu_used = cpu_seconds(pids) - cpu_before
            line = next((line for line in result.stdout.splitlines() if line.startswith("PERF_JSON ")), None)
            if line is None:
                raise RuntimeError("load generator lacks PERF_JSON output; rebuild perf/Cargo.toml")
            stats = json.loads(line.removeprefix("PERF_JSON "))["stats"]
            record = {"module": label, "round": round_number, "mode": mode,
                      "concurrency": args.concurrency, "workers": args.workers,
                      "worker_cpu_affinities": affinities,
                      "requests": stats["requests"], "rps": stats["rps"], "errors": stats["errors"],
                      "p50_us": stats["p50"], "p95_us": stats["p95"], "p99_us": stats["p99"],
                      "max_us": stats["max"], "client_elapsed_seconds": stats["elapsed_secs"],
                      "host_load_before": host_load_before, "host_load_after": os.getloadavg(),
                      "worker_cpu_seconds": cpu_used,
                      "client_cpu_seconds": client_cpu,
                      "worker_cpu_cores": cpu_used / stats["elapsed_secs"],
                      "client_cpu_cores": client_cpu / stats["elapsed_secs"],
                      # Includes the handshake requests; their small
                      # fixed cost is amortized over the timed request count.
                      "worker_cpu_us_per_request": round(cpu_used * 1e6 / max(stats["requests"], 1), 3)}
            if record["errors"] or record["rps"] <= 0:
                raise RuntimeError(f"benchmark failed validation: {record}")
            return record
        finally:
            os.kill(master, signal.SIGQUIT)
            for _ in range(200):
                if not (root / "nginx.pid").exists():
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError("nginx did not stop")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["nginx", "before", "after", "client"]:
        parser.add_argument("--" + name, type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--concurrency-list", type=int, nargs="+",
                        help="compare multiple client counts instead of --concurrency")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--server-cpus", type=cpu_set, help="Linux CPU list, e.g. 0,2-3")
    parser.add_argument("--client-cpus", type=cpu_set)
    parser.add_argument("--modes", nargs="+", choices=["baseline", "challenge", "cleared", "proof"],
                        default=["baseline", "challenge", "cleared", "proof"])
    parser.add_argument("--warmup-seconds", type=int, default=0,
                        help="run the after module's proof mode before collecting samples")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        parser.error("performance measurements are supported only on Linux/amd64")
    concurrencies = args.concurrency_list or [args.concurrency]
    if min(args.seconds, args.rounds, args.workers, *concurrencies) < 1:
        parser.error("seconds, rounds, workers, and concurrency must be positive")
    if len(set(concurrencies)) != len(concurrencies) or len(set(args.modes)) != len(args.modes):
        parser.error("concurrency and mode lists must not contain duplicates")
    if args.warmup_seconds < 0:
        parser.error("warmup seconds must not be negative")
    validate_affinity(args, parser)
    data = {"platform": "linux/amd64", "seconds": args.seconds,
            "concurrency": concurrencies[0] if len(concurrencies) == 1 else None,
            "concurrencies": concurrencies, "workers": args.workers, "modes": args.modes,
            "server_cpus": sorted(args.server_cpus) if args.server_cpus is not None else None,
            "client_cpus": sorted(args.client_cpus) if args.client_cpus is not None else None,
            "sha256": {label: hashlib.sha256(path.read_bytes()).hexdigest()
                       for label, path in [("before", args.before), ("after", args.after), ("client", args.client), ("nginx", args.nginx)]}, "runs": []}
    if args.warmup_seconds:
        warmup = argparse.Namespace(**{**vars(args), "seconds": args.warmup_seconds,
                                       "concurrency": max(concurrencies)})
        data["warmup"] = measure(warmup, args.after, "after", 0, "proof")
        print(json.dumps({"warmup": data["warmup"]}), flush=True)
    for number in range(args.rounds):
        for index, concurrency in enumerate(concurrencies):
            current = argparse.Namespace(**{**vars(args), "concurrency": concurrency})
            for mode in args.modes:
                order = [("before", args.before), ("after", args.after)]
                if (number + index) % 2:
                    order.reverse()
                for label, module in order:
                    row = measure(current, module, label, number + 1, mode)
                    data["runs"].append(row)
                    print(json.dumps(row), flush=True)
                    args.output.write_text(json.dumps(data, indent=2) + "\n")
    data["medians_by_concurrency"] = {}
    for concurrency in concurrencies:
        summary = data["medians_by_concurrency"][str(concurrency)] = {}
        for label in ["before", "after"]:
            summary[label] = {}
            for mode in args.modes:
                rows = [row for row in data["runs"] if row["module"] == label
                        and row["mode"] == mode and row["concurrency"] == concurrency]
                summary[label][mode] = {key: statistics.median(row[key] for row in rows)
                    for key in ["rps", "p50_us", "p95_us", "p99_us", "worker_cpu_us_per_request",
                                "worker_cpu_cores", "client_cpu_cores"]}
    if len(concurrencies) == 1:
        data["medians"] = data["medians_by_concurrency"][str(concurrencies[0])]
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps(data["medians_by_concurrency"], indent=2))


if __name__ == "__main__":
    main()
