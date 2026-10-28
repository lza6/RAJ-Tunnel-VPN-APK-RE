#!/usr/bin/env python3
"""Harvest RAJ/BD-Tunnel white-label server configs into new-api friendly files.

    python harvest.py <blob.txt|dir> [-o out] [--probe] [--bench N]

Input : one or more files containing the base64 config blob (the thing the app
        loads from res/raw/servers or from filesDir/classes3.dex!a.rlb).
Output: out/nodes.json       app-format node list (host/port/protocol)
        out/proxies.txt      "host:port" one per line (raw endpoints, TCP)
        out/socks_template.txt  socks5://127.0.0.1:PORT template for
                                TRYINGOPEN_PROXY_FILE (fill in after bridging)
        out/report.json      probe/bench result when --probe/--bench is used
"""
import argparse
import json
import os
import queue
import socket
import statistics
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import raj_decrypt as rd  # noqa: E402


def collect(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isfile(full) and os.path.getsize(full) > 64:
                    files.append(full)
        else:
            files.append(p)
    return files


def probe_one(host, port, timeout):
    started = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        return True, (time.perf_counter() - started) * 1000.0, ''
    except Exception as exc:
        return False, (time.perf_counter() - started) * 1000.0, str(exc)[:120]
    finally:
        if sock is not None:
            sock.close()


def bench(nodes, workers, rounds, timeout):
    jobs = queue.Queue()
    for _ in range(rounds):
        for node in nodes:
            jobs.put(node)
    lat, failures = [], 0
    lock = threading.Lock()

    def worker():
        nonlocal failures
        while True:
            try:
                node = jobs.get_nowait()
            except queue.Empty:
                return
            ok, ms, _err = probe_one(node['host'], node['port'], timeout)
            with lock:
                if ok:
                    lat.append(ms)
                else:
                    failures += 1

    started = time.perf_counter()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - started
    lat.sort()

    def pct(p):
        return round(lat[min(len(lat) - 1, int(round(p / 100.0 * (len(lat) - 1))))], 1) if lat else None

    total = len(lat) + failures
    return {
        'attempts': total, 'alive': len(lat), 'dead': failures,
        'alive_rate': round(100.0 * len(lat) / total, 1) if total else 0.0,
        'p50_ms': pct(50), 'p95_ms': pct(95), 'p99_ms': pct(99),
        'avg_ms': round(statistics.fmean(lat), 1) if lat else None,
        'elapsed_s': round(elapsed, 2),
        'conn_per_s': round(len(lat) / elapsed, 1) if elapsed else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('paths', nargs='+', help='blob file(s) or directory')
    ap.add_argument('-o', '--out', default='out')
    ap.add_argument('--probe', action='store_true', help='TCP handshake every node')
    ap.add_argument('--bench', type=int, default=0, help='concurrency for a stress run')
    ap.add_argument('--rounds', type=int, default=3)
    ap.add_argument('--timeout', type=float, default=4.0)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    nodes, report = [], {'inputs': [], 'errors': []}
    for path in collect(args.paths):
        try:
            cfg = rd.load_config(open(path, encoding='utf-8', errors='replace').read())
        except Exception as exc:
            report['errors'].append({'file': path, 'error': str(exc)[:160]})
            continue
        got = rd.nodes_from_config(cfg)
        report['inputs'].append({'file': path, 'servers': len(cfg.get('Servers') or []),
                                 'networks': len(cfg.get('Networks') or []), 'nodes': len(got)})
        nodes.extend(got)

    live = [n for n in nodes if n['host'] and n['port']]
    seen, uniq = set(), []
    for n in live:
        key = (n['host'], n['port'])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(n)

    with open(os.path.join(args.out, 'nodes.json'), 'w', encoding='utf-8') as fh:
        json.dump({'nodes': uniq}, fh, ensure_ascii=False, indent=1)
    with open(os.path.join(args.out, 'proxies.txt'), 'w', encoding='utf-8') as fh:
        fh.write('# raw endpoints, not socks/http proxies — bridge them first\n')
        for n in uniq:
            fh.write('%s:%s\n' % (n['host'], n['port']))
    with open(os.path.join(args.out, 'socks_template.txt'), 'w', encoding='utf-8') as fh:
        fh.write('# after running one local OVPN/xray bridge per node, list them here\n')
        fh.write('# TRYINGOPEN_PROXY_FILE points at this file\n')
        for i, n in enumerate(uniq, 1):
            fh.write('socks5://127.0.0.1:%d#raj-%d-%s\n' % (10800 + i, i, n['name'][:20] or n['host']))

    if args.probe:
        report['probe'] = [
            {**n, 'alive': ok, 'ms': round(ms, 1), 'error': err}
            for n in uniq for ok, ms, err in [probe_one(n['host'], n['port'], args.timeout)]
        ]
    if args.bench:
        report['bench'] = bench(uniq, args.bench, args.rounds, args.timeout)

    report['summary'] = {'nodes': len(nodes), 'unique_endpoints': len(uniq)}
    with open(os.path.join(args.out, 'report.json'), 'w', encoding='utf-8') as fh:
        json.dump(report, fh, ensure_ascii=False, indent=1)
    print(json.dumps(report['summary'], ensure_ascii=False))
    if report['errors']:
        print('errors:', report['errors'], file=sys.stderr)


if __name__ == '__main__':
    main()
