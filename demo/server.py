#!/usr/bin/env python3
"""RAJ Tunnel VPN — demo + probe/bench server.

Serves a small UI and four JSON APIs:

    GET  /api/builtin          解包内置 res/raw/servers 配置（占位符）
    POST /api/decrypt {blob}   解密任意该家族的 servers 配置
    POST /api/probe   {nodes}  TCP 握手测活
    POST /api/bench   {nodes, workers, rounds}  并发压测

stdlib only, no third-party deps.
"""
import json
import os
import queue
import socket
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tools'))
import raj_decrypt as rd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
# 仓库内自带占位符样本；本地逆向工作区若有 apktool_out 则优先生用它
BUILTIN_BLOB = next((p for p in (
    os.path.join(HERE, '..', 'apktool_out', 'res', 'raw', 'd.js'),
    os.path.join(HERE, '..', 'samples', 'blob_1.5.txt'),
) if os.path.exists(p)), os.path.join(HERE, '..', 'samples', 'blob_1.5.txt'))
PORT = int(os.environ.get('RAJ_PORT', '8960'))


def tcp_probe(host, port, timeout):
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


def summarize(latencies, failures, elapsed):
    lat = sorted(latencies)
    def pct(p):
        if not lat:
            return None
        idx = min(len(lat) - 1, int(round((p / 100.0) * (len(lat) - 1))))
        return round(lat[idx], 1)
    total = len(lat) + failures
    return {
        'attempts': total,
        'alive': len(lat),
        'dead': failures,
        'alive_rate': round(100.0 * len(lat) / total, 1) if total else 0.0,
        'p50_ms': pct(50), 'p95_ms': pct(95), 'p99_ms': pct(99),
        'min_ms': round(lat[0], 1) if lat else None,
        'max_ms': round(lat[-1], 1) if lat else None,
        'avg_ms': round(statistics.fmean(lat), 1) if lat else None,
        'elapsed_s': round(elapsed, 2),
        'conn_per_s': round(len(lat) / elapsed, 1) if elapsed > 0 else None,
    }


def bench(nodes, workers, rounds, timeout):
    jobs = queue.Queue()
    for _ in range(rounds):
        for node in nodes:
            jobs.put(node)
    latencies, failures = [], 0
    lock = threading.Lock()

    def worker():
        nonlocal failures
        while True:
            try:
                node = jobs.get_nowait()
            except queue.Empty:
                return
            ok, ms, _err = tcp_probe(node['host'], node['port'], timeout)
            with lock:
                if ok:
                    latencies.append(ms)
                else:
                    failures += 1

    started = time.perf_counter()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return summarize(latencies, failures, time.perf_counter() - started)


def config_payload(blob):
    cfg = rd.load_config(blob)
    return {
        'mykey': rd.MYKEY.decode(),
        'sha256': rd.K.hex(),
        'config': cfg,
        'nodes': rd.nodes_from_config(cfg),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype='application/json; charset=utf-8'):
        raw = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _json_body(self):
        length = int(self.headers.get('Content-Length') or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode('utf-8'))

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            with open(os.path.join(HERE, 'index.html'), 'rb') as fh:
                self._send(200, fh.read(), 'text/html; charset=utf-8')
            return
        if self.path == '/api/builtin':
            with open(BUILTIN_BLOB, encoding='utf-8') as fh:
                self._send(200, json.dumps(config_payload(fh.read()), ensure_ascii=False))
            return
        self._send(404, json.dumps({'error': 'not found'}))

    def do_POST(self):
        try:
            body = self._json_body()
            if self.path == '/api/decrypt':
                self._send(200, json.dumps(config_payload(body['blob']), ensure_ascii=False))
                return
            nodes = [n for n in body.get('nodes') or [] if n.get('host') and n.get('port')]
            if self.path == '/api/probe':
                timeout = float(body.get('timeout') or 3)
                results = []
                for node in nodes:
                    ok, ms, err = tcp_probe(node['host'], node['port'], timeout)
                    results.append({**node, 'alive': ok, 'ms': round(ms, 1), 'error': err})
                self._send(200, json.dumps({
                    'results': results,
                    'summary': summarize([r['ms'] for r in results if r['alive']],
                                         len(results) - len([r for r in results if r['alive']]), 0.001),
                }, ensure_ascii=False))
                return
            if self.path == '/api/bench':
                stats = bench(nodes,
                              int(body.get('workers') or 32),
                              int(body.get('rounds') or 3),
                              float(body.get('timeout') or 3))
                self._send(200, json.dumps(stats, ensure_ascii=False))
                return
            self._send(404, json.dumps({'error': 'not found'}))
        except Exception as exc:  # keep the demo alive, report the failure
            self._send(400, json.dumps({'error': str(exc)}, ensure_ascii=False))


if __name__ == '__main__':
    print('RAJ Tunnel VPN demo on http://127.0.0.1:%d' % PORT)
    print('myKey =', rd.MYKEY.decode(), '| sha256 =', rd.K.hex())
    ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
