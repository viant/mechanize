#!/usr/bin/env python3
"""Local, metadata-only OTLP/HTTP JSON receiver for development profiling."""
import argparse
import datetime
import gzip
import hmac
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 8 * 1024 * 1024
SAFE_TEXT = re.compile(r'^[A-Za-z0-9_.:/-]{1,192}$')
TEXT_KEYS = {'tool', 'toolname', 'model', 'modelslug', 'provider', 'authmode',
             'originator', 'sessionsource', 'appversion', 'servicename',
             'serviceversion', 'environment', 'deploymentenvironment',
             'eventname', 'kind', 'status', 'errorcode', 'method'}
ID_KEYS = {'conversationid', 'sessionid', 'threadid', 'turnid', 'callid',
           'operationid', 'runid', 'requestid', 'traceid', 'spanid'}


def value(v):
    for key in ('stringValue', 'intValue', 'doubleValue', 'boolValue'):
        if key in v:
            return v[key]
    return None


def attributes(items):
    result = {}
    for item in items[:256]:
        key = item.get('key', '')
        normalized = re.sub('[^a-z0-9]', '', key.lower())
        v = value(item.get('value', {}))
        if normalized in TEXT_KEYS | ID_KEYS and isinstance(v, str) and SAFE_TEXT.fullmatch(v):
            result[key] = v
        elif normalized in {'success', 'approved', 'cancelled', 'cached'} and isinstance(v, bool):
            result[key] = v
        elif any(word in normalized for word in ('duration', 'latency', 'elapsed', 'tokens', 'tokencount')) or normalized in {'attempt', 'retrycount', 'statuscode', 'httpstatuscode', 'promptlength'}:
            if isinstance(v, (int, float)) or isinstance(v, str) and re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?', v):
                number = float(v)
                if math.isfinite(number):
                    result[key] = int(number) if number.is_integer() else number
    return result


def name(v):
    return v if isinstance(v, str) and SAFE_TEXT.fullmatch(v) else 'redacted-name'


def project(path, payload):
    rows = []
    groups = {'/v1/logs': ('resourceLogs', 'scopeLogs', 'logRecords'),
              '/v1/traces': ('resourceSpans', 'scopeSpans', 'spans'),
              '/v1/metrics': ('resourceMetrics', 'scopeMetrics', 'metrics')}
    root_key, scope_key, item_key = groups[path]
    if root_key not in payload:
        raise ValueError('Unexpected OTLP signal')
    for resource in payload[root_key][:128]:
        common = attributes(resource.get('resource', {}).get('attributes', []))
        for scope in resource.get(scope_key, [])[:128]:
            for item in scope.get(item_key, [])[:4096]:
                row = {'signal': path.rsplit('/', 1)[-1], 'resource': common,
                       'attributes': attributes(item.get('attributes', []))}
                if path == '/v1/logs':
                    candidates = [item.get('eventName'), row['attributes'].get('event.name'),
                                  row['attributes'].get('event_name'), value(item.get('body', {}))]
                    row['name'] = next((v for v in candidates if isinstance(v, str) and v.startswith('codex.') and SAFE_TEXT.fullmatch(v)), 'redacted-name')
                    stamp = str(item.get('timeUnixNano', ''))
                    if re.fullmatch('[0-9]{1,24}', stamp):
                        row['timeUnixNano'] = stamp
                    for key in ('traceId', 'spanId'):
                        if item.get(key):
                            row[key] = name(item[key])
                elif path == '/v1/traces':
                    row.update(name=name(item.get('name')), traceId=name(item.get('traceId')),
                               spanId=name(item.get('spanId')), parentSpanId=name(item.get('parentSpanId')))
                    start, end = int(item.get('startTimeUnixNano', 0)), int(item.get('endTimeUnixNano', 0))
                    row['duration_ms'] = max(0, end-start)/1000000
                    code = item.get('status', {}).get('code')
                    if code in (0, 1, 2, 'STATUS_CODE_UNSET', 'STATUS_CODE_OK', 'STATUS_CODE_ERROR'):
                        row['status_code'] = code
                else:
                    row['name'] = name(item.get('name'))
                    points = []
                    for kind in ('gauge', 'sum', 'histogram', 'exponentialHistogram', 'summary'):
                        for point in item.get(kind, {}).get('dataPoints', [])[:1024]:
                            p = {'kind': kind, 'attributes': attributes(point.get('attributes', []))}
                            for key in ('asInt', 'asDouble', 'count', 'sum', 'min', 'max', 'timeUnixNano', 'startTimeUnixNano'):
                                v = point.get(key)
                                if isinstance(v, (int, float)) or isinstance(v, str) and re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?', v):
                                    p[key] = v
                            points.append(p)
                    row['points'] = points
                rows.append(row)
                if len(rows) >= 10000:
                    raise ValueError('Batch exceeds record bound')
    return rows


class Sink:
    def __init__(self, directory, token):
        self.directory, self.token = Path(directory), token
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Private owned output directory required')
        self.lock = threading.Lock()
        self.records = 0

    def append(self, rows):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data = ''.join(json.dumps({'receivedAt': now, **r}, allow_nan=False)+'\n' for r in rows).encode()
        path = self.directory / 'events.jsonl'
        with self.lock:
            if path.exists() and path.stat().st_size > 16 * 1024 * 1024:
                for index in range(3, 0, -1):
                    old = self.directory / ('events.%d.jsonl' % index)
                    if old.exists():
                        os.replace(old, self.directory / ('events.%d.jsonl' % (index+1)))
                os.replace(path, self.directory / 'events.1.jsonl')
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'ab') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise ValueError('Private regular log required')
                stream.write(data)
            self.records += len(rows)


def handler(sink):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.reply(200 if self.path == '/healthz' else 404, {'ok': self.path == '/healthz', 'records': sink.records, 'pid': os.getpid()})

        def do_POST(self):
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+sink.token):
                return self.reply(401, {})
            if self.path not in ('/v1/logs', '/v1/traces', '/v1/metrics'):
                return self.reply(404, {})
            try:
                length = int(self.headers.get('Content-Length', 0))
                if not 0 < length <= MAX_BODY:
                    return self.reply(413, {})
                self.connection.settimeout(5)
                raw = self.rfile.read(length)
                if self.headers.get('Content-Encoding') == 'gzip':
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(MAX_BODY+1)
                if len(raw) > MAX_BODY:
                    return self.reply(413, {})
                rows = project(self.path, json.loads(raw))
                sink.append(rows)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError):
                return self.reply(400, {})
            self.reply(200, {})
    return Handler


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--token-file', required=True, type=Path)
    parser.add_argument('--port', type=int, default=4318)
    args = parser.parse_args()
    info = args.token_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
        raise ValueError('Private owned token file required')
    token = args.token_file.read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', token):
        raise ValueError('Local receiver token required')
    server = ThreadingHTTPServer(('127.0.0.1', args.port), handler(Sink(args.directory, token)))
    server.daemon_threads = True
    server.serve_forever()
