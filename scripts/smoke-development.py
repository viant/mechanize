#!/usr/bin/env python3
"""Read-only authenticated installed-broker smoke; never logs credentials."""
import argparse
import ipaddress
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def private_text(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 1 << 20:
            raise ValueError('private owner-only bounded regular file required')
        with os.fdopen(fd, 'r') as source:
            fd = -1
            return source.read()
    finally:
        if fd >= 0:
            os.close(fd)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credential', required=True)
    parser.add_argument('--url', default='http://127.0.0.1:4987/mcp')
    args = parser.parse_args()
    target = urllib.parse.urlsplit(args.url)
    if target.scheme != 'http' or not ipaddress.ip_address(target.hostname).is_loopback or target.username or target.password or target.query or target.fragment or target.path != '/mcp':
        raise ValueError('fixed loopback MCP endpoint required')
    token = private_text(args.credential).strip()
    if not isinstance(token, str) or not token or len(token) > 32768:
        raise ValueError('bounded token credential required')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def request(method, params, sequence, authenticated=True):
        params = dict(params, _meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}})
        payload = json.dumps({'jsonrpc': '2.0', 'id': sequence, 'method': method, 'params': params}).encode()
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + token
        with opener.open(urllib.request.Request(args.url, data=payload, headers=headers), timeout=15) as reply:
            raw = reply.read((1 << 20) + 1)
            if len(raw) > 1 << 20:
                raise ValueError('oversized MCP response')
            if reply.headers.get('Content-Type', '').startswith('text/event-stream'):
                records = [json.loads(line[5:].strip()) for line in raw.decode().splitlines() if line.startswith('data:')]
                result = next(item for item in records if item.get('id') == sequence)
            else:
                result = json.loads(raw)
            if result.get('id') != sequence or 'error' in result or 'result' not in result:
                print(json.dumps({'failedMethod':method,'replyId':result.get('id'),'errorCode':result.get('error',{}).get('code'),'errorMessage':result.get('error',{}).get('message')}))
                raise ValueError('MCP request failed')
            return result['result']
    try:
        request('tools/list', {}, 1, False)
        raise ValueError('unauthenticated request accepted')
    except urllib.error.HTTPError as denied:
        if denied.code != 401:
            raise ValueError('unexpected unauthenticated status') from None
    initialized = request('server/discover', {}, 2)
    tools = request('tools/list', {}, 3)
    names = sorted(item['name'] for item in tools['tools'])
    required = {'mechanize_state_get', 'mechanize_recovery_context', 'mechanize_capture', 'mechanize_scenario_list'}
    if not required.issubset(names):
        print(json.dumps({'discoveredTools':names}))
        raise ValueError('required MCP tools missing')
    print(json.dumps({'unauthenticatedStatus':401, 'protocolVersion':'2026-07-28', 'toolCount':len(names), 'requiredToolsDiscovered':True, 'desktopInputPerformed':False}))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Exception bodies can include remote payloads; report only their type.
        raise SystemExit('read-only smoke failed: ' + type(error).__name__ + (' status=' + str(error.code) if isinstance(error, urllib.error.HTTPError) else ''))
