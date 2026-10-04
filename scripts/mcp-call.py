#!/usr/bin/env python3
"""Call the local Mechanize MCP using its private Scy file credential reference."""
import argparse
import ipaddress
import json
import os
import stat
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 1 << 20:
            raise ValueError('private regular file required')
        with os.fdopen(fd, 'r') as source:
            fd = -1
            return source.read()
    finally:
        if fd >= 0:
            os.close(fd)

def call(config, name, arguments, url='http://127.0.0.1:4987/mcp'):
    endpoint = urllib.parse.urlsplit(url)
    if endpoint.scheme != 'http' or not ipaddress.ip_address(endpoint.hostname).is_loopback or endpoint.path != '/mcp' or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('fixed loopback MCP endpoint required')
    settings = json.loads(private_read(config))
    resource = settings.get('stdioCredential', {})
    credential_path = resource.get('URL', '')
    if not os.path.isabs(credential_path) or resource.get('Fallback') or resource.get('Data'):
        raise ValueError('explicit private file credential reference required')
    token = private_read(credential_path).strip()
    if not token or len(token) > 32768:
        raise ValueError('bounded credential required')
    params = {'name': name, 'arguments': arguments, '_meta': {
        'io.modelcontextprotocol/protocolVersion':'2026-07-28',
        'io.modelcontextprotocol/clientCapabilities':{}}}
    body = json.dumps({'jsonrpc':'2.0', 'id':1, 'method':'tools/call', 'params':params}).encode()
    if len(body) > 1 << 20:
        raise ValueError('bounded tool request required')
    headers = {'Authorization':'Bearer '+token, 'Content-Type':'application/json',
               'Accept':'application/json, text/event-stream', 'Mcp-Protocol-Version':'2026-07-28',
               'Mcp-Method':'tools/call', 'Mcp-Name':name}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(urllib.request.Request(url, data=body, headers=headers), timeout=45) as reply:
        raw = reply.read((4 << 20) + 1)
        if len(raw) > 4 << 20:
            raise ValueError('bounded response required')
        if reply.headers.get('Content-Type', '').startswith('text/event-stream'):
            result = next(json.loads(line[5:].strip()) for line in raw.decode().splitlines() if line.startswith('data:') and json.loads(line[5:].strip()).get('id') == 1)
        else:
            result = json.loads(raw)
    if result.get('id') != 1 or 'error' in result:
        raise ValueError('MCP protocol request failed')
    return result['result']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--tool', required=True)
    parser.add_argument('--url', default='http://127.0.0.1:4987/mcp')
    options = parser.parse_args()
    # Tool arguments use stdin, so sensitive arguments need not appear in argv.
    import sys
    raw = sys.stdin.read((1 << 20) + 1)
    if len(raw.encode()) > 1 << 20:
        raise ValueError('bounded arguments required')
    arguments = json.loads(raw or '{}')
    if not isinstance(arguments, dict):
        raise ValueError('object arguments required')
    result = call(options.config, options.tool, arguments, options.url)
    print(json.dumps(result))
    return 3 if result.get('isError') else 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Never print credential values or a request body from an exception.
        raise SystemExit('Mechanize tool call failed: ' + type(error).__name__)
