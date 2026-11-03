import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import codex_otel_receiver as receiver


class ReceiverTests(unittest.TestCase):
    def payload(self):
        return {'resourceLogs': [{'resource': {'attributes': [
            {'key': 'service.name', 'value': {'stringValue': 'codex_cli_rs'}},
            {'key': 'user.email', 'value': {'stringValue': 'PRIVATE_CANARY'}}]},
            'scopeLogs': [{'logRecords': [{'body': {'stringValue': 'PRIVATE_CANARY'},
                'attributes': [
                    {'key': 'event.name', 'value': {'stringValue': 'codex.tool_result'}},
                    {'key': 'tool_name', 'value': {'stringValue': 'fixture.tool'}},
                    {'key': 'duration_ms', 'value': {'doubleValue': 123.5}},
                    {'key': 'input_tokens', 'value': {'intValue': '17'}},
                    {'key': 'arguments', 'value': {'stringValue': 'PRIVATE_CANARY'}},
                    {'key': 'output', 'value': {'stringValue': 'PRIVATE_CANARY'}}]}]}]}]}

    def test_metadata_projection_drops_content_and_identity(self):
        rows = receiver.project('/v1/logs', self.payload())
        self.assertNotIn('PRIVATE_CANARY', json.dumps(rows))
        self.assertEqual(rows[0]['name'], 'codex.tool_result')
        self.assertEqual(rows[0]['attributes']['duration_ms'], 123.5)
        self.assertEqual(rows[0]['attributes']['input_tokens'], 17)

    def test_trace_duration_and_metric_values(self):
        trace = {'resourceSpans': [{'scopeSpans': [{'spans': [{'name': 'codex.tool_call',
            'startTimeUnixNano': '1000000', 'endTimeUnixNano': '3500000',
            'status': {'code': 2, 'message': 'PRIVATE_CANARY'}}]}]}]}
        rows = receiver.project('/v1/traces', trace)
        self.assertEqual(rows[0]['duration_ms'], 2.5)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(rows))
        metric = {'resourceMetrics': [{'scopeMetrics': [{'metrics': [{'name': 'codex.tool.call.duration_ms',
            'histogram': {'dataPoints': [{'count': '3', 'sum': 15.5, 'attributes': []}]}}]}]}]}
        self.assertEqual(receiver.project('/v1/metrics', metric)[0]['points'][0]['count'], '3')

    def test_loopback_authentication_and_private_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            sink = receiver.Sink(directory, 'fixture-token')
            server = receiver.ThreadingHTTPServer(('127.0.0.1', 0), receiver.handler(sink))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = 'http://127.0.0.1:%d/v1/logs' % server.server_port
                data = json.dumps(self.payload()).encode()
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=2)
                self.assertEqual(denied.exception.code, 401)
                self.assertEqual(sink.records, 0)
                req = urllib.request.Request(url, data=data, headers={'Authorization': 'Bearer fixture-token', 'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                path = Path(directory) / 'events.jsonl'
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn('PRIVATE_CANARY', path.read_text())
                self.assertEqual(sink.records, 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
