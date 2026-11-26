import http.client
import importlib.util
import json
from pathlib import Path
import socket
import threading
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'ext' / 'lp_scan_server.py'
spec = importlib.util.spec_from_file_location('lp_scan_server', MODULE)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class HttpJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = scan.ThreadingHTTPServer(('127.0.0.1', 0), scan.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, body, content_length=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            headers = {'Content-Type': 'application/json'}
            if content_length is not None:
                headers['Content-Length'] = str(content_length)
            conn.request('POST', '/api/awdp/delete', body=body, headers=headers)
            # Let the broken negative-length implementation finish reading until EOF.
            if content_length is not None:
                conn.sock.shutdown(socket.SHUT_WR)
            try:
                response = conn.getresponse()
                return response.status, response.read(), response.will_close
            except http.client.RemoteDisconnected:
                return None, b'connection closed without a response', True
        finally:
            conn.close()

    def test_non_object_json_is_a_client_error(self):
        for value in [[], ['item'], 'text', 7, True, None]:
            with self.subTest(value=value):
                status, body, _ = self.request(json.dumps(value))
                self.assertEqual(status, 400, body)

    def test_malformed_json_is_a_client_error(self):
        status, body, _ = self.request('{')
        self.assertEqual(status, 400, body)

    def test_integer_exceeding_parser_limit_is_a_client_error(self):
        status, body, _ = self.request('{"id": ' + '9' * 5000 + '}')
        self.assertEqual(status, 400, body)

    def test_negative_content_length_is_rejected(self):
        status, body, closed = self.request('', -1)
        self.assertEqual(status, 400, body)
        self.assertTrue(closed)

    def test_non_numeric_content_length_is_rejected(self):
        status, body, closed = self.request('', 'invalid')
        self.assertEqual(status, 400, body)
        self.assertTrue(closed)

    def test_oversized_body_is_rejected_without_waiting_for_payload(self):
        status, body, closed = self.request('', scan.MAX_BODY + 1)
        self.assertEqual(status, 413, body)
        self.assertTrue(closed)

    def test_truncated_body_is_rejected(self):
        status, body, closed = self.request('{}', 8)
        self.assertEqual(status, 400, body)
        self.assertTrue(closed)

    def test_valid_object_reaches_route_validation(self):
        status, body, _ = self.request('{}')
        self.assertEqual(status, 404, body)

    def test_health_remains_available(self):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            conn.request('GET', '/api/health')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(json.loads(response.read())['ok'])
        finally:
            conn.close()


if __name__ == '__main__':
    unittest.main()
