import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'ext' / 'lp_scan_server.py'
spec = importlib.util.spec_from_file_location('lp_scan_server', MODULE)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class SessionPathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name)
        self.root = self.parent / 'sessions'
        self.root.mkdir()
        self.env = patch.dict(os.environ, {'LP_AWDP_DIR': str(self.root)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_current_directory_is_not_a_session(self):
        self.assertIsNone(scan.awdp_session_dir('.'))

    def test_parent_directory_is_not_a_session(self):
        self.assertIsNone(scan.awdp_session_dir('..'))

    def test_symlink_cannot_escape_session_root(self):
        outside = self.parent / 'outside'
        outside.mkdir()
        (self.root / 'linked').symlink_to(outside, target_is_directory=True)
        self.assertIsNone(scan.awdp_session_dir('linked'))

    def test_existing_named_session_is_found(self):
        session = self.root / '20261126-demo'
        session.mkdir()
        self.assertEqual(scan.awdp_session_dir(session.name), str(session.resolve()))

    def test_missing_or_invalid_session_is_not_found(self):
        for name in ['', 'missing', '../outside', '/outside', 'a/b']:
            with self.subTest(name=name):
                self.assertIsNone(scan.awdp_session_dir(name))

    def test_delete_parent_id_does_not_remove_any_parent_files(self):
        # All files, including the parent being targeted, belong to this test's temp dir.
        sentinel = self.parent / 'keep.txt'
        sentinel.write_text('keep')
        server = scan.ThreadingHTTPServer(('127.0.0.1', 0), scan.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        conn = http.client.HTTPConnection(*server.server_address, timeout=2)
        try:
            conn.request('POST', '/api/awdp/delete', json.dumps({'id': '..'}),
                         {'Content-Type': 'application/json'})
            response = conn.getresponse()
            response.read()
            self.assertTrue(sentinel.exists(), "删除请求不得影响会话根目录之外的文件")
            self.assertEqual(response.status, 404)
            self.assertEqual(sentinel.read_text(), 'keep')
            self.assertTrue(self.root.is_dir())
        finally:
            conn.close()
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
