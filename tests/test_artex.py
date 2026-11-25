import json
import unittest
from unittest.mock import patch

from penlocal.artex import ArtexClient, ArtexConfig, ArtexError


class ArtexClientTests(unittest.TestCase):
    def test_rejects_non_http_url(self):
        with self.assertRaises(ArtexError):
            ArtexClient(ArtexConfig("file:///etc/passwd"))

    def test_rejects_endpoint_escape(self):
        with self.assertRaises(ArtexError):
            ArtexClient(ArtexConfig("http://127.0.0.1:8787", endpoints={"tasks": "//evil.test"}))

    @patch("penlocal.artex.urlopen")
    def test_uses_get_and_bearer_token(self, open_url):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b'{"items": []}'
        open_url.return_value = Response()
        client = ArtexClient(ArtexConfig("http://127.0.0.1:8787", "secret"))
        self.assertEqual(client.collection("tasks"), {"items": []})
        request = open_url.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")

    @patch("penlocal.artex.urlopen")
    def test_status_reports_connection_error_without_traceback(self, open_url):
        from urllib.error import URLError
        open_url.side_effect = URLError("offline")
        client = ArtexClient(ArtexConfig("http://127.0.0.1:8787"))
        self.assertFalse(client.status()["reachable"])


if __name__ == "__main__":
    unittest.main()
