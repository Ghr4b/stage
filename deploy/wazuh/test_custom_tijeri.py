import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request


SCRIPT = Path(__file__).with_name("custom-tijeri.py")
SPEC = importlib.util.spec_from_file_location("custom_tijeri", SCRIPT)
INTEGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INTEGRATION)


class FakeResponse:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        if self.error:
            raise self.error
        return self.response


class WazuhIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.alert_path = Path(self.temp_dir.name) / "alert.json"
        self.alert = {"agent": {"id": "001", "name": "host-a", "ip": "192.0.2.4"}, "syscheck": {"path": "/etc/hosts"}}
        self.alert_path.write_text(json.dumps(self.alert), encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def send(self, opener, url="https://tijeri.example/api/v1/webhooks/wazuh", token="t" * 32):
        return INTEGRATION.send_alert(self.alert_path, url, token, opener_factory=lambda *handlers: opener)

    def test_posts_json_with_bearer_token_and_timeout(self):
        opener = FakeOpener()
        self.send(opener)

        self.assertEqual(opener.request.method, "POST")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer " + "t" * 32)
        self.assertEqual(opener.request.get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(opener.request.data), self.alert)
        self.assertEqual(opener.timeout, 10)

    def test_rejects_non_https_urls(self):
        with self.assertRaises(ValueError):
            self.send(FakeOpener(), url="http://tijeri.example/webhook")

    def test_rejects_embedded_url_credentials(self):
        with self.assertRaises(ValueError):
            self.send(FakeOpener(), url="https://user:secret@tijeri.example/webhook")

    def test_rejects_short_tokens(self):
        with self.assertRaises(ValueError):
            self.send(FakeOpener(), token="short")

    def test_rejects_oversized_alerts(self):
        self.alert_path.write_bytes(b" " * (INTEGRATION.MAX_ALERT_BYTES + 1))
        with self.assertRaises(ValueError):
            self.send(FakeOpener())

    def test_non_success_response_fails_delivery(self):
        opener = FakeOpener(response=type("Response", (), {"status": 302, "__enter__": lambda self: self, "__exit__": lambda *args: False})())
        with self.assertRaises(ValueError):
            self.send(opener)

    def test_http_error_is_not_swallowed(self):
        opener = FakeOpener(error=HTTPError("https://tijeri.example", 503, "unavailable", {}, io.BytesIO()))
        with self.assertRaises(HTTPError):
            self.send(opener)


if __name__ == "__main__":
    unittest.main()
