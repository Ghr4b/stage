#!/usr/bin/env python3
import json
import os
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener


MAX_ALERT_BYTES = 1 << 20


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def send_alert(alert_path, hook_url, api_token, ca_bundle=None, opener_factory=build_opener):
    parsed_url = urlsplit(hook_url)
    if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password:
        raise ValueError("TIJERI_WAZUH_WEBHOOK_URL must be an HTTPS URL without embedded credentials")
    if len(api_token) < 32:
        raise ValueError("TIJERI_API_TOKEN must contain at least 32 characters")

    alert_file = Path(alert_path)
    if alert_file.stat().st_size > MAX_ALERT_BYTES:
        raise ValueError("Wazuh alert exceeds the maximum size")
    with alert_file.open("r", encoding="utf-8") as source:
        alert = json.load(source)
    if not isinstance(alert, dict):
        raise ValueError("Wazuh alert must be a JSON object")

    request = Request(
        hook_url,
        data=json.dumps(alert, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + api_token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    tls_context = ssl.create_default_context(cafile=ca_bundle or None)
    opener = opener_factory(NoRedirectHandler, HTTPSHandler(context=tls_context))
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as error:
        error.close()
        raise
    with response:
        if response.status < 200 or response.status >= 300:
            raise ValueError("Tijeri returned a non-success status")


def main(argv=None):
    arguments = sys.argv if argv is None else argv
    if len(arguments) < 2:
        sys.stderr.write("Wazuh alert path is required.\n")
        return 2

    hook_url = os.environ.get("TIJERI_WAZUH_WEBHOOK_URL", "")
    api_token = os.environ.get("TIJERI_API_TOKEN", "")
    ca_bundle = os.environ.get("TIJERI_CA_BUNDLE")
    try:
        send_alert(arguments[1], hook_url, api_token, ca_bundle)
    except (OSError, ValueError, json.JSONDecodeError, HTTPError, URLError, TimeoutError) as error:
        status = getattr(error, "code", None)
        message = "Tijeri rejected the Wazuh alert (HTTP {}).".format(status) if status else "Could not deliver the Wazuh alert."
        sys.stderr.write(message + "\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
