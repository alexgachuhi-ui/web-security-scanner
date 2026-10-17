import unittest
from unittest.mock import patch
from email.message import Message

from scanner import SECURITY_HEADERS, scan_website


class ScannerTests(unittest.TestCase):

    def test_security_headers_are_defined(self):
        self.assertIn("Content-Security-Policy", SECURITY_HEADERS)
        self.assertIn("X-Content-Type-Options", SECURITY_HEADERS)

    @patch("builtins.print")
    def test_invalid_url_is_rejected(self, mock_print):
        scan_website("not-a-valid-url")

        output = " ".join(
            str(call) for call in mock_print.call_args_list
        )
        self.assertIn("Error", output)

    @patch("scanner.urlopen")
    @patch("builtins.print")
    def test_missing_headers_are_reported(
        self, mock_print, mock_urlopen
    ):
        headers = Message()
        headers["Content-Security-Policy"] = "default-src 'self'"

        response = mock_urlopen.return_value.__enter__.return_value
        response.status = 200
        response.headers = headers

        scan_website("https://example.com")

        output = " ".join(
            str(call) for call in mock_print.call_args_list
        )
        self.assertIn("[PRESENT] Content-Security-Policy", output)
        self.assertIn("[MISSING] Referrer-Policy", output)


if __name__ == "__main__":
    unittest.main()
