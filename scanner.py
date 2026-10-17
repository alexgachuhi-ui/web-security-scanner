import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps restrict which resources a browser can load.",
    "Strict-Transport-Security":
        "Tells browsers to use HTTPS for future connections.",
    "X-Content-Type-Options":
        "Helps prevent MIME-type sniffing.",
    "X-Frame-Options":
        "Helps control whether a page can be embedded in frames.",
    "Referrer-Policy":
        "Controls how much referrer information browsers send.",
}


def scan_website(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("Error: enter a valid HTTP or HTTPS URL.")
        return

    request = Request(
        url,
        headers={"User-Agent": "WebSecurityScanner/1.0"},
        method="GET",
    )

    try:
        with urlopen(request, timeout=10) as response:
            status = response.status
            headers = response.headers

    except HTTPError as error:
        status = error.code
        headers = error.headers

    except (URLError, TimeoutError, OSError) as error:
        print(f"Request failed: {error}")
        return

    print(f"\nWebsite: {url}")
    print(f"HTTP status: {status}")
    print("\n--- Security Header Report ---")

    findings = []

    for header, explanation in SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and parsed.scheme != "https":
            print(f"\n[SKIPPED] {header}")
            print("HSTS should be evaluated over HTTPS.")
            continue

        if headers.get(header):
            print(f"\n[PRESENT] {header}")
        else:
            print(f"\n[MISSING] {header}")
            findings.append(header)

        print(f"  Purpose: {explanation}")

    print("\n--- Summary ---")
    print(f"Missing headers: {len(findings)}")
    print(f"Headers checked: {len(SECURITY_HEADERS)}")

    if findings:
        print("Review the missing headers against the site's requirements.")
    else:
        print("No missing headers were detected in these checks.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py https://example.com")
        sys.exit(1)

    scan_website(sys.argv[1])
