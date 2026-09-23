import os
import re
import json
import time
import hashlib
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup


# ============================================================
# CONFIG
# ============================================================

TARGET = os.environ.get(
    "TARGET_URL",
    "https://www.mirpurcollege.edu.bd/"
).rstrip("/")

REPORT_DIR = "reports"

TIMEOUT = 15

MAX_DISCOVERED_URLS = 150

REQUEST_DELAY = 0.25

USER_AGENT = (
    "Authorized-Security-Audit/2.0 "
    "(Passive Non-Destructive Scanner)"
)

os.makedirs(REPORT_DIR, exist_ok=True)


# ============================================================
# SESSION
# ============================================================

session = requests.Session()

session.headers.update({
    "User-Agent": USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/xml;q=0.9,*/*;q=0.8"
    )
})


# ============================================================
# REPORT STRUCTURE
# ============================================================

report = {
    "target": TARGET,
    "scan_type": "passive_non_destructive",
    "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "technologies": [],
    "server": None,
    "main_page": {},
    "security_headers": {},
    "cookies": [],
    "robots": {},
    "sitemap": {},
    "links": [],
    "forms": [],
    "interesting_public_links": [],
    "endpoint_checks": [],
    "findings": [],
    "errors": []
}


# ============================================================
# HELPERS
# ============================================================

def normalize_url(url):
    """
    Normalize URL and remove fragments.
    """
    try:
        url = urldefrag(url)[0]

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return None

        return url.rstrip("/") or url

    except Exception:
        return None


def same_host(url):
    """
    Check whether URL belongs to target hostname.
    """

    try:
        target_host = urlparse(TARGET).netloc.lower()
        host = urlparse(url).netloc.lower()

        return host == target_host

    except Exception:
        return False


def add_finding(severity, title, detail, url=None, evidence=None):
    """
    Add a security finding.
    """

    item = {
        "severity": severity,
        "title": title,
        "detail": detail
    }

    if url:
        item["url"] = url

    if evidence:
        item["evidence"] = evidence

    report["findings"].append(item)


def safe_get(url):
    """
    Safe GET request.
    """

    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        time.sleep(REQUEST_DELAY)

        return response

    except requests.RequestException as e:

        report["errors"].append({
            "url": url,
            "error": str(e)
        })

        return None


def response_preview(text, max_chars=350):
    """
    Small evidence preview.
    """

    text = re.sub(
        r"\s+",
        " ",
        text or ""
    ).strip()

    return text[:max_chars]


def is_html(response):
    content_type = (
        response.headers.get(
            "Content-Type",
            ""
        ).lower()
    )

    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
    )


# ============================================================
# MAIN PAGE
# ============================================================

print("=" * 60)
print("AUTHORIZED WEBSITE SECURITY AUDIT")
print("=" * 60)
print()
print("Target:", TARGET)
print()

main_response = safe_get(TARGET)

if not main_response:

    add_finding(
        "ERROR",
        "Website unreachable",
        "The target could not be reached."
    )

else:

    report["server"] = main_response.headers.get(
        "Server"
    )

    report["main_page"] = {
        "status_code": main_response.status_code,
        "final_url": main_response.url,
        "content_type": main_response.headers.get(
            "Content-Type"
        ),
        "content_length": len(
            main_response.content
        ),
        "server": main_response.headers.get(
            "Server"
        ),
        "powered_by": main_response.headers.get(
            "X-Powered-By"
        )
    }


# ============================================================
# SECURITY HEADERS
# ============================================================

if main_response:

    security_headers = {

        "Content-Security-Policy": {
            "severity": "LOW",
            "reason": (
                "CSP can reduce the impact of "
                "some content-injection/XSS attacks."
            )
        },

        "X-Frame-Options": {
            "severity": "LOW",
            "reason": (
                "Provides clickjacking protection "
                "when appropriately configured."
            )
        },

        "X-Content-Type-Options": {
            "severity": "LOW",
            "reason": (
                "Helps prevent MIME-type sniffing."
            )
        },

        "Referrer-Policy": {
            "severity": "LOW",
            "reason": (
                "Controls referrer information "
                "sent by browsers."
            )
        },

        "Permissions-Policy": {
            "severity": "LOW",
            "reason": (
                "Can restrict browser features "
                "such as camera, microphone, etc."
            )
        },

        "Strict-Transport-Security": {
            "severity": "LOW",
            "reason": (
                "Allows browsers to enforce HTTPS "
                "for future connections."
            )
        }
    }

    for header, info in security_headers.items():

        value = main_response.headers.get(header)

        if value:

            report["security_headers"][header] = {
                "present": True,
                "value": value
            }

        else:

            report["security_headers"][header] = {
                "present": False
            }

            add_finding(
                info["severity"],
                f"Missing security header: {header}",
                info["reason"]
            )


# ============================================================
# COOKIE ANALYSIS
# ============================================================

if main_response:

    set_cookie_headers = main_response.raw.headers.get_all(
        "Set-Cookie"
    )

    if set_cookie_headers:

        for cookie in set_cookie_headers:

            cookie_lower = cookie.lower()

            name = cookie.split(
                "=",
                1
            )[0].strip()

            cookie_info = {
                "name": name,
                "secure": "secure" in cookie_lower,
                "httponly": "httponly" in cookie_lower,
                "samesite": None
            }

            same_site_match = re.search(
                r"samesite\s*=\s*([^;\s]+)",
                cookie,
                re.I
            )

            if same_site_match:

                cookie_info["samesite"] = (
                    same_site_match.group(1)
                )

            report["cookies"].append(
                cookie_info
            )

            # Session cookies deserve extra attention.

            sensitive_name = any(
                keyword in name.lower()
                for keyword in [
                    "session",
                    "auth",
                    "token"
                ]
            )

            if sensitive_name:

                if not cookie_info["secure"]:

                    add_finding(
                        "MEDIUM",
                        "Sensitive cookie without Secure flag",
                        (
                            "A session/authentication-related "
                            "cookie does not appear to have "
                            "the Secure attribute."
                        )
                    )

                if not cookie_info["httponly"]:

                    add_finding(
                        "MEDIUM",
                        "Sensitive cookie without HttpOnly flag",
                        (
                            "A potentially sensitive cookie "
                            "does not appear to have HttpOnly."
                        )
                    )

                if cookie_info["samesite"] is None:

                    add_finding(
                        "LOW",
                        "Sensitive cookie without SameSite attribute",
                        (
                            "Review whether SameSite should be "
                            "configured for this cookie."
                        )
                    )


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

technologies = set()

if main_response:

    html = main_response.text

    html_lower = html.lower()

    headers_lower = str(
        dict(main_response.headers)
    ).lower()


    # Server / backend hints

    if "laravel_session" in headers_lower:
        technologies.add("Laravel")

    if "laravel" in html_lower:
        technologies.add("Laravel")


    if "wordpress" in html_lower:
        technologies.add("WordPress")

    if "wp-content" in html_lower:
        technologies.add("WordPress")


    if "bootstrap" in html_lower:
        technologies.add("Bootstrap")


    if "jquery" in html_lower:
        technologies.add("jQuery")


    if "react" in html_lower:
        technologies.add("React")


    if "vue" in html_lower:
        technologies.add("Vue.js")


    if "angular" in html_lower:
        technologies.add("Angular")


    powered_by = main_response.headers.get(
        "X-Powered-By"
    )

    if powered_by:

        technologies.add(
            "X-Powered-By: " + powered_by
        )


report["technologies"] = sorted(
    technologies
)


# ============================================================
# HTML DISCOVERY
# ============================================================

discovered_urls = set()

if main_response and is_html(main_response):

    soup = BeautifulSoup(
        main_response.text,
        "html.parser"
    )


    # --------------------------------------------------------
    # LINKS
    # --------------------------------------------------------

    for tag in soup.find_all(
        "a",
        href=True
    ):

        raw_href = tag.get("href")

        if not raw_href:
            continue

        absolute = urljoin(
            main_response.url,
            raw_href
        )

        normalized = normalize_url(
            absolute
        )

        if not normalized:
            continue

        if same_host(normalized):

            discovered_urls.add(
                normalized
            )

            if len(discovered_urls) >= MAX_DISCOVERED_URLS:
                break


    # --------------------------------------------------------
    # FORMS
    # --------------------------------------------------------

    for form in soup.find_all("form"):

        action = form.get(
            "action",
            ""
        )

        method = form.get(
            "method",
            "GET"
        ).upper()

        action_url = normalize_url(
            urljoin(
                main_response.url,
                action
            )
        )

        form_data = {
            "action": action_url,
            "method": method,
            "inputs": []
        }

        for field in form.find_all(
            ["input", "textarea", "select"]
        ):

            form_data["inputs"].append({
                "name": field.get("name"),
                "type": field.get(
                    "type",
                    field.name
                )
            })

        report["forms"].append(
            form_data
        )


# ============================================================
# INTERESTING PUBLIC LINKS
# ============================================================

interesting_keywords = [
    "admin",
    "administrator",
    "login",
    "signin",
    "dashboard",
    "backend",
    "manage",
    "panel"
]

for url in sorted(discovered_urls):

    path = urlparse(
        url
    ).path.lower()

    if any(
        keyword in path
        for keyword in interesting_keywords
    ):

        report[
            "interesting_public_links"
        ].append(url)


# ============================================================
# ROBOTS.TXT
# ============================================================

robots_url = urljoin(
    TARGET + "/",
    "robots.txt"
)

robots_response = safe_get(
    robots_url
)

if robots_response:

    report["robots"] = {
        "url": robots_url,
        "status": robots_response.status_code,
        "content": robots_response.text[:5000]
    }


    # Note: robots.txt is NOT an access-control mechanism.

    disallowed = []

    for line in robots_response.text.splitlines():

        line = line.strip()

        if line.lower().startswith(
            "disallow:"
        ):

            path = line.split(
                ":",
                1
            )[1].strip()

            if path:
                disallowed.append(path)


    report["robots"]["disallowed_paths"] = (
        disallowed
    )


# ============================================================
# SITEMAP
# ============================================================

sitemap_candidates = [
    "sitemap.xml",
    "sitemap_index.xml"
]

for path in sitemap_candidates:

    sitemap_url = urljoin(
        TARGET + "/",
        path
    )

    sitemap_response = safe_get(
        sitemap_url
    )

    if sitemap_response and sitemap_response.status_code == 200:

        report["sitemap"] = {
            "url": sitemap_url,
            "status": sitemap_response.status_code,
            "content_type":
                sitemap_response.headers.get(
                    "Content-Type"
                ),
            "size":
                len(sitemap_response.content)
        }

        break


# ============================================================
# SAFE PUBLIC RESOURCE CHECKS
# ============================================================

# These are GET requests only.
#
# This does NOT attempt:
# - authentication bypass
# - SQL injection
# - password guessing
# - command execution
# - file upload
# - destructive actions

public_resources = [
    ".env",
    ".git/HEAD",
    "composer.json",
    "package.json",
    "phpinfo.php",
    "server-status",
    "server-info",
    "debug",
    "storage/logs/laravel.log"
]


for path in public_resources:

    url = urljoin(
        TARGET + "/",
        path
    )

    response = safe_get(
        url
    )

    if not response:
        continue

    item = {
        "url": url,
        "status": response.status_code,
        "content_type":
            response.headers.get(
                "Content-Type"
            ),
        "size":
            len(response.content)
    }

    report[
        "endpoint_checks"
    ].append(item)


    if response.status_code == 200:

        # Avoid automatically classifying every 200 as a vulnerability.
        #
        # Check obvious sensitive content indicators.

        body = response.text[:20000]

        sensitive_indicators = [
            "APP_KEY=",
            "DB_PASSWORD=",
            "DB_USERNAME=",
            "AWS_SECRET",
            "PRIVATE KEY",
            "[core]",
            '"dependencies"',
            '"require"'
        ]

        matches = [
            indicator
            for indicator in sensitive_indicators
            if indicator.lower()
            in body.lower()
        ]

        if matches:

            add_finding(
                "HIGH",
                f"Potential sensitive resource exposure: /{path}",
                (
                    "A publicly accessible resource returned "
                    "content containing potentially sensitive "
                    "configuration indicators."
                ),
                url=url,
                evidence=", ".join(matches)
            )

        else:

            add_finding(
                "INFO",
                f"Public resource returned HTTP 200: /{path}",
                (
                    "Verify manually whether this resource "
                    "is intended to be publicly accessible."
                ),
                url=url
            )


# ============================================================
# ERROR / DEBUG DISCLOSURE DETECTION
# ============================================================

error_patterns = {

    "stack trace": [
        r"stack\s*trace",
        r"traceback"
    ],

    "Laravel debug": [
        r"Whoops[,!]",
        r"Laravel\s+Exception",
        r"Illuminate\\"
    ],

    "Symfony debug": [
        r"Symfony\\Component",
        r"Symfony Exception"
    ],

    "PHP fatal error": [
        r"Fatal error:",
        r"Parse error:"
    ],

    "SQL error": [
        r"SQLSTATE\[[0-9A-Z]+\]",
        r"mysql_fetch",
        r"MySQL server version",
        r"PDOException"
    ],

    "debug information": [
        r"APP_DEBUG\s*=\s*true",
        r"debug\s*mode"
    ]
}


def detect_errors(
    response,
    url
):

    if not response:
        return

    if not is_html(response):
        return

    body = response.text

    body_lower = body.lower()

    matches = []

    for category, patterns in error_patterns.items():

        for pattern in patterns:

            if re.search(
                pattern,
                body,
                re.I
            ):

                matches.append(
                    category
                )

                break


    if matches:

        evidence = response_preview(
            body,
            500
        )

        add_finding(
            "MEDIUM",
            "Possible error/debug information exposure",
            (
                "The response contains indicators associated "
                "with server-side error/debug output."
            ),
            url=url,
            evidence={
                "patterns": sorted(set(matches)),
                "preview": evidence
            }
        )


# ============================================================
# CHECK MAIN PAGE FOR ERRORS
# ============================================================

detect_errors(
    main_response,
    TARGET
)


# ============================================================
# CHECK DISCOVERED PUBLIC URLS
# ============================================================

print()
print(
    f"Discovered URLs: {len(discovered_urls)}"
)
print()

for index, url in enumerate(
    sorted(discovered_urls),
    start=1
):

    if index > MAX_DISCOVERED_URLS:
        break

    print(
        f"[{index}/{min(len(discovered_urls), MAX_DISCOVERED_URLS)}] "
        f"{url}"
    )

    response = safe_get(
        url
    )

    if not response:
        continue

    endpoint_info = {
        "url": url,
        "status": response.status_code,
        "final_url": response.url,
        "content_type":
            response.headers.get(
                "Content-Type"
            ),
        "size":
            len(response.content),
        "server":
            response.headers.get(
                "Server"
            )
    }

    report[
        "endpoint_checks"
    ].append(endpoint_info)

    detect_errors(
        response,
        url
    )


# ============================================================
# INFORMATION DISCLOSURE CHECKS
# ============================================================

if main_response:

    headers = main_response.headers


    # Server version exposure

    server_header = headers.get(
        "Server"
    )

    if server_header:

        if re.search(
            r"/\d+\.\d+",
            server_header
        ):

            add_finding(
                "LOW",
                "Server version information exposed",
                (
                    "The Server response header appears "
                    "to include a software version."
                ),
                evidence=server_header
            )


    # X-Powered-By

    powered_by = headers.get(
        "X-Powered-By"
    )

    if powered_by:

        add_finding(
            "LOW",
            "Technology information exposed",
            (
                "X-Powered-By reveals backend technology "
                "information."
            ),
            evidence=powered_by
        )


# ============================================================
# STATUS CODE SUMMARY
# ============================================================

status_summary = {}

for item in report["endpoint_checks"]:

    status = str(
        item.get(
            "status",
            "unknown"
        )
    )

    status_summary[status] = (
        status_summary.get(
            status,
            0
        ) + 1
    )

report["status_summary"] = status_summary


# ============================================================
# DEDUPLICATION
# ============================================================

unique_findings = []

seen_findings = set()

for item in report["findings"]:

    key = (
        item.get("severity"),
        item.get("title"),
        item.get("url"),
        str(item.get("evidence"))
    )

    if key not in seen_findings:

        seen_findings.add(key)

        unique_findings.append(
            item
        )

report["findings"] = unique_findings


# ============================================================
# FINAL TIMESTAMP
# ============================================================

report["finished_at"] = (
    time.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
)


# ============================================================
# JSON REPORT
# ============================================================

json_path = os.path.join(
    REPORT_DIR,
    "audit-report.json"
)

with open(
    json_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        report,
        f,
        indent=2,
        ensure_ascii=False
    )


# ============================================================
# TEXT REPORT
# ============================================================

txt_path = os.path.join(
    REPORT_DIR,
    "audit-report.txt"
)

with open(
    txt_path,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "AUTHORIZED WEBSITE SECURITY AUDIT\n"
    )

    f.write(
        "==================================\n\n"
    )

    f.write(
        f"Target: {TARGET}\n"
    )

    f.write(
        "Scan type: Passive / Non-destructive\n\n"
    )


    # Technologies

    f.write(
        "TECHNOLOGIES\n"
    )

    f.write(
        "------------\n"
    )

    if report["technologies"]:

        for tech in report["technologies"]:

            f.write(
                f"- {tech}\n"
            )

    else:

        f.write(
            "No technology detected.\n"
        )


    f.write("\n")


    # Main page

    f.write(
        "MAIN PAGE\n"
    )

    f.write(
        "---------\n"
    )

    for key, value in report[
        "main_page"
    ].items():

        f.write(
            f"{key}: {value}\n"
        )


    f.write("\n")


    # Findings

    f.write(
        "FINDINGS\n"
    )

    f.write(
        "--------\n"
    )

    if not report["findings"]:

        f.write(
            "No findings detected.\n"
        )

    else:

        for number, item in enumerate(
            report["findings"],
            start=1
        ):

            f.write(
                f"\n[{number}] "
                f"[{item['severity']}] "
                f"{item['title']}\n"
            )

            f.write(
                f"Detail: "
                f"{item['detail']}\n"
            )

            if item.get("url"):

                f.write(
                    f"URL: "
                    f"{item['url']}\n"
                )

            if item.get("evidence"):

                f.write(
                    "Evidence:\n"
                )

                f.write(
                    json.dumps(
                        item["evidence"],
                        ensure_ascii=False,
                        indent=2
                    )
                )

                f.write("\n")


    # Interesting links

    f.write(
        "\nPUBLICLY DISCOVERED "
        "INTERESTING LINKS\n"
    )

    f.write(
        "-------------------------------\n"
    )

    if report[
        "interesting_public_links"
    ]:

        for url in report[
            "interesting_public_links"
        ]:

            f.write(
                f"- {url}\n"
            )

    else:

        f.write(
            "None found from public links.\n"
        )


    # Status summary

    f.write(
        "\nHTTP STATUS SUMMARY\n"
    )

    f.write(
        "-------------------\n"
    )

    for status, count in sorted(
        report[
            "status_summary"
        ].items()
    ):

        f.write(
            f"{status}: {count}\n"
        )


    # Errors

    f.write(
        "\nSCANNER ERRORS\n"
    )

    f.write(
        "--------------\n"
    )

    if report["errors"]:

        for error in report["errors"]:

            f.write(
                f"- {error['url']}: "
                f"{error['error']}\n"
            )

    else:

        f.write(
            "None\n"
        )


# ============================================================
# CONSOLE SUMMARY
# ============================================================

print()
print("=" * 60)
print("AUDIT COMPLETED")
print("=" * 60)

print(
    "Target:",
    TARGET
)

print(
    "Technologies:",
    ", ".join(
        report["technologies"]
    ) or "None"
)

print(
    "Discovered URLs:",
    len(discovered_urls)
)

print(
    "Checked endpoints:",
    len(
        report["endpoint_checks"]
    )
)

print(
    "Findings:",
    len(
        report["findings"]
    )
)

print()
print(
    "Reports:"
)

print(
    json_path
)

print(
    txt_path
)

print()
