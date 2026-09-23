import os
import re
import json
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

TARGET = os.environ.get(
    "TARGET_URL",
    "https://www.mirpurcollege.edu.bd/"
).rstrip("/")

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

session = requests.Session()
session.headers.update({
    "User-Agent": "Authorized-Security-Audit/1.0"
})

report = {
    "target": TARGET,
    "findings": [],
    "links": [],
    "forms": [],
    "technologies": [],
    "checks": {}
}


def finding(severity, title, detail):
    report["findings"].append({
        "severity": severity,
        "title": title,
        "detail": detail
    })


def get(path):
    url = urljoin(TARGET + "/", path.lstrip("/"))
    try:
        r = session.get(url, timeout=15, allow_redirects=True)
        return r
    except Exception as e:
        return None


# --------------------------------------------------
# Main page
# --------------------------------------------------

try:
    response = session.get(TARGET, timeout=20, allow_redirects=True)

    report["checks"]["status_code"] = response.status_code
    report["checks"]["final_url"] = response.url
    report["checks"]["server"] = response.headers.get("Server")
    report["checks"]["content_type"] = response.headers.get("Content-Type")

except Exception as e:
    finding("ERROR", "Website unreachable", str(e))
    response = None


if response:

    # --------------------------------------------------
    # Security headers
    # --------------------------------------------------

    security_headers = {
        "Content-Security-Policy":
            "Helps reduce XSS and content injection risk",

        "X-Frame-Options":
            "Helps prevent clickjacking",

        "X-Content-Type-Options":
            "Prevents MIME sniffing",

        "Referrer-Policy":
            "Controls referrer information",

        "Permissions-Policy":
            "Restricts browser capabilities",

        "Strict-Transport-Security":
            "Enforces HTTPS"
    }

    for header, explanation in security_headers.items():

        value = response.headers.get(header)

        if value:
            report["checks"][header] = value
        else:
            finding(
                "LOW",
                f"Missing security header: {header}",
                explanation
            )


    # --------------------------------------------------
    # Cookies
    # --------------------------------------------------

    cookies = response.headers.get("Set-Cookie", "")

    if cookies:

        report["checks"]["set_cookie"] = cookies

        cookie_lower = cookies.lower()

        if "secure" not in cookie_lower:
            finding(
                "MEDIUM",
                "Cookie may lack Secure flag",
                "Review whether authentication/session cookies are sent only over HTTPS."
            )

        if "httponly" not in cookie_lower:
            finding(
                "MEDIUM",
                "Cookie may lack HttpOnly flag",
                "Review whether sensitive cookies should be inaccessible to JavaScript."
            )

        if "samesite" not in cookie_lower:
            finding(
                "LOW",
                "Cookie may lack SameSite attribute",
                "Review CSRF protection and cookie policy."
            )


    # --------------------------------------------------
    # Technology detection
    # --------------------------------------------------

    headers_text = str(response.headers).lower()
    html = response.text

    technologies = set()

    if "laravel" in html.lower() or "laravel_session" in headers_text:
        technologies.add("Laravel")

    if "wordpress" in html.lower() or "wp-content" in html.lower():
        technologies.add("WordPress")

    if "bootstrap" in html.lower():
        technologies.add("Bootstrap")

    if "jquery" in html.lower():
        technologies.add("jQuery")

    if "react" in html.lower():
        technologies.add("React")

    if "vue" in html.lower():
        technologies.add("Vue.js")

    if response.headers.get("X-Powered-By"):
        technologies.add(
            "X-Powered-By: " +
            response.headers.get("X-Powered-By")
        )

    report["technologies"] = sorted(technologies)


    # --------------------------------------------------
    # HTML parsing
    # --------------------------------------------------

    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a", href=True):

        href = urljoin(response.url, a["href"])

        if urlparse(href).netloc == urlparse(TARGET).netloc:

            report["links"].append(href)

    report["links"] = sorted(set(report["links"]))


    # Forms

    for form in soup.find_all("form"):

        report["forms"].append({
            "action": urljoin(
                response.url,
                form.get("action", "")
            ),
            "method": form.get(
                "method",
                "GET"
            ).upper()
        })


    # --------------------------------------------------
    # Publicly linked admin/login pages
    # --------------------------------------------------

    interesting = []

    for link in report["links"]:

        path = urlparse(link).path.lower()

        keywords = [
            "admin",
            "administrator",
            "login",
            "signin",
            "dashboard",
            "backend",
            "manage"
        ]

        if any(x in path for x in keywords):
            interesting.append(link)

    report["checks"]["interesting_public_links"] = sorted(
        set(interesting)
    )


# --------------------------------------------------
# robots.txt / sitemap.xml
# --------------------------------------------------

for path in [
    "robots.txt",
    "sitemap.xml"
]:

    r = get(path)

    if r and r.status_code == 200:

        report["checks"][path] = {
            "status": r.status_code,
            "size": len(r.content)
        }


# --------------------------------------------------
# Safe public-file checks
# Only GET; no authentication bypass/exploitation.
# --------------------------------------------------

public_paths = [
    ".env",
    ".git/HEAD",
    "composer.json",
    "package.json",
    "phpinfo.php",
    "server-status"
]

for path in public_paths:

    r = get(path)

    if not r:
        continue

    if r.status_code == 200:

        finding(
            "HIGH",
            f"Potentially exposed file: /{path}",
            f"The resource returned HTTP 200. Verify whether this resource is intentionally public."
        )

    elif r.status_code not in [403, 404]:
        report["checks"][f"/{path}"] = r.status_code


# --------------------------------------------------
# Common error exposure check
# --------------------------------------------------

for path in [
    "?test_invalid_parameter=1"
]:

    r = get(path)

    if not r:
        continue

    text = r.text.lower()

    error_words = [
        "stack trace",
        "exception",
        "traceback",
        "sqlstate",
        "syntax error",
        "debug mode"
    ]

    matches = [
        x for x in error_words
        if x in text
    ]

    if matches:

        finding(
            "MEDIUM",
            "Possible error/debug information exposure",
            "Response contains: " + ", ".join(matches)
        )


# --------------------------------------------------
# Deduplicate
# --------------------------------------------------

report["links"] = sorted(set(report["links"]))


# --------------------------------------------------
# Save JSON
# --------------------------------------------------

with open(
    f"{REPORT_DIR}/security-report.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        report,
        f,
        indent=2,
        ensure_ascii=False
    )


# --------------------------------------------------
# Human-readable report
# --------------------------------------------------

with open(
    f"{REPORT_DIR}/security-report.txt",
    "w",
    encoding="utf-8"
) as f:

    f.write("WEBSITE SECURITY AUDIT\n")
    f.write("======================\n\n")

    f.write(f"Target: {TARGET}\n\n")

    f.write("TECHNOLOGIES\n")
    f.write("------------\n")

    for tech in report["technologies"]:
        f.write(f"- {tech}\n")

    f.write("\nFINDINGS\n")
    f.write("--------\n")

    if not report["findings"]:
        f.write("No obvious passive findings detected.\n")

    for item in report["findings"]:

        f.write(
            f"[{item['severity']}] "
            f"{item['title']}\n"
        )

        f.write(
            f"  {item['detail']}\n\n"
        )

    f.write("\nPUBLICLY DISCOVERED INTERESTING LINKS\n")
    f.write("--------------------------------------\n")

    for link in report["checks"].get(
        "interesting_public_links",
        []
    ):
        f.write(f"- {link}\n")

print("Audit completed.")
print(f"Findings: {len(report['findings'])}")
