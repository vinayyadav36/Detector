SIGNATURES = [
    "phish.js",
    "interceptor.js",
    "keylogger.js",
    "class=\"phish-form\"",
    "class=\"credential-harvest\"",
    "class='phish-form'",
    "class='credential-harvest'",
    "evilginx",
    "evilproxy"
]

def detect_phaas_signatures(html_text: str) -> bool:
    html_lower = html_text.lower()
    for sig in SIGNATURES:
        if sig in html_lower:
            return True
    return False
