from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env", override=True)


def parse_csv_list(value: str | None, default: list[str] | None = None) -> list[str]:
    """Parse a comma-separated env var into a trimmed list."""
    if not value:
        return default or []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_csv_set(value: str | None, default: set[str] | None = None) -> set[str]:
    """Parse a comma-separated env var into a trimmed set."""
    if not value:
        return default or set()
    return {item.strip() for item in value.split(",") if item.strip()}


def load_heuristics_lists(config: dict) -> None:
    """Inject parsed list env vars into a config dict so heuristics can consume them."""
    config["TOP_BRANDS"] = parse_csv_list(os.getenv("TOP_BRANDS"))
    config["SUSPICIOUS_KEYWORDS"] = parse_csv_set(os.getenv("SUSPICIOUS_KEYWORDS"))
    config["SHORTENERS"] = parse_csv_set(os.getenv("SHORTENERS"))
    config["PHISHING_TLDS"] = parse_csv_set(os.getenv("PHISHING_TLDS"))

    config["CONTENT_POLICY_KEYWORDS_GAMBLING"] = parse_csv_list(os.getenv("CONTENT_POLICY_KEYWORDS_GAMBLING"))
    config["CONTENT_POLICY_KEYWORDS_BETTING_INDIA"] = parse_csv_list(os.getenv("CONTENT_POLICY_KEYWORDS_BETTING_INDIA"))
    config["CONTENT_POLICY_KEYWORDS_ADULT"] = parse_csv_list(os.getenv("CONTENT_POLICY_KEYWORDS_ADULT"))
    config["CONTENT_POLICY_CATEGORIES_GAMBLING"] = parse_csv_list(os.getenv("CONTENT_POLICY_CATEGORIES_GAMBLING"))
    config["CONTENT_POLICY_CATEGORIES_ADULT"] = parse_csv_list(os.getenv("CONTENT_POLICY_CATEGORIES_ADULT"))
    config["GAMBLING_DENSITY_KEYWORDS"] = parse_csv_list(os.getenv("GAMBLING_DENSITY_KEYWORDS"))
    config["ADULT_DENSITY_KEYWORDS"] = parse_csv_list(os.getenv("ADULT_DENSITY_KEYWORDS"))

    config["SUSPICIOUS_PAGE_PHRASES"] = parse_csv_list(os.getenv("SUSPICIOUS_PAGE_PHRASES"))
    config["SUSPICIOUS_PAGE_WORDS"] = parse_csv_list(os.getenv("SUSPICIOUS_PAGE_WORDS"))
    config["SHARED_HOSTING_INDICATORS"] = parse_csv_list(os.getenv("SHARED_HOSTING_INDICATORS"))


def compute_label_from_score(score: int, config: dict | None = None) -> str:
    """Canonical score-to-label mapping. Every layer must use this."""
    cfg = config or {}
    phishing_threshold = int(cfg.get("PHISHING_THRESHOLD", 50))
    suspicious_threshold = int(cfg.get("SUSPICIOUS_THRESHOLD", 25))
    if score >= phishing_threshold:
        return "phishing"
    elif score >= suspicious_threshold:
        return "suspicious"
    else:
        return "safe"


class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/instance/detector.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    ANALYZE_RATE_LIMIT = os.getenv("ANALYZE_RATE_LIMIT", "30/hour")
    REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
    MAX_REDIRECT_DEPTH = int(os.getenv("MAX_REDIRECT_DEPTH", "5"))

    # Label thresholds: score < SUSPICIOUS_THRESHOLD = safe, >= SUSPICIOUS_THRESHOLD = suspicious, >= PHISHING_THRESHOLD = phishing
    SUSPICIOUS_THRESHOLD = int(os.getenv("SUSPICIOUS_THRESHOLD", "25"))
    PHISHING_THRESHOLD = int(os.getenv("PHISHING_THRESHOLD", "50"))

    # Domain age buckets
    DOMAIN_AGE_EXTREME_RISK_DAYS = int(os.getenv("DOMAIN_AGE_EXTREME_RISK_DAYS", "30"))
    DOMAIN_AGE_VERY_HIGH_RISK_DAYS = int(os.getenv("DOMAIN_AGE_VERY_HIGH_RISK_DAYS", "90"))
    DOMAIN_AGE_HIGH_RISK_DAYS = int(os.getenv("DOMAIN_AGE_HIGH_RISK_DAYS", "180"))
    DOMAIN_AGE_MODERATE_RISK_DAYS = int(os.getenv("DOMAIN_AGE_MODERATE_RISK_DAYS", "365"))

    NEW_DOMAIN_DAYS = int(os.getenv("NEW_DOMAIN_DAYS", "7"))
    YOUNG_DOMAIN_DAYS = int(os.getenv("YOUNG_DOMAIN_DAYS", "30"))
    NEW_DOMAIN_PENALTY = int(os.getenv("NEW_DOMAIN_PENALTY", "20"))
    YOUNG_DOMAIN_PENALTY = int(os.getenv("YOUNG_DOMAIN_PENALTY", "10"))

    # ── Scoring / Weightage Scheme ──────────────────────────────────────
    # URL-level weights
    TYPO_SQUATTING_PENALTY   = int(os.getenv("TYPO_SQUATTING_PENALTY", "30"))
    URL_LONG_PENALTY         = int(os.getenv("URL_LONG_PENALTY", "8"))
    URL_LONG_THRESHOLD       = int(os.getenv("URL_LONG_THRESHOLD", "75"))
    SUBDOMAIN_THRESHOLD      = int(os.getenv("SUBDOMAIN_THRESHOLD", "2"))
    SUBDOMAIN_PENALTY_UNIT   = int(os.getenv("SUBDOMAIN_PENALTY_UNIT", "6"))
    IP_ADDRESS_PENALTY       = int(os.getenv("IP_ADDRESS_PENALTY", "20"))
    CHAR_PENALTY_UNIT        = int(os.getenv("CHAR_PENALTY_UNIT", "2"))
    CHAR_MAX_PENALTY         = int(os.getenv("CHAR_MAX_PENALTY", "12"))
    KEYWORD_PENALTY_UNIT     = int(os.getenv("KEYWORD_PENALTY_UNIT", "6"))
    KEYWORD_MAX_PENALTY      = int(os.getenv("KEYWORD_MAX_PENALTY", "24"))
    SHORTENER_PENALTY        = int(os.getenv("SHORTENER_PENALTY", "15"))
    PHISHING_TLD_PENALTY     = int(os.getenv("PHISHING_TLD_PENALTY", "12"))
    NO_HTTPS_PENALTY         = int(os.getenv("NO_HTTPS_PENALTY", "10"))

    # Content-level weights
    HTTP_PASSWORD_PENALTY      = int(os.getenv("HTTP_PASSWORD_PENALTY", "15"))
    EXTERNAL_FORM_PENALTY      = int(os.getenv("EXTERNAL_FORM_PENALTY", "12"))
    IFRAME_PENALTY_UNIT        = int(os.getenv("IFRAME_PENALTY_UNIT", "5"))
    IFRAME_MAX_PENALTY         = int(os.getenv("IFRAME_MAX_PENALTY", "15"))
    EXTERNAL_SCRIPT_PENALTY_UNIT = int(os.getenv("EXTERNAL_SCRIPT_PENALTY_UNIT", "3"))
    EXTERNAL_SCRIPT_MAX_PENALTY  = int(os.getenv("EXTERNAL_SCRIPT_MAX_PENALTY", "9"))
    REDIRECT_PENALTY_UNIT       = int(os.getenv("REDIRECT_PENALTY_UNIT", "3"))
    REDIRECT_MAX_PENALTY        = int(os.getenv("REDIRECT_MAX_PENALTY", "12"))
    HTTP_ERROR_PENALTY          = int(os.getenv("HTTP_ERROR_PENALTY", "8"))
    FAVICON_PENALTY             = int(os.getenv("FAVICON_PENALTY", "4"))
    NO_CONTACT_PENALTY          = int(os.getenv("NO_CONTACT_PENALTY", "5"))
    NO_PRIVACY_POLICY_PENALTY   = int(os.getenv("NO_PRIVACY_POLICY_PENALTY", "4"))
    OUTDATED_COPYRIGHT_PENALTY  = int(os.getenv("OUTDATED_COPYRIGHT_PENALTY", "6"))
    EXCESSIVE_ADS_PENALTY       = int(os.getenv("EXCESSIVE_ADS_PENALTY", "8"))
    CONTENT_MISMATCH_PENALTY    = int(os.getenv("CONTENT_MISMATCH_PENALTY", "12"))
    BOT_BLOCKED_PENALTY         = int(os.getenv("BOT_BLOCKED_PENALTY", "5"))
    BINARY_RESPONSE_PENALTY     = int(os.getenv("BINARY_RESPONSE_PENALTY", "15"))
    UNREACHABLE_PENALTY         = int(os.getenv("UNREACHABLE_PENALTY", "10"))
    UNREACHABLE_YOUNG_PENALTY   = int(os.getenv("UNREACHABLE_YOUNG_PENALTY", "20"))

    # Domain-level weights
    DOMAIN_EXTREME_YOUNG_PENALTY   = int(os.getenv("DOMAIN_EXTREME_YOUNG_PENALTY", "35"))
    DOMAIN_VERY_YOUNG_PENALTY      = int(os.getenv("DOMAIN_VERY_YOUNG_PENALTY", "25"))
    DOMAIN_YOUNG_PENALTY           = int(os.getenv("DOMAIN_YOUNG_PENALTY", "15"))
    DOMAIN_MODERATE_YOUNG_PENALTY  = int(os.getenv("DOMAIN_MODERATE_YOUNG_PENALTY", "8"))
    WHOIS_UNAVAILABLE_PENALTY      = int(os.getenv("WHOIS_UNAVAILABLE_PENALTY", "5"))
    BRAND_IN_DOMAIN_PENALTY        = int(os.getenv("BRAND_IN_DOMAIN_PENALTY", "10"))
    BRAND_SUSPICIOUS_TLD_PENALTY   = int(os.getenv("BRAND_SUSPICIOUS_TLD_PENALTY", "10"))
    BRAND_DIGITS_PENALTY           = int(os.getenv("BRAND_DIGITS_PENALTY", "10"))
    BRAND_EXTRA_TEXT_PENALTY       = int(os.getenv("BRAND_EXTRA_TEXT_PENALTY", "8"))
    BRAND_NEW_DOMAIN_PENALTY       = int(os.getenv("BRAND_NEW_DOMAIN_PENALTY", "15"))
    SUSPICIOUS_TLD_NEW_PENALTY     = int(os.getenv("SUSPICIOUS_TLD_NEW_PENALTY", "10"))
    SSL_ISSUES_PENALTY             = int(os.getenv("SSL_ISSUES_PENALTY", "10"))
    FREE_SSL_ISSUER_PENALTY        = int(os.getenv("FREE_SSL_ISSUER_PENALTY", "5"))
    NO_MX_PENALTY                  = int(os.getenv("NO_MX_PENALTY", "10"))

    # External-threat weights
    SB_FLAGGED_PENALTY             = int(os.getenv("SB_FLAGGED_PENALTY", "20"))
    ABUSEIPDB_CONFIDENCE_DIVISOR   = int(os.getenv("ABUSEIPDB_CONFIDENCE_DIVISOR", "5"))
    ABUSEIPDB_MAX_PENALTY          = int(os.getenv("ABUSEIPDB_MAX_PENALTY", "15"))
    VT_DOMAIN_MALICIOUS_PENALTY    = int(os.getenv("VT_DOMAIN_MALICIOUS_PENALTY", "15"))
    VT_IP_MALICIOUS_PENALTY        = int(os.getenv("VT_IP_MALICIOUS_PENALTY", "15"))
    VT_TOTAL_CAP                   = int(os.getenv("VT_TOTAL_CAP", "40"))

    DOMAIN_VERY_OLD_TRUST          = int(os.getenv("DOMAIN_VERY_OLD_TRUST", "5"))
    DOMAIN_VERY_OLD_THRESHOLD      = int(os.getenv("DOMAIN_VERY_OLD_THRESHOLD", "730"))

    # VirusTotal Integration (optional enrichment, disabled by default)
    VT_ENABLED = os.getenv("VT_ENABLED", "false").lower() == "true"
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    VT_TIMEOUT = int(os.getenv("VT_TIMEOUT", "10"))
    VT_SCORE_BUMP_MALICIOUS = int(os.getenv("VT_SCORE_BUMP_MALICIOUS", "15"))
    VT_SCORE_BUMP_SUSPICIOUS = int(os.getenv("VT_SCORE_BUMP_SUSPICIOUS", "5"))
    VT_MAX_BUMP_MALICIOUS = int(os.getenv("VT_MAX_BUMP_MALICIOUS", "30"))
    VT_MAX_BUMP_SUSPICIOUS = int(os.getenv("VT_MAX_BUMP_SUSPICIOUS", "10"))

    VT_SCORE_BUMP_CATEGORY = int(os.getenv("VT_SCORE_BUMP_CATEGORY", "8"))
    VT_SCORE_BUMP_REPUTATION_NEGATIVE = int(os.getenv("VT_SCORE_BUMP_REPUTATION_NEGATIVE", "5"))
    VT_SCORE_REDUCTION_OLD_CLEAN = int(os.getenv("VT_SCORE_REDUCTION_OLD_CLEAN", "5"))
    VT_SCORE_REDUCTION_HARMLESS_VOTES = int(os.getenv("VT_SCORE_REDUCTION_HARMLESS_VOTES", "3"))
    VT_MAX_POSITIVE_REDUCTION = int(os.getenv("VT_MAX_POSITIVE_REDUCTION", "8"))
    VT_CACHE_HOURS = int(os.getenv("VT_CACHE_HOURS", "12"))

    # Optional Enrichment APIs
    SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY", "")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
    URLSCAN_SCORE_BUMP_MALICIOUS = int(os.getenv("URLSCAN_SCORE_BUMP_MALICIOUS", "15"))
    URLSCAN_SCORE_BUMP_SUSPICIOUS = int(os.getenv("URLSCAN_SCORE_BUMP_SUSPICIOUS", "5"))
    URLSCAN_MAX_BUMP = int(os.getenv("URLSCAN_MAX_BUMP", "20"))
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    # Content Policy (India regulatory compliance: gambling/adult flagged as suspicious)
    CONTENT_POLICY_ENABLED = os.getenv("CONTENT_POLICY_ENABLED", "true").lower() == "true"
    CONTENT_POLICY_SCORE_BUMP = int(os.getenv("CONTENT_POLICY_SCORE_BUMP", "25"))
    CONTENT_POLICY_FLOOR = int(os.getenv("CONTENT_POLICY_FLOOR", "25"))

    # Unknown Domain Suspicion (no brand + no external corroboration → suspicious baseline)
    UNKNOWN_DOMAIN_SUSPICIOUS_FLOOR = int(os.getenv("UNKNOWN_DOMAIN_SUSPICIOUS_FLOOR", "25"))
    UNKNOWN_DOMAIN_MIN_SOURCES = int(os.getenv("UNKNOWN_DOMAIN_MIN_SOURCES", "2"))

    WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")
    RESULTS_DIR = os.getenv("RESULTS_DIR", "results")
    CSP = {
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self'",
        "img-src": "'self' data:",
        "connect-src": "'self'",
        "object-src": "'none'",
        "frame-ancestors": "'none'",
    }
