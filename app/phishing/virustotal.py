from __future__ import annotations

import base64
import logging
import time
from typing import Any

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

_last_vt_call_time: float = 0.0
_VT_MIN_INTERVAL = 15.0


def _vt_request(method: str, url: str, headers: dict, data: dict | None, timeout: int):
    if method == "POST":
        return requests.post(url, headers=headers, data=data, timeout=timeout)
    return requests.get(url, headers=headers, timeout=timeout)


def get_virustotal_report(url: str, config: dict[str, Any]) -> dict[str, Any] | None:
    """
    Full VT enrichment: POST to scan URL, then poll GET for report.
    Public API: 4 requests/minute. We enforce a local 15s minimum interval.
    """
    global _last_vt_call_time

    if not config.get("VT_ENABLED", False):
        return None

    api_key = config.get("VT_API_KEY")
    if not api_key:
        logger.warning("[VT] VT_ENABLED=true but VT_API_KEY not set. Skipping lookup.")
        return None

    timeout = config.get("VT_TIMEOUT", 10)

    elapsed = time.monotonic() - _last_vt_call_time
    if elapsed < _VT_MIN_INTERVAL:
        wait = _VT_MIN_INTERVAL - elapsed
        logger.info(f"[VT] Rate-limit guard: waiting {wait:.1f}s since last VT call.")
        time.sleep(wait)

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers_json = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded",
    }

    headers_get = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        logger.info(f"[VT] Submitting URL for scan: {url}")
        _last_vt_call_time = time.monotonic()
        scan_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers_json,
            data={"url": url},
            timeout=timeout,
        )

        if scan_resp.status_code == 429:
            logger.warning("[VT] Rate limit exceeded on scan (429).")
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded during scan submission"}

        if scan_resp.status_code == 401:
            logger.warning("[VT] Invalid API key (401). Check VT_API_KEY.")
            return {"status": "error", "message": "VirusTotal authentication failed (invalid API key)"}

        if scan_resp.status_code == 400:
            logger.warning("[VT] Bad request (400). URL may be malformed.")
            return {"status": "error", "message": "VirusTotal rejected the URL (bad request)"}

        scan_resp.raise_for_status()
        logger.info("[VT] Scan submitted. Polling for report...")

        time.sleep(3)

        _last_vt_call_time = time.monotonic()
        report_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers_get,
            timeout=timeout,
        )

        if report_resp.status_code == 429:
            logger.warning("[VT] Rate limit exceeded on report retrieval (429).")
            return {"status": "rate_limited", "message": "VirusTotal rate limit exceeded during report retrieval"}

        if report_resp.status_code == 404:
            logger.info("[VT] URL not found in VT database after scan (404).")
            return {"status": "not_found", "message": "URL not found in VirusTotal database"}

        report_resp.raise_for_status()
        data = report_resp.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless + undetected

        summary = {
            "status": "success",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_engines": total,
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation", 0),
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
        }

        logger.info(
            f"[VT] Report retrieved: {malicious} malicious, {suspicious} suspicious, "
            f"{harmless} harmless, {undetected} undetected (out of {total} engines)"
        )
        return summary

    except RequestException as e:
        logger.warning(f"[VT] Network/API error: {e}")
        return {"status": "error", "message": f"Network error: {e}"}
    except Exception as e:
        logger.warning(f"[VT] Unexpected error: {e}")
        return {"status": "error", "message": "Internal error during VT lookup"}
