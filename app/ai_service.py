from __future__ import annotations

import json
import logging
from typing import Any

from flask import current_app

logger = logging.getLogger(__name__)


def analyze_with_ai(url: str, page_content: str, features_summary: dict[str, Any]) -> dict[str, Any]:
    api_key = current_app.config.get("GOOGLE_API_KEY", "")
    if not api_key:
        return {"available": False, "message": "AI analysis unavailable: no API key configured"}

    try:
        from google import genai

        client = genai.Client(api_key=api_key)

        prompt = _build_master_prompt(url, page_content, features_summary)

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )

        if not response.text:
            return {"available": True, "summary": "AI returned no analysis text."}

        return _parse_ai_response(response.text)

    except Exception as exc:
        logger.warning("AI analysis failed for %s: %s", url, exc)
        return {"available": False, "message": f"AI analysis error: {exc}"}


def _build_master_prompt(url: str, page_content: str, features: dict[str, Any]) -> str:
    content_preview = (page_content or "")[:12000]
    features_json = json.dumps(features, indent=2)

    return f"""You are a senior cybersecurity analyst performing a comprehensive phishing and threat assessment. Analyze the target website thoroughly and provide a detailed forensic report.

TARGET URL: {url}

HEURISTIC ANALYSIS FEATURES:
{features_json}

PAGE CONTENT PREVIEW (first 12000 chars):
{content_preview}

Perform a MASTER ANALYSIS covering:

1. THREAT CLASSIFICATION: Is this phishing, malware distribution, scam, legitimate, or suspicious?
2. ATTACK VECTOR ANALYSIS: Identify specific techniques (credential harvesting, drive-by download, social engineering, brand impersonation, etc.)
3. INFRASTRUCTURE ANALYSIS: Domain age, hosting, SSL/TLS, DNS records, redirect chains, subdomain abuse
4. CONTENT ANALYSIS: Forms, scripts, iframes, external resources, obfuscation, brand imitation indicators
5. BEHAVIORAL INDICATORS: Urgency tactics, trust signals abuse, data exfiltration patterns
6. RISK SCORING: Provide a calibrated risk score 0-100 with justification
7. ACTIONABLE RECOMMENDATIONS: Specific steps for users and security teams

Return ONLY valid JSON in this exact format:
{{
  "summary": "Concise 2-3 sentence executive summary of the threat assessment",
  "threat_classification": "phishing|malware|scam|legitimate|suspicious|unknown",
  "risk_score": 0-100,
  "risk_level": "critical|high|medium|low|minimal",
  "confidence": 0.0-1.0,
  "attack_vectors": ["specific techniques identified"],
  "infrastructure_analysis": {{
    "domain_age_risk": "new|recent|established|unknown",
    "ssl_tls_status": "valid|invalid|self-signed|missing|unknown",
    "hosting_reputation": "clean|suspicious|malicious|unknown",
    "redirect_chain_risk": "none|low|medium|high|critical",
    "subdomain_abuse": true|false
  }},
  "content_analysis": {{
    "credential_harvesting": true|false,
    "brand_impersonation": "none|suspected|confirmed",
    "targeted_brand": "brand name or none",
    "obfuscation_detected": true|false,
    "external_forms": true|false,
    "suspicious_scripts": true|false,
    "drive_by_download_risk": "none|low|medium|high"
  }},
  "behavioral_indicators": ["list of psychological/social engineering tactics"],
  "key_indicators": ["specific technical indicators supporting the classification"],
  "recommendations": ["immediate actions for users", "security team actions", "monitoring suggestions"],
  "detailed_assessment": "3-4 paragraph comprehensive analysis explaining the reasoning, evidence, and context"
}}"""


def _parse_ai_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        text = text.rsplit("```", 1)[0]
    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"available": True, "summary": text[:500]}

    return {
        "available": True,
        "summary": data.get("summary", "No summary provided."),
        "threat_classification": data.get("threat_classification", "unknown"),
        "risk_score": data.get("risk_score", 0),
        "risk_level": data.get("risk_level", "unknown"),
        "confidence": data.get("confidence", 0.0),
        "attack_vectors": data.get("attack_vectors", []),
        "infrastructure_analysis": data.get("infrastructure_analysis", {}),
        "content_analysis": data.get("content_analysis", {}),
        "behavioral_indicators": data.get("behavioral_indicators", []),
        "key_indicators": data.get("key_indicators", []),
        "recommendations": data.get("recommendations", []),
        "detailed_assessment": data.get("detailed_assessment", ""),
    }