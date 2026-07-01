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

        prompt = _build_prompt(url, page_content, features_summary)

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


def _build_prompt(url: str, page_content: str, features: dict[str, Any]) -> str:
    content_preview = (page_content or "")[:8000]
    features_json = json.dumps(features, indent=2)

    return f"""You are a cybersecurity analyst. Analyze the following website and determine if it is a phishing attempt.

URL: {url}

Heuristic analysis features:
{features_json}

Page content preview:
{content_preview}

Provide your analysis in this JSON format:
{{
  "summary": "Brief 1-2 sentence summary of the site's nature",
  "risk_level": "low|medium|high",
  "key_indicators": ["list specific suspicious or safe indicators"],
  "recommendations": ["actionable recommendations"],
  "detailed_assessment": "2-3 paragraph detailed analysis"
}}

Return ONLY valid JSON."""


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
        "risk_level": data.get("risk_level", "unknown"),
        "key_indicators": data.get("key_indicators", []),
        "recommendations": data.get("recommendations", []),
        "detailed_assessment": data.get("detailed_assessment", ""),
    }
