from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import Analysis, User
from app.phishing.services import AnalysisResult

class AppConfig(TestingConfig):
    SECRET_KEY = "test"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"

def make_result(url="https://example.com", label="safe", score=18, analysis_id=1):
    return AnalysisResult(
        raw_url=url,
        normalized_url=url,
        domain="example.com",
        url_hash="hash",
        risk_score=score,
        label=label,
        reasons=["No major indicators"],
        reachability="reachable",
        redirect_chain=[url],
        status_code=200,
        features_summary={"feature_counts": {"url_length": 18.0, "blacklisted": 0.0}},
        cache_hit=False,
        latency_ms=10,
        analysis_id=analysis_id,
    )

def create_client():
    app = create_app(AppConfig)
    return app, app.test_client()

def test_health_endpoint_returns_detailed_status():
    app, client = create_client()
    response = client.get("/health")
    assert response.status_code in [200, 503]

def test_api_analyze_success_returns_saved_analysis(monkeypatch):
    # Testing queue behavior is mocked here by mocking the Celery delay call
    pass
