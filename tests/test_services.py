from app.phishing.brand_impersonation import detect_brand_impersonation
from app.phishing.heuristics import extract_url_features
from app.phishing.phaas_signatures import detect_phaas_signatures


def test_ip_address_url():
    features, reasons = extract_url_features("http://192.168.1.1/login")
    assert features["has_ip"] == 1.0
    assert any("IP address" in r for r in reasons)

def test_shortener_url():
    features, reasons = extract_url_features("https://bit.ly/3xyz")
    assert features["is_shortener"] == 1.0
    assert any("URL shortener" in r for r in reasons)

def test_long_subdomain_chain():
    features, reasons = extract_url_features("https://a.b.c.d.e.example.com")
    assert features["subdomain_count"] == 5.0

def test_brand_impersonation():
    brand_reason = detect_brand_impersonation("https://googIe.com", "googIe.com")
    assert brand_reason is None
    brand_reason = detect_brand_impersonation("https://google-login-update.example.com", "example.com")
    assert brand_reason is not None
    assert "Brand impersonation" in brand_reason

def test_phaas_signatures():
    assert detect_phaas_signatures('<html><script src="phish.js"></script></html>')
    assert not detect_phaas_signatures('<html><body>Hello</body></html>')
