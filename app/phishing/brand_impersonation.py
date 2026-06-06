BRANDS = {
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com", "paypalobjects.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "netflix": ["netflix.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "linkedin": ["linkedin.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "whatsapp": ["whatsapp.com"]
}

def detect_brand_impersonation(url: str, domain: str) -> str | None:
    url_lower = url.lower()
    for brand, official_domains in BRANDS.items():
        if brand in url_lower:
            is_official = False
            for official_domain in official_domains:
                if domain == official_domain or domain.endswith("." + official_domain):
                    is_official = True
                    break
            if not is_official:
                return f"Brand impersonation: claims to be {brand} but domain is {domain}"
    return None
