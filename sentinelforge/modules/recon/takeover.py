from __future__ import annotations

_PATTERNS = {
    "amazonaws": ["s3.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com"],
    "azure": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
    "github-pages": ["github.io"],
    "heroku": ["herokuapp.com", "herokudns.com"],
    "netlify": ["netlify.app"],
    "vercel": ["vercel.app"],
    "shopify": ["myshopify.com"],
    "fastly": ["fastly.net"],
}


def takeover_hints(dns_data: dict, subdomains: list[str] | None = None) -> list[dict]:
    hints = []
    for cname in dns_data.get("CNAME", []) if isinstance(dns_data, dict) else []:
        hint = _hint_for(cname)
        if hint:
            hints.append({"name": "", "cname": cname, **hint})
    for name in subdomains or []:
        # Subdomain source data may not include CNAME targets yet. Keep a stable
        # shape for future per-subdomain DNS expansion.
        if name.endswith(".github.io"):
            hints.append({"name": name, "cname": name, "provider": "github-pages", "confidence": "low"})
    return hints


def _hint_for(value: str) -> dict:
    low = (value or "").lower().rstrip(".")
    for provider, suffixes in _PATTERNS.items():
        if any(low.endswith(suffix) for suffix in suffixes):
            return {
                "provider": provider,
                "confidence": "medium",
                "warning": "Potential dangling hosted-service CNAME; manually verify ownership and provider state.",
            }
    return {}
