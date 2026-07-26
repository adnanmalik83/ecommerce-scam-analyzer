import datetime
from urllib.parse import urlparse
import bs4
import requests
import whois


def calculate_scam_risk(url):
    """Analyzes a website and generates a mathematical scam risk score from 0-100."""
    print(f"\n[+] Running Risk Assessment Engine on: {url}")

    risk_score = 0
    breakdown = []
    metadata = {}

    # 1. Clean URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # 2. Check Connection Security (Weight: 15 points)
    if parsed_url.scheme != "https":
        risk_score += 15
        breakdown.append("❌ Insecure Connection (No HTTPS) [+15 Risk]")
    else:
        metadata["Security"] = "HTTPS Enabled"

    # 3. Check Domain Age via WHOIS (Weight: 45 points)
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.datetime.now() - creation_date).days
            metadata["Domain Age (Days)"] = age_days

            # Brand new domains are highly dangerous
            if age_days < 90:
                risk_score += 45
                breakdown.append(
                    f"❌ Freshly Registered Domain ({age_days} days old) [+45 Risk]"
                )
            elif age_days < 365:
                risk_score += 20
                breakdown.append(
                    f"⚠️ Relatively New Domain ({age_days} days old) [+20 Risk]"
                )
        else:
            risk_score += 30
            breakdown.append("⚠️ Domain Age hidden or unverified [+30 Risk]")
    except Exception:
        risk_score += 30
        breakdown.append("⚠️ WHOIS record lookup failed/hidden [+30 Risk]")

    # 4. Text & Content Analysis (Weight: 40 points)
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        soup = bs4.BeautifulSoup(response.text, "html.parser")

        # Extract meta title
        metadata["Page Title"] = (
            soup.title.string.strip() if soup.title else "No Title"
        )

        # Look for manipulative marketing phrases
        page_text = soup.get_text().lower()
        scam_phrases = [
            "90% off",
            "liquidation sale",
            "clearance blow-out",
            "free luxury",
        ]
        found_phrases = [p for p in scam_phrases if p in page_text]

        if found_phrases:
            risk_score += 20
            breakdown.append(
                f"❌ Found high-pressure phrases: {found_phrases} [+20 Risk]"
            )

        # Look for missing legal protections
        html_links = [a.get("href", "").lower() for a in soup.find_all("a")]
        has_privacy = any("privacy" in link for link in html_links)
        has_terms = any(
            "terms" in link or "condition" in link for link in html_links
        )

        if not has_privacy or not has_terms:
            risk_score += 20
            breakdown.append(
                "❌ Missing standard Privacy Policy or Terms links [+20 Risk]"
            )

    except Exception as e:
        print(f"[-] Web scraping error: {e}")

    # Ensure score caps safely at 100
    risk_score = min(risk_score, 100)

    # 5. Display the Visual Report Card
    print("\n--- ANALYZER DATA ---")
    for key, value in metadata.items():
        print(f" • {key}: {value}")

    print("\n--- RISK BREAKDOWN LOG ---")
    for item in breakdown:
        print(item)

    print("\n--- FINAL SECURITY VERDICT ---")
    if risk_score >= 60:
        print(f"🚨 HIGH SCAM RISK: {risk_score}/100")
    elif risk_score >= 30:
        print(f"⚠️ MODERATE RISK: {risk_score}/100")
    else:
        print(f"✅ SAFE / LOW RISK: {risk_score}/100")

    return risk_score


if __name__ == "__main__":
    # Test your updated intelligence engine
    calculate_scam_risk("stc.com.bh")
