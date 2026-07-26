import datetime
from urllib.parse import urlparse
import bs4
import requests
import streamlit as st
import whois

# Set up clean web browser tab styling
st.set_page_config(
    page_title="E-Commerce Scam Site Analyzer",
    page_icon="🛡️",
    layout="centered",
)

# App Title Header
st.title("🛡️ E-Commerce Scam Analyzer")
st.markdown(
    "Paste a website link below to instantly scan its domain age, security encryption, and scam risk score metrics."
)


# Core Logic Function (Optimized for Web Display)
def run_web_assessment(url):
    risk_score = 0
    breakdown = []
    metadata = {}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # 1. Connection Encryption Status
    if parsed_url.scheme != "https":
        risk_score += 15
        breakdown.append("Insecure Connection (Missing HTTPS) [+15]")
    else:
        metadata["Security Protocol"] = "HTTPS (Secure/Encrypted)"

    # 2. Registry Registration Age Analysis
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.datetime.now() - creation_date).days
            metadata["Domain Age"] = f"{age_days} days old"
            if age_days < 90:
                risk_score += 45
                breakdown.append(
                    f"Dangerously Fresh Registration ({age_days} days old) [+45]"
                )
            elif age_days < 365:
                risk_score += 20
                breakdown.append(f"Relatively New Domain ({age_days} days old) [+20]")
        else:
            risk_score += 30
            breakdown.append("Domain history records hidden/masked [+30]")
    except Exception:
        risk_score += 30
        breakdown.append("Registry data lookup blocked/hidden [+30]")

    # 3. Content Analysis
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=5)
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        metadata["Page Title"] = (
            soup.title.string.strip() if soup.title else "No Metadata Title"
        )

        page_text = soup.get_text().lower()
        scam_phrases = [
            "90% off",
            "liquidation sale",
            "clearance blow-out",
            "free luxury",
        ]
        found = [p for p in scam_phrases if p in page_text]
        if found:
            risk_score += 20
            breakdown.append(f"Manipulative marketing terms detected: {found} [+20]")

        html_links = [a.get("href", "").lower() for a in soup.find_all("a")]
        has_privacy = any("privacy" in link for link in html_links)
        has_terms = any(
            "terms" in link or "condition" in link for link in html_links
        )
        if not has_privacy or not has_terms:
            risk_score += 20
            breakdown.append(
                "Missing verified legal context or Privacy policy pages [+20]"
            )
    except Exception:
        pass

    risk_score = min(risk_score, 100)
    return risk_score, breakdown, metadata


# --- Visual Frontend Layout ---
target_url = st.text_input("Enter E-Commerce URL to Inspect:", "example.com")

if st.button("Run Security Scan"):
    with st.spinner("Analyzing site architecture..."):
        score, logs, meta = run_web_assessment(target_url)

        st.subheader("📊 Visual Risk Assessment")

        # Dynamic Color Banner Based on Score
        if score >= 60:
            st.error(f"🚨 HIGH SCAM RISK VALUE: {score}/100")
        elif score >= 30:
            st.warning(f"⚠️ MODERATE SAFETY RISK: {score}/100")
        else:
            st.success(f"✅ SECURE / LOW RISK SITE: {score}/100")

        # Metadata Layout Columns
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**🌐 Extracted Metadata**")
            for k, v in meta.items():
                st.write(f"• **{k}:** {v}")
        with col2:
            st.markdown("**🔍 Risk Factor Explanations**")
            if not logs:
                st.write("• No automated risk triggers tripped.")
            for log in logs:
                st.write(f"• {log}")
