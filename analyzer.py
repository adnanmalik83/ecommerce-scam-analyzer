import argparse

import requests
from bs4 import BeautifulSoup
import tldextract
import whois


def fetch_html(url, timeout=10):
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.text


def parse_html(html):
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    desc_tag = soup.find("meta", attrs={"name": "description"})
    description = desc_tag.get("content", "").strip() if desc_tag else ""
    links = [a.get("href").strip() for a in soup.find_all("a", href=True)]
    return {
        "title": title,
        "description": description,
        "links": links,
    }


def extract_domain_info(url):
    extracted = tldextract.extract(url)
    return {
        "subdomain": extracted.subdomain,
        "domain": extracted.domain,
        "suffix": extracted.suffix,
        "registered_domain": extracted.registered_domain,
    }


def query_whois(domain):
    try:
        data = whois.whois(domain)
    except Exception as exc:
        return {"error": str(exc)}

    if isinstance(data, dict):
        return data

    keys = [
        "domain_name",
        "registrar",
        "whois_server",
        "creation_date",
        "expiration_date",
        "updated_date",
        "emails",
        "name",
        "org",
        "address",
        "city",
        "state",
        "country",
        "zipcode",
    ]
    return {key: getattr(data, key, None) for key in keys}


def analyze_url(url):
    html = fetch_html(url)
    parsed = parse_html(html)
    domain_info = extract_domain_info(url)
    whois_data = query_whois(domain_info["registered_domain"] or url)
    return {
        "url": url,
        "domain_info": domain_info,
        "page": parsed,
        "whois": whois_data,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a URL using requests, BeautifulSoup, tldextract, and python-whois."
    )
    parser.add_argument("url", help="URL to analyze")
    args = parser.parse_args()
    result = analyze_url(args.url)

    print("URL:", result["url"])
    print("Title:", result["page"]["title"])
    print("Description:", result["page"]["description"])
    print("Domain:", result["domain_info"]["registered_domain"])
    print("WHOIS registrar:", result["whois"].get("registrar"))
    print("Creation date:", result["whois"].get("creation_date"))
    print("Expiration date:", result["whois"].get("expiration_date"))
    print("Emails:", result["whois"].get("emails"))
    print("Found links:", len(result["page"]["links"]))


if __name__ == "__main__":
    main()

