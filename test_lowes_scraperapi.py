"""
Test Lowe's scraping using ScraperAPI
ScraperAPI handles anti-bot protection, proxies, and CAPTCHA solving

Free tier: 5,000 requests/month
Sign up at: https://www.scraperapi.com/

Usage:
    1. Sign up for free at https://www.scraperapi.com/
    2. Get your API key from the dashboard
    3. Run: python test_lowes_scraperapi.py
"""
import requests
from bs4 import BeautifulSoup
import re

# Get your free API key from https://www.scraperapi.com/
API_KEY = input("Enter your ScraperAPI key (get free at scraperapi.com): ").strip()

def test_lowes_search():
    """Test scraping Lowe's product search using ScraperAPI"""

    search_term = "outdoor bleach"
    lowes_url = f"https://www.lowes.com/search?searchTerm={search_term.replace(' ', '+')}"

    print(f"\nTesting Lowe's search for: {search_term}")
    print(f"Target URL: {lowes_url}")

    # ScraperAPI endpoint - handles all the anti-bot stuff
    scraperapi_url = "http://api.scraperapi.com"

    params = {
        'api_key': API_KEY,
        'url': lowes_url,
        'render': 'true',  # Enable JavaScript rendering (important for React sites)
        'country_code': 'us',
    }

    print("\nSending request via ScraperAPI (this may take 10-30 seconds)...")

    try:
        response = requests.get(scraperapi_url, params=params, timeout=60)

        print(f"Response status: {response.status_code}")

        if response.status_code == 200:
            html = response.text

            # Check if we got blocked anyway
            if "access denied" in html.lower() or "something went wrong" in html.lower():
                print("\n❌ Still got blocked even with ScraperAPI")
                print("You may need to enable 'premium' proxies in ScraperAPI settings")

                # Save HTML for debugging
                with open("lowes_scraperapi_blocked.html", "w", encoding="utf-8") as f:
                    f.write(html)
                print("HTML saved to lowes_scraperapi_blocked.html for debugging")
                return

            print("\n✓ Page loaded successfully!")

            # Parse with BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')

            # Save HTML for analysis
            with open("lowes_scraperapi_success.html", "w", encoding="utf-8") as f:
                f.write(html)
            print("Full HTML saved to lowes_scraperapi_success.html")

            # Try to find products
            print("\nSearching for product elements...")

            # Try various product selectors
            product_selectors = [
                'div[data-selector="splp-prd-grid-tile"]',
                'div.product-card',
                '[class*="ProductCard"]',
                '[class*="product-card"]',
                'div[data-itemid]',
                'article',
            ]

            products = []
            for selector in product_selectors:
                found = soup.select(selector)
                if found:
                    print(f"✓ Found {len(found)} elements with: {selector}")
                    products = found
                    break

            if products:
                print(f"\n✓ SUCCESS! Found {len(products)} products")

                # Try to extract first product info
                first = products[0]

                # Get product name
                name_elem = first.select_one('[class*="title"], h2, h3, a[href*="/pd/"]')
                if name_elem:
                    print(f"Product name: {name_elem.get_text(strip=True)[:80]}")

                # Get price
                price_elem = first.select_one('[class*="price"]')
                if price_elem:
                    price_text = price_elem.get_text(strip=True)
                    price_match = re.search(r'\$?([\d,]+\.?\d*)', price_text)
                    if price_match:
                        print(f"Price: ${price_match.group(1)}")

                # Get product link
                link_elem = first.select_one('a[href*="/pd/"]')
                if link_elem:
                    href = link_elem.get('href', '')
                    if href.startswith('/'):
                        href = 'https://www.lowes.com' + href
                    print(f"Product URL: {href[:80]}...")

                print("\n" + "="*50)
                print("✓ SCRAPERAPI WORKS FOR LOWE'S!")
                print("="*50)
                print("\nNext steps:")
                print("1. Sign up for a paid plan if you need more than 5K requests/mo")
                print("2. I'll update the backend to use ScraperAPI")

            else:
                print("\n⚠ Page loaded but no products found")
                print("The HTML structure may have changed")

                # Show what we got
                body_text = soup.get_text()[:500]
                print(f"\nPage text preview:\n{body_text}")

        elif response.status_code == 403:
            print("\n❌ ScraperAPI returned 403 - may need premium proxies")

        elif response.status_code == 401:
            print("\n❌ Invalid API key - check your ScraperAPI dashboard")

        else:
            print(f"\n❌ Unexpected status code: {response.status_code}")
            print(f"Response: {response.text[:500]}")

    except requests.Timeout:
        print("\n❌ Request timed out - try again")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    print("="*60)
    print("LOWE'S SCRAPERAPI TEST")
    print("="*60)
    print("\nScraperAPI handles anti-bot protection automatically.")
    print("Free tier: 5,000 requests/month")
    print("Sign up: https://www.scraperapi.com/")
    print()

    if not API_KEY:
        print("No API key provided. Please sign up at scraperapi.com first.")
    else:
        test_lowes_search()
