"""
Test Lowe's public search WITHOUT login
Using regular Selenium with anti-detection measures

Usage:
    python test_lowes_public.py
"""
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

def test_lowes_public_search():
    print("Testing Lowe's PUBLIC search (no login)...")

    # Set up Chrome with anti-detection
    options = Options()
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_experimental_option('excludeSwitches', ['enable-automation'])
    options.add_experimental_option('useAutomationExtension', False)
    options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36')

    print("Initializing browser...")
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)

    # Mask webdriver detection
    driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
        'source': '''
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            window.chrome = { runtime: {} };
        '''
    })

    try:
        # Go directly to a search page
        search_term = "outdoor bleach"
        search_url = f"https://www.lowes.com/search?searchTerm={search_term.replace(' ', '+')}"

        print(f"Navigating to: {search_url}")
        driver.get(search_url)
        time.sleep(6)

        print(f"Page title: {driver.title}")
        print(f"Current URL: {driver.current_url}")

        # Check if we got blocked
        page_lower = driver.page_source.lower()
        title_lower = driver.title.lower()

        if "access denied" in title_lower or "something went wrong" in page_lower or "error" in title_lower:
            print("\n❌ GOT BLOCKED on public search too")
            driver.save_screenshot("lowes_public_blocked.png")
            print("Screenshot saved to lowes_public_blocked.png")
        else:
            print("\n✓ Page loaded!")

            # Try to find products
            wait = WebDriverWait(driver, 15)

            # Look for product cards
            product_selectors = [
                "div[data-selector='splp-prd-grid-tile']",
                "div.product-card",
                "[class*='ProductCard']",
                "[class*='product-card']",
                "div[data-itemid]",
            ]

            products_found = False
            for selector in product_selectors:
                try:
                    products = driver.find_elements(By.CSS_SELECTOR, selector)
                    if products:
                        print(f"✓ Found {len(products)} products using: {selector}")
                        products_found = True

                        # Try to extract info from first product
                        first = products[0]
                        print(f"\nFirst product HTML (snippet): {first.get_attribute('outerHTML')[:500]}...")

                        # Try to get price
                        try:
                            price_elem = first.find_element(By.CSS_SELECTOR, "[class*='price'], span.price, div.price")
                            print(f"Price element text: {price_elem.text}")
                        except:
                            print("Could not find price element")

                        # Try to get title
                        try:
                            title_elem = first.find_element(By.CSS_SELECTOR, "[class*='title'], h2, h3, a")
                            print(f"Title element text: {title_elem.text[:100] if title_elem.text else '(no text)'}")
                        except:
                            print("Could not find title element")

                        break
                except Exception as e:
                    continue

            if not products_found:
                print("\n❌ No products found with any selector")
                # Show page content
                body = driver.find_element(By.TAG_NAME, "body")
                print(f"\nPage body text (first 1000 chars):\n{body.text[:1000]}")
                driver.save_screenshot("lowes_public_no_products.png")
                print("\nScreenshot saved to lowes_public_no_products.png")

        input("\nPress Enter to close browser...")

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("lowes_public_error.png")
        input("\nPress Enter to close...")
    finally:
        driver.quit()

if __name__ == "__main__":
    test_lowes_public_search()
