"""
Vendor quote pulling service
Handles automated login and price fetching from vendor websites using Selenium
Uses ScraperAPI for sites with strong anti-bot protection (like Lowe's)
"""
import os
import json
import asyncio
import time
import re
import requests
from typing import List, Dict, Optional
from datetime import datetime
from urllib.parse import quote_plus
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.service import Service as EdgeService
import logging

logger = logging.getLogger(__name__)

# Preferred browser order (will try each in sequence until one works)
BROWSER_PREFERENCE = os.getenv('PREFERRED_BROWSER', 'chrome,firefox,edge').lower().split(',')

# Force demo mode (skip browser automation entirely)
# Set to 'true' to always use demo data, 'false' to attempt real scraping
FORCE_DEMO_MODE = os.getenv('FORCE_DEMO_MODE', 'false').lower() == 'true'

# Disable demo mode fallback in production
# Set to 'true' to fail loudly when real scraping fails (no fallback to demo data)
# This ensures only real pricing data is used for actual purchases
PRODUCTION_MODE = os.getenv('PRODUCTION_MODE', 'false').lower() == 'true'

# ScraperAPI key for sites with strong anti-bot protection (like Lowe's)
# Get your API key at https://www.scraperapi.com/
SCRAPERAPI_KEY = os.getenv('SCRAPERAPI_KEY', '')

# Encryption key for storing passwords securely
# In production, store this in environment variables
ENCRYPTION_KEY = os.getenv('VENDOR_ENCRYPTION_KEY', Fernet.generate_key())
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_password(password: str) -> str:
    """Encrypt a password for secure storage"""
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a stored password"""
    return cipher.decrypt(encrypted_password.encode()).decode()

class VendorQuoteFetcher:
    """Base class for vendor-specific quote fetchers"""

    def __init__(self, username: str, encrypted_password: str, allow_demo_fallback: bool = True):
        self.username = username
        # Try to decrypt, but if it fails (demo mode), just use the encrypted value as-is
        try:
            self.password = decrypt_password(encrypted_password)
        except Exception:
            # In demo mode, password doesn't matter
            self.password = encrypted_password
        self.driver = None
        self.is_logged_in = False
        self.allow_demo_fallback = allow_demo_fallback  # Can this fetcher fall back to demo mode?

    def init_driver(self):
        """Initialize Selenium WebDriver with automatic browser detection and fallback"""
        if self.driver is None:
            # Use a recent, realistic user agent
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'

            # Try each browser in preference order
            for browser in BROWSER_PREFERENCE:
                browser = browser.strip()
                try:
                    if browser == 'chrome':
                        logger.info("Attempting to initialize Chrome browser...")
                        chrome_options = ChromeOptions()

                        # Use new headless mode (less detectable than old --headless)
                        chrome_options.add_argument('--headless=new')
                        chrome_options.add_argument('--no-sandbox')
                        chrome_options.add_argument('--disable-dev-shm-usage')
                        chrome_options.add_argument('--disable-gpu')
                        chrome_options.add_argument('--window-size=1920,1080')
                        chrome_options.add_argument(f'--user-agent={user_agent}')

                        # Anti-detection measures
                        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
                        chrome_options.add_argument('--disable-infobars')
                        chrome_options.add_argument('--disable-extensions')
                        chrome_options.add_argument('--disable-popup-blocking')
                        chrome_options.add_argument('--start-maximized')
                        chrome_options.add_argument('--ignore-certificate-errors')
                        chrome_options.add_argument('--allow-running-insecure-content')

                        # Additional anti-detection
                        chrome_options.add_experimental_option('excludeSwitches', ['enable-automation', 'enable-logging'])
                        chrome_options.add_experimental_option('useAutomationExtension', False)

                        # Get the driver path and fix the webdriver-manager bug
                        driver_path = ChromeDriverManager().install()
                        logger.info(f"ChromeDriverManager returned path: {driver_path}")

                        # If the path points to THIRD_PARTY_NOTICES, find the actual chromedriver
                        if 'THIRD_PARTY_NOTICES' in driver_path or not driver_path.endswith('chromedriver'):
                            import os
                            import glob
                            driver_dir = os.path.dirname(driver_path)
                            logger.info(f"Looking for chromedriver in: {driver_dir}")

                            # Try different possible chromedriver names
                            possible_names = ['chromedriver', 'chromedriver.exe', 'chromedriver-linux64', 'chromedriver-mac-x64']
                            for name in possible_names:
                                actual_driver = os.path.join(driver_dir, name)
                                if os.path.exists(actual_driver) and os.path.isfile(actual_driver):
                                    driver_path = actual_driver
                                    logger.info(f"Found chromedriver at: {driver_path}")
                                    break
                            else:
                                # List all files in directory for debugging
                                try:
                                    files = os.listdir(driver_dir)
                                    logger.info(f"Files in {driver_dir}: {files}")
                                    # Look for any file containing 'chromedriver' that's not THIRD_PARTY
                                    for f in files:
                                        if 'chromedriver' in f.lower() and 'third_party' not in f.lower() and 'notices' not in f.lower():
                                            candidate = os.path.join(driver_dir, f)
                                            if os.path.isfile(candidate):
                                                driver_path = candidate
                                                logger.info(f"Found chromedriver candidate: {driver_path}")
                                                break
                                except Exception as e:
                                    logger.error(f"Could not list driver directory: {e}")

                        # Ensure chromedriver has execute permissions
                        import stat
                        if os.path.exists(driver_path):
                            os.chmod(driver_path, os.stat(driver_path).st_mode | stat.S_IEXEC)
                            logger.info(f"Set execute permissions on: {driver_path}")

                        service = ChromeService(driver_path)
                        self.driver = webdriver.Chrome(service=service, options=chrome_options)

                        # Execute JavaScript to mask webdriver detection
                        self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                            'source': '''
                                Object.defineProperty(navigator, 'webdriver', {
                                    get: () => undefined
                                });
                                Object.defineProperty(navigator, 'plugins', {
                                    get: () => [1, 2, 3, 4, 5]
                                });
                                Object.defineProperty(navigator, 'languages', {
                                    get: () => ['en-US', 'en']
                                });
                                window.chrome = {
                                    runtime: {}
                                };
                            '''
                        })

                        logger.info("Successfully initialized Chrome browser with anti-detection")
                        break

                    elif browser == 'firefox':
                        logger.info("Attempting to initialize Firefox browser...")
                        firefox_options = FirefoxOptions()
                        firefox_options.add_argument('--headless')
                        firefox_options.set_preference('general.useragent.override', user_agent)

                        service = FirefoxService(GeckoDriverManager().install())
                        self.driver = webdriver.Firefox(service=service, options=firefox_options)
                        logger.info("Successfully initialized Firefox browser")
                        break

                    elif browser == 'edge':
                        logger.info("Attempting to initialize Edge browser...")
                        edge_options = EdgeOptions()
                        edge_options.add_argument('--headless')
                        edge_options.add_argument('--no-sandbox')
                        edge_options.add_argument('--disable-dev-shm-usage')
                        edge_options.add_argument('--disable-gpu')
                        edge_options.add_argument('--window-size=1920,1080')
                        edge_options.add_argument(f'--user-agent={user_agent}')

                        service = EdgeService(EdgeChromiumDriverManager().install())
                        self.driver = webdriver.Edge(service=service, options=edge_options)
                        logger.info("Successfully initialized Edge browser")
                        break

                except WebDriverException as e:
                    logger.warning(f"Failed to initialize {browser} browser: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Unexpected error initializing {browser}: {e}")
                    continue

            if self.driver is None:
                error_msg = f"Failed to initialize any browser. Tried: {', '.join(BROWSER_PREFERENCE)}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            self.driver.implicitly_wait(10)

    def close_driver(self):
        """Close the WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

    async def login(self) -> bool:
        """Login to vendor website - override in subclasses"""
        raise NotImplementedError

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search for products - override in subclasses"""
        raise NotImplementedError

    async def get_quote(self, item_description: str, quantity: int = 1) -> List[Dict]:
        """Get quotes for an item"""
        # Check if demo mode is forced
        if FORCE_DEMO_MODE:
            logger.info(f"FORCE_DEMO_MODE enabled - returning demo quote for {item_description}")
            return self._get_demo_quote(item_description, quantity)

        # Try real browser automation
        try:
            self.init_driver()

            if not self.is_logged_in:
                await self.login()

            result = await self.search_product(item_description, quantity)

            # If real scraping succeeded and returned data, use it
            if result:
                logger.info(f"Successfully fetched real quote for {item_description}")
                return result
            else:
                # Real scraping returned empty
                # Check both PRODUCTION_MODE and allow_demo_fallback setting
                if PRODUCTION_MODE or not self.allow_demo_fallback:
                    # Fail loudly - no fallback to demo data
                    error_msg = f"Failed to fetch real quote for {item_description}: No results found from vendor website"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)
                else:
                    # Fall back to demo
                    logger.warning(f"Real scraping returned no results, using demo data for {item_description}")
                    return self._get_demo_quote(item_description, quantity)

        except RuntimeError as e:
            # Browser initialization failed or real scraping failed
            # Check both PRODUCTION_MODE and allow_demo_fallback setting
            if PRODUCTION_MODE or not self.allow_demo_fallback:
                # Fail loudly - no fallback to demo data
                logger.error(f"Quote request failed (demo fallback disabled) - {e}")
                raise  # Re-raise the error to fail loudly
            else:
                # Return demo data
                logger.warning(f"Browser not available, returning demo data: {e}")
                return self._get_demo_quote(item_description, quantity)
        except Exception as e:
            # Check both PRODUCTION_MODE and allow_demo_fallback setting
            if PRODUCTION_MODE or not self.allow_demo_fallback:
                # Fail loudly - no fallback to demo data
                error_msg = f"Failed to fetch real quote for {item_description}: {e}"
                logger.error(f"Quote request failed (demo fallback disabled): {error_msg}")
                raise RuntimeError(error_msg)
            else:
                # Fall back to demo data
                logger.error(f"Error getting quote, falling back to demo data: {e}")
                return self._get_demo_quote(item_description, quantity)
        finally:
            self.close_driver()

    def _get_demo_quote(self, query: str, quantity: int) -> List[Dict]:
        """Generate demo quote data when browser automation is not available"""
        # This is implemented in each subclass
        return []


class HomeDepotQuoteFetcher(VendorQuoteFetcher):
    """Home Depot specific implementation with real web scraping"""

    BASE_URL = "https://www.homedepot.com"
    LOGIN_URL = "https://www.homedepot.com/auth/view/signin"

    async def login(self) -> bool:
        """Login to Home Depot"""
        try:
            logger.info("Logging into Home Depot...")
            self.driver.get(self.LOGIN_URL)

            # Wait for login form
            wait = WebDriverWait(self.driver, 15)

            # Find and fill email field
            email_field = wait.until(EC.presence_of_element_located((By.ID, "Email")))
            email_field.clear()
            email_field.send_keys(self.username)

            # Find and fill password field
            password_field = self.driver.find_element(By.ID, "Password")
            password_field.clear()
            password_field.send_keys(self.password)

            # Click login button
            login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            login_button.click()

            # Wait for redirect to home page
            time.sleep(3)

            # Check if login was successful
            if "myaccount" in self.driver.current_url or self.driver.current_url == self.BASE_URL + "/":
                logger.info("Successfully logged into Home Depot")
                self.is_logged_in = True
                return True
            else:
                logger.warning("Home Depot login may have failed")
                self.is_logged_in = False
                return False

        except Exception as e:
            logger.error(f"Home Depot login failed: {e}")
            self.is_logged_in = False
            return False

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search Home Depot for products and extract real pricing"""
        try:
            logger.info(f"Searching Home Depot for: {query}")

            # Navigate to search page
            search_url = f"{self.BASE_URL}/s/{query.replace(' ', '%20')}"
            self.driver.get(search_url)

            time.sleep(2)

            # Wait for search results
            wait = WebDriverWait(self.driver, 10)

            # Find first product in results
            try:
                first_product = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "div.product-pod")))
            except TimeoutException:
                logger.warning("No products found on Home Depot")
                return []

            # Extract product information
            product_name = first_product.find_element(By.CSS_SELECTOR, "span.product-header__title").text

            # Extract price
            try:
                price_element = first_product.find_element(By.CSS_SELECTOR, "div.price")
                price_text = price_element.text.replace('$', '').replace(',', '').strip()
                unit_price = float(price_text.split()[0])
            except:
                logger.warning("Could not extract price from Home Depot")
                unit_price = 0.0

            # Extract product URL
            try:
                product_link = first_product.find_element(By.CSS_SELECTOR, "a.product-pod__title")
                product_url = product_link.get_attribute('href')
            except:
                product_url = search_url

            # Extract SKU/Item number
            try:
                sku_element = first_product.find_element(By.CSS_SELECTOR, "span.product-identifier")
                sku = sku_element.text.split('#')[-1].strip()
            except:
                sku = f"HD-{abs(hash(query)) % 1000000}"

            # Extract availability
            try:
                availability_element = first_product.find_element(By.CSS_SELECTOR, "div.fulfillment__availability")
                availability = availability_element.text
            except:
                availability = "Check store availability"

            return [{
                'vendor_name': 'Home Depot',
                'item_name': product_name,
                'item_description': product_name,
                'unit_price': unit_price,
                'quantity': quantity,
                'total_price': unit_price * quantity,
                'vendor_item_number': sku,
                'availability': availability,
                'vendor_url': product_url
            }]

        except Exception as e:
            logger.error(f"Home Depot search failed: {e}")
            return []

    def _get_demo_quote(self, query: str, quantity: int) -> List[Dict]:
        """Return demo data for Home Depot when browser automation fails"""
        base_prices = {
            'light': 8.97, 'bulb': 12.49, 'led': 15.99, 'filter': 24.99,
            'paint': 34.98, 'lock': 19.97, 'faucet': 89.99, 'door': 199.00,
            'battery': 6.99, 'cleaning': 7.49, 'bleach': 3.99, 'outdoor': 12.99
        }

        query_lower = query.lower()
        unit_price = 25.00  # Default
        for keyword, price in base_prices.items():
            if keyword in query_lower:
                unit_price = price
                break

        product_id = abs(hash(query)) % 1000000000
        product_slug = query.lower().replace(' ', '-').replace('/', '-')
        product_url = f"{self.BASE_URL}/p/{product_slug}/{product_id}"

        return [{
            'vendor_name': 'Home Depot',
            'item_name': f"⚠️ DEMO: {query}",
            'item_description': f"⚠️ WARNING: This is SIMULATED pricing data, NOT real! Do not use for actual purchases. ({query} - Professional Grade)",
            'unit_price': unit_price,
            'quantity': quantity,
            'total_price': unit_price * quantity,
            'vendor_item_number': f"DEMO-HD-{hash(query) % 100000}",
            'availability': '⚠️ DEMO MODE - Not Real Availability',
            'vendor_url': product_url
        }]


class LowesQuoteFetcher(VendorQuoteFetcher):
    """Lowe's specific implementation using ScraperAPI to bypass anti-bot protection"""

    BASE_URL = "https://www.lowes.com"
    LOGIN_URL = "https://www.lowes.com/mylowes/login"
    SCRAPERAPI_URL = "http://api.scraperapi.com"

    def __init__(self, username: str = "", encrypted_password: str = "", allow_demo_fallback: bool = True):
        """Initialize Lowe's fetcher - doesn't need credentials for public pricing"""
        super().__init__(username, encrypted_password, allow_demo_fallback)
        self.scraperapi_key = SCRAPERAPI_KEY

    async def login(self) -> bool:
        """Login not required for Lowe's public pricing via ScraperAPI"""
        # ScraperAPI fetches public pages - no login needed for basic pricing
        if self.scraperapi_key:
            logger.info("Lowe's: Using ScraperAPI for public pricing (no login required)")
            self.is_logged_in = True
            return True
        else:
            logger.warning("Lowe's: No ScraperAPI key configured, will use demo mode")
            self.is_logged_in = False
            return False

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search Lowe's for products using ScraperAPI"""
        # If no ScraperAPI key, fall back to demo mode
        if not self.scraperapi_key:
            logger.warning("No ScraperAPI key configured - using demo mode for Lowe's")
            return self._get_demo_quote(query, quantity)

        try:
            logger.info(f"Searching Lowe's via ScraperAPI for: {query}")

            # Build Lowe's search URL
            search_url = f"{self.BASE_URL}/search?searchTerm={quote_plus(query)}"

            # ScraperAPI parameters
            params = {
                'api_key': self.scraperapi_key,
                'url': search_url,
                'render': 'true',  # JavaScript rendering for React site
                'country_code': 'us',
            }

            # Make request via ScraperAPI
            logger.info(f"Fetching via ScraperAPI: {search_url}")
            response = requests.get(self.SCRAPERAPI_URL, params=params, timeout=60)

            if response.status_code != 200:
                logger.error(f"ScraperAPI returned status {response.status_code}")
                if self.allow_demo_fallback and not PRODUCTION_MODE:
                    return self._get_demo_quote(query, quantity)
                return []

            html = response.text

            # Check if we got blocked anyway
            if "access denied" in html.lower() or "something went wrong" in html.lower():
                logger.warning("Lowe's blocked request even via ScraperAPI")
                if self.allow_demo_fallback and not PRODUCTION_MODE:
                    return self._get_demo_quote(query, quantity)
                return []

            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')

            # Try to find products with various selectors
            products = []
            product_selectors = [
                'div[data-selector="splp-prd-grid-tile"]',
                'div.product-card',
                '[class*="ProductCard"]',
                '[class*="product-card"]',
                'div[data-itemid]',
            ]

            for selector in product_selectors:
                products = soup.select(selector)
                if products:
                    logger.info(f"Found {len(products)} products with selector: {selector}")
                    break

            if not products:
                logger.warning(f"No products found for query: {query}")
                if self.allow_demo_fallback and not PRODUCTION_MODE:
                    return self._get_demo_quote(query, quantity)
                return []

            # Extract info from first product
            first = products[0]

            # Get product name
            product_name = query  # Default
            name_selectors = ['[class*="title"]', 'h2', 'h3', 'a[href*="/pd/"]']
            for sel in name_selectors:
                name_elem = first.select_one(sel)
                if name_elem and name_elem.get_text(strip=True):
                    product_name = name_elem.get_text(strip=True)[:100]
                    break

            # Get price
            unit_price = 0.0
            price_selectors = ['[class*="price"]', 'span.price', 'div.price']
            for sel in price_selectors:
                price_elem = first.select_one(sel)
                if price_elem:
                    price_text = price_elem.get_text(strip=True)
                    price_match = re.search(r'\$?([\d,]+\.?\d*)', price_text)
                    if price_match:
                        unit_price = float(price_match.group(1).replace(',', ''))
                        logger.info(f"Extracted price: ${unit_price}")
                        break

            # Get product URL
            product_url = search_url
            link_elem = first.select_one('a[href*="/pd/"]')
            if link_elem:
                href = link_elem.get('href', '')
                if href.startswith('/'):
                    product_url = self.BASE_URL + href
                elif href.startswith('http'):
                    product_url = href

            # Get item number
            item_number = f"LOW-{abs(hash(query)) % 1000000}"
            if first.get('data-itemid'):
                item_number = first.get('data-itemid')

            logger.info(f"Found Lowe's product: {product_name} - ${unit_price}")

            return [{
                'vendor_name': "Lowe's",
                'item_name': product_name,
                'item_description': product_name,
                'unit_price': unit_price,
                'quantity': quantity,
                'total_price': unit_price * quantity,
                'vendor_item_number': item_number,
                'availability': 'Check store availability',
                'vendor_url': product_url
            }]

        except requests.Timeout:
            logger.error("ScraperAPI request timed out")
            if self.allow_demo_fallback and not PRODUCTION_MODE:
                return self._get_demo_quote(query, quantity)
            return []
        except Exception as e:
            logger.error(f"Lowe's ScraperAPI search failed: {e}")
            if self.allow_demo_fallback and not PRODUCTION_MODE:
                return self._get_demo_quote(query, quantity)
            return []

    async def _legacy_login(self) -> bool:
        """Login to Lowe's - handles two-step login flow"""
        try:
            logger.info("Logging into Lowe's...")
            self.driver.get(self.LOGIN_URL)
            time.sleep(3)

            wait = WebDriverWait(self.driver, 15)
            short_wait = WebDriverWait(self.driver, 5)

            # Find and fill email field - try multiple selectors
            email_field = None
            email_selectors = [
                (By.ID, "email"),
                (By.NAME, "email"),
                (By.CSS_SELECTOR, "input[type='email']"),
                (By.XPATH, "//input[@type='email' or @name='email']"),
                (By.CSS_SELECTOR, "input[autocomplete='email']"),
                (By.CSS_SELECTOR, "input[autocomplete='username']")
            ]

            for selector_type, selector_value in email_selectors:
                try:
                    email_field = wait.until(EC.element_to_be_clickable((selector_type, selector_value)))
                    logger.info(f"Found email field using: {selector_type}")
                    break
                except:
                    continue

            if not email_field:
                raise Exception("Could not find email field")

            email_field.clear()
            email_field.send_keys(self.username)
            logger.info(f"Entered email: {self.username}")
            time.sleep(1)

            # Check if password field is already visible (single-page login)
            password_field = None
            password_selectors = [
                (By.ID, "password"),
                (By.NAME, "password"),
                (By.CSS_SELECTOR, "input[type='password']"),
                (By.XPATH, "//input[@type='password']"),
                (By.CSS_SELECTOR, "input[autocomplete='current-password']")
            ]

            for selector_type, selector_value in password_selectors:
                try:
                    password_field = self.driver.find_element(selector_type, selector_value)
                    if password_field.is_displayed():
                        logger.info(f"Found password field (single-page login) using: {selector_type}")
                        break
                    else:
                        password_field = None
                except:
                    continue

            # If password field not found, this might be two-step login
            # Click continue/next button to proceed to password step
            if not password_field:
                logger.info("Password field not visible - trying two-step login flow")

                # Log page info for debugging
                try:
                    logger.info(f"Current URL: {self.driver.current_url}")
                    logger.info(f"Page title: {self.driver.title}")
                except Exception as e:
                    logger.warning(f"Could not get page info: {e}")

                # Log all buttons on page for debugging
                try:
                    all_buttons = self.driver.find_elements(By.TAG_NAME, "button")
                    logger.info(f"DEBUG: Found {len(all_buttons)} buttons on page")
                    for i, btn in enumerate(all_buttons[:10]):  # Log first 10 buttons
                        try:
                            btn_text = btn.text.strip()[:50] if btn.text else "(no text)"
                            btn_type = btn.get_attribute("type") or "(no type)"
                            btn_class = btn.get_attribute("class") or "(no class)"
                            btn_displayed = btn.is_displayed()
                            logger.info(f"DEBUG Button {i}: text='{btn_text}', type='{btn_type}', visible={btn_displayed}, class='{btn_class[:60]}'")
                        except Exception as btn_err:
                            logger.warning(f"DEBUG Button {i}: Could not inspect - {btn_err}")
                except Exception as e:
                    logger.warning(f"Could not enumerate buttons: {e}")

                # Also log all input fields
                try:
                    all_inputs = self.driver.find_elements(By.TAG_NAME, "input")
                    logger.info(f"DEBUG: Found {len(all_inputs)} input fields on page")
                    for i, inp in enumerate(all_inputs[:10]):
                        try:
                            inp_type = inp.get_attribute("type") or "(no type)"
                            inp_name = inp.get_attribute("name") or "(no name)"
                            inp_id = inp.get_attribute("id") or "(no id)"
                            inp_displayed = inp.is_displayed()
                            logger.info(f"DEBUG Input {i}: type='{inp_type}', name='{inp_name}', id='{inp_id}', visible={inp_displayed}")
                        except Exception as inp_err:
                            logger.warning(f"DEBUG Input {i}: Could not inspect - {inp_err}")
                except Exception as e:
                    logger.warning(f"Could not enumerate inputs: {e}")

                # Look for continue/next button with expanded selectors
                continue_button = None
                continue_selectors = [
                    # Text-based selectors using normalize-space and descendant text (for React/styled-components)
                    (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'continue')]"),
                    (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'next')]"),
                    (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in')]"),
                    (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'log in')]"),
                    (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'submit')]"),
                    # Fallback: direct text matching
                    (By.XPATH, "//button[contains(text(), 'Continue')]"),
                    (By.XPATH, "//button[contains(text(), 'continue')]"),
                    # Type-based selectors
                    (By.CSS_SELECTOR, "button[type='submit']"),
                    (By.XPATH, "//button[@type='submit']"),
                    (By.CSS_SELECTOR, "input[type='submit']"),
                    # Class-based selectors
                    (By.CSS_SELECTOR, "button.continue-btn"),
                    (By.CSS_SELECTOR, "button.submit-btn"),
                    (By.CSS_SELECTOR, "button.btn-primary"),
                    (By.CSS_SELECTOR, "button.primary"),
                    (By.CSS_SELECTOR, "button[class*='submit']"),
                    (By.CSS_SELECTOR, "button[class*='continue']"),
                    (By.CSS_SELECTOR, "button[class*='primary']"),
                    # Generic button in form
                    (By.XPATH, "//form//button"),
                ]

                for selector_type, selector_value in continue_selectors:
                    try:
                        elements = self.driver.find_elements(selector_type, selector_value)
                        for elem in elements:
                            if elem.is_displayed() and elem.is_enabled():
                                continue_button = elem
                                logger.info(f"Found continue button using: {selector_type} = {selector_value}")
                                break
                        if continue_button:
                            break
                    except Exception as e:
                        continue

                if continue_button:
                    try:
                        # Try regular click first
                        continue_button.click()
                        logger.info("Clicked continue button, waiting for password field...")
                    except Exception as e:
                        logger.warning(f"Regular click failed: {e}, trying JavaScript click")
                        try:
                            self.driver.execute_script("arguments[0].click();", continue_button)
                            logger.info("JavaScript click succeeded")
                        except Exception as e2:
                            logger.error(f"JavaScript click also failed: {e2}")
                    time.sleep(5)  # Increased wait time

                    # Log page state after clicking continue
                    try:
                        logger.info(f"After clicking continue - URL: {self.driver.current_url}")
                        logger.info(f"After clicking continue - Title: {self.driver.title}")
                        # Log what inputs are now visible
                        all_inputs = self.driver.find_elements(By.TAG_NAME, "input")
                        logger.info(f"After clicking continue - Found {len(all_inputs)} input fields")
                        for i, inp in enumerate(all_inputs[:5]):
                            try:
                                inp_type = inp.get_attribute("type") or "(no type)"
                                inp_name = inp.get_attribute("name") or "(no name)"
                                inp_displayed = inp.is_displayed()
                                logger.info(f"Input {i}: type='{inp_type}', name='{inp_name}', visible={inp_displayed}")
                            except:
                                pass
                    except Exception as e:
                        logger.warning(f"Could not log page state after continue: {e}")

                    # Now look for password field again
                    for selector_type, selector_value in password_selectors:
                        try:
                            password_field = wait.until(EC.element_to_be_clickable((selector_type, selector_value)))
                            logger.info(f"Found password field (two-step login) using: {selector_type}")
                            break
                        except:
                            continue
                else:
                    # No continue button found - try pressing Enter on email field
                    logger.info("No continue button found, trying Enter key on email field")
                    try:
                        from selenium.webdriver.common.keys import Keys
                        email_field.send_keys(Keys.RETURN)
                        logger.info("Pressed Enter on email field")
                        time.sleep(3)

                        # Look for password field again
                        for selector_type, selector_value in password_selectors:
                            try:
                                password_field = wait.until(EC.element_to_be_clickable((selector_type, selector_value)))
                                logger.info(f"Found password field after Enter key using: {selector_type}")
                                break
                            except:
                                continue
                    except Exception as e:
                        logger.error(f"Enter key approach failed: {e}")

            if not password_field:
                # Log page source for debugging
                logger.error("Could not find password field. Page title: " + self.driver.title)
                raise Exception("Could not find password field after trying all selectors")

            password_field.clear()
            password_field.send_keys(self.password)
            logger.info("Entered password")
            time.sleep(1)

            # Click sign in button
            login_button = None
            button_selectors = [
                (By.CSS_SELECTOR, "button[type='submit']"),
                # Use normalize-space(.) to get all descendant text (for React/styled-components)
                (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in')]"),
                (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'log in')]"),
                (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'login')]"),
                (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'submit')]"),
                (By.XPATH, "//button[contains(translate(normalize-space(.), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'continue')]"),
                (By.CSS_SELECTOR, "button.btn-primary"),
                (By.CSS_SELECTOR, "button.primary"),
                (By.CSS_SELECTOR, "button[class*='primary']"),
                (By.CSS_SELECTOR, "button[class*='submit']"),
                (By.CSS_SELECTOR, "input[type='submit']"),
                (By.XPATH, "//button[@type='submit']"),
                (By.XPATH, "//form//button"),
            ]

            for selector_type, selector_value in button_selectors:
                try:
                    elements = self.driver.find_elements(selector_type, selector_value)
                    for elem in elements:
                        if elem.is_displayed() and elem.is_enabled():
                            login_button = elem
                            logger.info(f"Found login button using: {selector_type}")
                            break
                    if login_button:
                        break
                except:
                    continue

            if login_button:
                try:
                    login_button.click()
                    logger.info("Clicked login button, waiting for redirect...")
                except Exception as e:
                    logger.warning(f"Regular click failed: {e}, trying JavaScript click")
                    try:
                        self.driver.execute_script("arguments[0].click();", login_button)
                        logger.info("JavaScript click succeeded")
                    except Exception as e2:
                        logger.error(f"JavaScript click also failed: {e2}")
            else:
                # No login button found - try pressing Enter on password field
                logger.info("No login button found, trying Enter key on password field")
                try:
                    from selenium.webdriver.common.keys import Keys
                    password_field.send_keys(Keys.RETURN)
                    logger.info("Pressed Enter on password field")
                except Exception as e:
                    logger.error(f"Enter key approach failed: {e}")
                    raise Exception("Could not find login button and Enter key failed")
            time.sleep(5)

            # Check if login was successful
            current_url = self.driver.current_url
            logger.info(f"After login attempt, current URL: {current_url}")

            if "mylowes" in current_url or current_url == self.BASE_URL + "/" or "account" in current_url:
                logger.info("Successfully logged into Lowe's")
                self.is_logged_in = True
                return True
            else:
                logger.warning(f"Lowe's login may have failed - URL: {current_url}")
                self.is_logged_in = False
                return False

        except Exception as e:
            logger.error(f"Lowe's login failed: {e}")
            self.is_logged_in = False
            return False

    async def _legacy_search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """[LEGACY - Not used] Search Lowe's using Selenium (blocked by anti-bot)"""
        try:
            logger.info(f"Searching Lowe's for: {query}")

            # Navigate to search page - use URL encoding for special chars
            search_url = f"{self.BASE_URL}/search?searchTerm={quote_plus(query)}"
            logger.info(f"Navigating to: {search_url}")
            self.driver.get(search_url)

            time.sleep(5)  # Increased wait time for page load

            # Log page info for debugging
            logger.info(f"Search page URL: {self.driver.current_url}")
            logger.info(f"Search page title: {self.driver.title}")

            wait = WebDriverWait(self.driver, 20)  # Increased timeout

            # Find first product in results - try multiple selectors
            first_product = None
            product_selectors = [
                (By.CSS_SELECTOR, "div[data-selector='splp-prd-grid-tile']"),
                (By.CSS_SELECTOR, "div.product-card"),
                (By.CSS_SELECTOR, "div[data-itemid]"),
                (By.CSS_SELECTOR, "[class*='ProductCard']"),
                (By.CSS_SELECTOR, "[class*='product-card']"),
                (By.CSS_SELECTOR, "article.product"),
                (By.CSS_SELECTOR, "div.product-pod"),
                (By.CSS_SELECTOR, "[data-testid*='product']"),
                (By.XPATH, "//div[contains(@class, 'product')]"),
                (By.XPATH, "//article[contains(@class, 'product')]"),
            ]

            for selector_type, selector_value in product_selectors:
                try:
                    first_product = wait.until(EC.presence_of_element_located((selector_type, selector_value)))
                    logger.info(f"Found product using: {selector_type} = {selector_value}")
                    break
                except TimeoutException:
                    logger.info(f"Selector not found: {selector_value}")
                    continue

            if not first_product:
                # Log page content for debugging
                logger.warning("No products found on Lowe's")
                try:
                    # Check if there's an error message or captcha
                    body_text = self.driver.find_element(By.TAG_NAME, "body").text[:500]
                    logger.info(f"Page body (first 500 chars): {body_text}")
                except Exception as e:
                    logger.warning(f"Could not get page body: {e}")
                return []

            # Extract product information - try multiple selectors
            product_name = "Unknown Product"
            name_selectors = [
                (By.CSS_SELECTOR, "div.product-title"),
                (By.CSS_SELECTOR, "h2.product-title"),
                (By.CSS_SELECTOR, "span.product-title"),
                (By.XPATH, ".//*[contains(@class, 'title')]")
            ]

            for selector_type, selector_value in name_selectors:
                try:
                    element = first_product.find_element(selector_type, selector_value)
                    product_name = element.text.strip()
                    if product_name:
                        break
                except:
                    continue

            # Extract price - try multiple selectors
            unit_price = 0.0
            price_selectors = [
                (By.CSS_SELECTOR, "span.price-amount"),
                (By.CSS_SELECTOR, "span.price"),
                (By.CSS_SELECTOR, "div.price"),
                (By.XPATH, ".//*[contains(@class, 'price')]")
            ]

            for selector_type, selector_value in price_selectors:
                try:
                    price_element = first_product.find_element(selector_type, selector_value)
                    price_text = price_element.text.replace('$', '').replace(',', '').strip()
                    # Extract just the number
                    import re
                    price_match = re.search(r'(\d+\.?\d*)', price_text)
                    if price_match:
                        unit_price = float(price_match.group(1))
                        logger.info(f"Extracted price: ${unit_price}")
                        break
                except:
                    continue

            # Extract product URL
            product_url = search_url
            link_selectors = [
                (By.CSS_SELECTOR, "a.product-link"),
                (By.CSS_SELECTOR, "a[href*='/pd/']"),
                (By.TAG_NAME, "a")
            ]

            for selector_type, selector_value in link_selectors:
                try:
                    product_link = first_product.find_element(selector_type, selector_value)
                    href = product_link.get_attribute('href')
                    if href:
                        product_url = href if href.startswith('http') else self.BASE_URL + href
                        break
                except:
                    continue

            # Extract item number
            item_number = f"LOW-{abs(hash(query)) % 1000000}"
            try:
                item_num = first_product.get_attribute('data-itemid') or first_product.get_attribute('data-item-number')
                if item_num:
                    item_number = item_num
            except:
                pass

            # Extract availability
            availability = "Check store availability"
            availability_selectors = [
                (By.CSS_SELECTOR, "div.availability"),
                (By.CSS_SELECTOR, "span.availability"),
                (By.XPATH, ".//*[contains(@class, 'availability')]")
            ]

            for selector_type, selector_value in availability_selectors:
                try:
                    availability_element = first_product.find_element(selector_type, selector_value)
                    avail_text = availability_element.text.strip()
                    if avail_text:
                        availability = avail_text
                        break
                except:
                    continue

            logger.info(f"Found product: {product_name} - ${unit_price}")

            return [{
                'vendor_name': "Lowe's",
                'item_name': product_name,
                'item_description': product_name,
                'unit_price': unit_price,
                'quantity': quantity,
                'total_price': unit_price * quantity,
                'vendor_item_number': item_number,
                'availability': availability,
                'vendor_url': product_url
            }]

        except Exception as e:
            logger.error(f"Lowe's search failed: {e}")
            return []

    def _get_demo_quote(self, query: str, quantity: int) -> List[Dict]:
        """Return demo data for Lowe's when browser automation fails"""
        base_prices = {
            'light': 9.48, 'bulb': 11.98, 'led': 14.99, 'filter': 23.97,
            'paint': 32.98, 'lock': 18.97, 'faucet': 84.99, 'door': 189.00,
            'battery': 7.49, 'cleaning': 6.99, 'bleach': 3.79, 'outdoor': 11.99
        }

        query_lower = query.lower()
        unit_price = 24.00  # Default
        for keyword, price in base_prices.items():
            if keyword in query_lower:
                unit_price = price
                break

        product_id = abs(hash(query)) % 1000000000
        product_slug = query.lower().replace(' ', '-').replace('/', '-')
        product_url = f"{self.BASE_URL}/pd/{product_slug}/{product_id}"

        return [{
            'vendor_name': "Lowe's",
            'item_name': f"⚠️ DEMO: {query}",
            'item_description': f"⚠️ WARNING: This is SIMULATED pricing data, NOT real! Do not use for actual purchases. ({query} - Contractor Select)",
            'unit_price': unit_price,
            'quantity': quantity,
            'total_price': unit_price * quantity,
            'vendor_item_number': f"DEMO-LOW-{hash(query) % 100000}",
            'availability': '⚠️ DEMO MODE - Not Real Availability',
            'vendor_url': product_url
        }]


class GraingerQuoteFetcher(VendorQuoteFetcher):
    """Grainger specific implementation with real web scraping"""

    BASE_URL = "https://www.grainger.com"
    LOGIN_URL = "https://www.grainger.com/login"

    async def login(self) -> bool:
        """Login to Grainger"""
        try:
            logger.info("Logging into Grainger...")
            self.driver.get(self.LOGIN_URL)

            wait = WebDriverWait(self.driver, 15)

            # Find and fill username field
            username_field = wait.until(EC.presence_of_element_located((By.ID, "username")))
            username_field.clear()
            username_field.send_keys(self.username)

            # Find and fill password field
            password_field = self.driver.find_element(By.ID, "password")
            password_field.clear()
            password_field.send_keys(self.password)

            # Click login button
            login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            login_button.click()

            time.sleep(3)

            # Check if login was successful
            if "myaccount" in self.driver.current_url or self.driver.current_url == self.BASE_URL + "/":
                logger.info("Successfully logged into Grainger")
                self.is_logged_in = True
                return True
            else:
                logger.warning("Grainger login may have failed")
                self.is_logged_in = False
                return False

        except Exception as e:
            logger.error(f"Grainger login failed: {e}")
            self.is_logged_in = False
            return False

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search Grainger for products and extract real pricing"""
        try:
            logger.info(f"Searching Grainger for: {query}")

            # Navigate to search page
            search_url = f"{self.BASE_URL}/search?searchQuery={query.replace(' ', '+')}"
            self.driver.get(search_url)

            time.sleep(2)

            wait = WebDriverWait(self.driver, 10)

            # Find first product in results
            try:
                first_product = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "div.product-grid-item")))
            except TimeoutException:
                logger.warning("No products found on Grainger")
                return []

            # Extract product information
            product_name = first_product.find_element(By.CSS_SELECTOR, "div.product-title").text

            # Extract price
            try:
                price_element = first_product.find_element(By.CSS_SELECTOR, "span.product-price")
                price_text = price_element.text.replace('$', '').replace(',', '').strip()
                unit_price = float(price_text.split('/')[0])
            except:
                logger.warning("Could not extract price from Grainger")
                unit_price = 0.0

            # Extract product URL
            try:
                product_link = first_product.find_element(By.CSS_SELECTOR, "a.product-link")
                product_url = self.BASE_URL + product_link.get_attribute('href')
            except:
                product_url = search_url

            # Extract Grainger item number
            try:
                item_element = first_product.find_element(By.CSS_SELECTOR, "span.grainger-id")
                item_number = item_element.text
            except:
                item_number = f"GR-{abs(hash(query)) % 1000000}"

            # Extract availability
            try:
                availability_element = first_product.find_element(By.CSS_SELECTOR, "div.availability-info")
                availability = availability_element.text
            except:
                availability = "Ships in 1-2 business days"

            return [{
                'vendor_name': 'Grainger',
                'item_name': product_name,
                'item_description': product_name,
                'unit_price': unit_price,
                'quantity': quantity,
                'total_price': unit_price * quantity,
                'vendor_item_number': item_number,
                'availability': availability,
                'vendor_url': product_url
            }]

        except Exception as e:
            logger.error(f"Grainger search failed: {e}")
            return []

    def _get_demo_quote(self, query: str, quantity: int) -> List[Dict]:
        """Return demo data for Grainger when browser automation fails"""
        base_prices = {
            'light': 11.99, 'bulb': 15.49, 'led': 19.99, 'filter': 29.99,
            'paint': 39.98, 'lock': 24.97, 'faucet': 109.99, 'door': 229.00,
            'battery': 8.99, 'cleaning': 9.49, 'bleach': 4.99, 'outdoor': 14.99
        }

        query_lower = query.lower()
        unit_price = 28.00  # Default
        for keyword, price in base_prices.items():
            if keyword in query_lower:
                unit_price = price
                break

        product_id = abs(hash(query)) % 1000000000
        item_number = f"DEMO-GR-{hash(query) % 100000}"
        product_url = f"{self.BASE_URL}/product/{item_number}/ecatalog/N{product_id}"

        return [{
            'vendor_name': 'Grainger',
            'item_name': f"⚠️ DEMO: {query}",
            'item_description': f"⚠️ WARNING: This is SIMULATED pricing data, NOT real! Do not use for actual purchases. ({query} - Industrial Grade)",
            'unit_price': unit_price,
            'quantity': quantity,
            'total_price': unit_price * quantity,
            'vendor_item_number': item_number,
            'availability': '⚠️ DEMO MODE - Not Real Availability',
            'vendor_url': product_url
        }]


# Factory to get the right fetcher for a vendor
VENDOR_FETCHERS = {
    "Home Depot": HomeDepotQuoteFetcher,
    "Lowe's": LowesQuoteFetcher,
    "Grainger": GraingerQuoteFetcher,
}

def get_vendor_fetcher(vendor_name: str, username: str, encrypted_password: str, allow_demo_fallback: bool = True) -> Optional[VendorQuoteFetcher]:
    """Get the appropriate fetcher for a vendor"""
    fetcher_class = VENDOR_FETCHERS.get(vendor_name)
    if fetcher_class:
        return fetcher_class(username, encrypted_password, allow_demo_fallback)
    return None


async def fetch_quotes_from_vendors(
    item_description: str,
    quantity: int,
    vendor_credentials: List[Dict],
    allow_demo_fallback: bool = True
) -> List[Dict]:
    """
    Fetch quotes from multiple vendors concurrently

    Args:
        item_description: What to search for
        quantity: How many
        vendor_credentials: List of {vendor_name, username, encrypted_password}
        allow_demo_fallback: Whether to allow fallback to demo quotes if real scraping fails

    Returns:
        List of quote dictionaries
    """
    tasks = []

    for cred in vendor_credentials:
        fetcher = get_vendor_fetcher(
            cred['vendor_name'],
            cred['username'],
            cred['encrypted_password'],
            allow_demo_fallback
        )

        if fetcher:
            tasks.append(fetcher.get_quote(item_description, quantity))

    # Run all fetchers concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Flatten results and filter out errors
    quotes = []
    for result in results:
        if isinstance(result, list):
            quotes.extend(result)

    return quotes


def generate_email_html(quote_request: Dict, quotes: List[Dict]) -> str:
    """
    Generate email-ready HTML for quotes

    Args:
        quote_request: {item_description, quantity, property_name, etc.}
        quotes: List of quote dictionaries

    Returns:
        HTML string ready for email
    """
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }}
            .header {{
                background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%);
                color: white;
                padding: 30px;
                border-radius: 8px;
                margin-bottom: 30px;
            }}
            .header h1 {{
                margin: 0 0 10px 0;
                font-size: 28px;
            }}
            .header p {{
                margin: 0;
                opacity: 0.9;
            }}
            .request-details {{
                background: #f8fafc;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 30px;
                border-left: 4px solid #4f46e5;
            }}
            .request-details h2 {{
                margin-top: 0;
                color: #4f46e5;
            }}
            .detail-row {{
                margin: 10px 0;
            }}
            .detail-label {{
                font-weight: bold;
                color: #64748b;
            }}
            .quotes-container {{
                margin-top: 30px;
            }}
            .quote-card {{
                background: white;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }}
            .quote-vendor {{
                font-size: 20px;
                font-weight: bold;
                color: #1e293b;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            .quote-price {{
                font-size: 28px;
                color: #10b981;
                font-weight: bold;
            }}
            .quote-details {{
                margin-top: 15px;
                padding-top: 15px;
                border-top: 1px solid #e2e8f0;
            }}
            .quote-row {{
                display: flex;
                justify-content: space-between;
                margin: 8px 0;
                font-size: 14px;
            }}
            .quote-label {{
                color: #64748b;
            }}
            .quote-value {{
                font-weight: 500;
                color: #1e293b;
            }}
            .quote-link {{
                display: inline-block;
                margin-top: 15px;
                padding: 10px 20px;
                background: #4f46e5;
                color: white;
                text-decoration: none;
                border-radius: 6px;
                font-size: 14px;
            }}
            .quote-link:hover {{
                background: #4338ca;
            }}
            .best-price {{
                background: #d1fae5;
                border-color: #10b981;
            }}
            .best-price .quote-vendor::after {{
                content: "BEST PRICE";
                font-size: 12px;
                background: #10b981;
                color: white;
                padding: 4px 12px;
                border-radius: 20px;
            }}
            .footer {{
                margin-top: 40px;
                padding-top: 20px;
                border-top: 2px solid #e2e8f0;
                text-align: center;
                color: #64748b;
                font-size: 14px;
            }}
            .summary-table {{
                width: 100%;
                margin-top: 20px;
                border-collapse: collapse;
            }}
            .summary-table th {{
                background: #f1f5f9;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #475569;
                border-bottom: 2px solid #e2e8f0;
            }}
            .summary-table td {{
                padding: 12px;
                border-bottom: 1px solid #e2e8f0;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🏢 Balancing Bolts Quote Comparison</h1>
            <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>

        <div class="request-details">
            <h2>Quote Request Details</h2>
            <div class="detail-row">
                <span class="detail-label">Item:</span> {quote_request.get('item_description', 'N/A')}
            </div>
            <div class="detail-row">
                <span class="detail-label">Quantity:</span> {quote_request.get('quantity', 1)}
            </div>
            <div class="detail-row">
                <span class="detail-label">Property:</span> {quote_request.get('property_name', 'N/A')}
            </div>
            <div class="detail-row">
                <span class="detail-label">Requested by:</span> {quote_request.get('user_name', 'N/A')}
            </div>
        </div>

        <div class="quotes-container">
            <h2>Price Comparison ({len(quotes)} vendors)</h2>
    """

    # Sort quotes by total price to identify best price
    sorted_quotes = sorted(quotes, key=lambda q: q.get('total_price', float('inf')))

    for i, quote in enumerate(sorted_quotes):
        best_class = ' best-price' if i == 0 and len(sorted_quotes) > 1 else ''

        html += f"""
            <div class="quote-card{best_class}">
                <div class="quote-vendor">
                    <span>{quote.get('vendor_name', 'Unknown Vendor')}</span>
                    <span class="quote-price">${quote.get('total_price', 0):.2f}</span>
                </div>
                <div class="quote-details">
                    <div class="quote-row">
                        <span class="quote-label">Product:</span>
                        <span class="quote-value">{quote.get('item_name', 'N/A')}</span>
                    </div>
                    <div class="quote-row">
                        <span class="quote-label">Unit Price:</span>
                        <span class="quote-value">${quote.get('unit_price', 0):.2f}</span>
                    </div>
                    <div class="quote-row">
                        <span class="quote-label">Quantity:</span>
                        <span class="quote-value">{quote.get('quantity', 1)}</span>
                    </div>
        """

        if quote.get('vendor_item_number'):
            html += f"""
                    <div class="quote-row">
                        <span class="quote-label">Item #:</span>
                        <span class="quote-value">{quote['vendor_item_number']}</span>
                    </div>
            """

        if quote.get('availability'):
            html += f"""
                    <div class="quote-row">
                        <span class="quote-label">Availability:</span>
                        <span class="quote-value">{quote['availability']}</span>
                    </div>
            """

        if quote.get('vendor_url'):
            html += f"""
                    <a href="{quote['vendor_url']}" class="quote-link" target="_blank">🔗 View Product on {quote.get('vendor_name')}</a>
            """

        html += """
                </div>
            </div>
        """

    # Add summary table
    html += """
        <h2 style="margin-top: 40px;">Summary</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Vendor</th>
                    <th>Unit Price</th>
                    <th>Total</th>
                    <th>Savings vs. Highest</th>
                </tr>
            </thead>
            <tbody>
    """

    if sorted_quotes:
        highest_price = sorted_quotes[-1].get('total_price', 0)
        for quote in sorted_quotes:
            total = quote.get('total_price', 0)
            savings = highest_price - total
            savings_pct = (savings / highest_price * 100) if highest_price > 0 else 0

            html += f"""
                <tr>
                    <td><strong>{quote.get('vendor_name', 'Unknown')}</strong></td>
                    <td>${quote.get('unit_price', 0):.2f}</td>
                    <td><strong>${total:.2f}</strong></td>
                    <td>${savings:.2f} ({savings_pct:.1f}%)</td>
                </tr>
            """

    html += """
            </tbody>
        </table>

        <div class="footer">
            <p><strong>Balancing Bolts</strong> - Apartment Inventory Management System</p>
            <p>This quote comparison was generated automatically from vendor websites.</p>
            <p style="margin-top: 10px; font-size: 12px;">
                Prices and availability are subject to change. Please verify with vendors before purchasing.
            </p>
        </div>
    </body>
    </html>
    """

    return html
