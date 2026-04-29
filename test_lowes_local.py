"""
Local test script for Lowe's scraper
Run this from your Windows machine to test scraping without cloud IP blocking

Usage:
    python test_lowes_local.py

Requirements:
    pip install selenium webdriver-manager
"""
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from webdriver_manager.chrome import ChromeDriverManager

# Your Lowe's credentials
EMAIL = "sraven0613@gmail.com"
PASSWORD = input("Enter your Lowe's password: ")

def test_lowes_login():
    print("Starting Lowe's login test...")

    # Set up Chrome options
    options = Options()
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_experimental_option('excludeSwitches', ['enable-automation'])
    options.add_experimental_option('useAutomationExtension', False)

    # Add a realistic user agent
    options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36')

    # Don't use headless for local testing - you can see what's happening
    # options.add_argument('--headless=new')

    print("Initializing Chrome browser...")
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)

    # Mask webdriver detection
    driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
        'source': '''
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        '''
    })

    try:
        # First visit the homepage to establish a normal session
        print("Visiting Lowe's homepage first...")
        driver.get("https://www.lowes.com")
        time.sleep(3)

        print(f"Homepage title: {driver.title}")

        # Check if we got blocked on homepage
        if "Access Denied" in driver.title or "something went wrong" in driver.page_source.lower():
            print("WARNING: Got blocked on homepage!")
            driver.save_screenshot("lowes_blocked.png")
            print("Screenshot saved to lowes_blocked.png")

        # Now navigate to login
        print("Navigating to Lowe's login page...")
        driver.get("https://www.lowes.com/mylowes/login")
        time.sleep(4)

        wait = WebDriverWait(driver, 15)

        # Find email field
        print("Looking for email field...")
        email_field = wait.until(EC.element_to_be_clickable((By.ID, "email")))
        print(f"Found email field, entering: {EMAIL}")
        email_field.clear()
        email_field.send_keys(EMAIL)
        time.sleep(1)

        # Check if password field is visible
        print("Checking for password field...")
        try:
            password_field = driver.find_element(By.ID, "password")
            if password_field.is_displayed():
                print("Password field visible (single-page login)")
            else:
                password_field = None
        except:
            password_field = None

        # If no password field, click Continue
        if not password_field:
            print("Password field not visible, looking for Continue button...")

            # List all buttons for debugging
            buttons = driver.find_elements(By.TAG_NAME, "button")
            print(f"Found {len(buttons)} buttons on page:")
            for i, btn in enumerate(buttons[:6]):
                try:
                    text = btn.text.strip()[:30] if btn.text else "(no text)"
                    visible = btn.is_displayed()
                    print(f"  Button {i}: '{text}' - visible={visible}")
                except:
                    pass

            # Find and click Continue button
            continue_btn = None
            for btn in buttons:
                try:
                    if btn.is_displayed() and 'continue' in btn.text.lower():
                        continue_btn = btn
                        break
                except:
                    pass

            if continue_btn:
                print("Clicking Continue button...")
                continue_btn.click()
                time.sleep(5)  # Wait longer for page transition

                print(f"After clicking continue - URL: {driver.current_url}")
                print(f"After clicking continue - Title: {driver.title}")

                # List ALL inputs on page with visibility status
                inputs = driver.find_elements(By.TAG_NAME, "input")
                print(f"Found {len(inputs)} input fields:")
                for i, inp in enumerate(inputs):
                    try:
                        inp_type = inp.get_attribute("type")
                        inp_name = inp.get_attribute("name")
                        inp_id = inp.get_attribute("id")
                        visible = inp.is_displayed()
                        enabled = inp.is_enabled()
                        print(f"  Input {i}: type='{inp_type}', name='{inp_name}', id='{inp_id}', visible={visible}, enabled={enabled}")
                    except Exception as e:
                        print(f"  Input {i}: Error - {e}")

                # Look for a VISIBLE password field specifically
                password_field = None
                for inp in inputs:
                    try:
                        if inp.get_attribute("type") == "password" and inp.is_displayed():
                            password_field = inp
                            print(f"Found VISIBLE password field: id='{inp.get_attribute('id')}', name='{inp.get_attribute('name')}'")
                            break
                    except:
                        continue

                if not password_field:
                    print("No visible password field found, trying wait...")
                    try:
                        # Wait for a visible password field
                        password_field = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type='password']")))
                        print("Found password field via visibility wait!")
                    except:
                        print("Could not find visible password field after Continue")
            else:
                print("Could not find Continue button, trying Enter key...")
                email_field.send_keys(Keys.RETURN)
                time.sleep(3)

                try:
                    password_field = wait.until(EC.element_to_be_clickable((By.ID, "password")))
                    print("Found password field after pressing Enter!")
                except:
                    print("Could not find password field after Enter")

        if password_field:
            print("Entering password...")
            # Wait for the field to be fully ready
            time.sleep(2)

            # Scroll the field into view
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", password_field)
            time.sleep(0.5)

            # Use ActionChains for realistic typing
            try:
                actions = ActionChains(driver)
                actions.move_to_element(password_field)
                actions.click()
                actions.perform()
                time.sleep(0.5)

                # Type password character by character
                print("Typing password with ActionChains...")
                for char in PASSWORD:
                    actions = ActionChains(driver)
                    actions.send_keys(char)
                    actions.perform()
                    time.sleep(0.05)  # Small delay between characters

                print("Password entered successfully via ActionChains")
            except Exception as e:
                print(f"ActionChains failed: {e}, trying direct send_keys...")
                try:
                    password_field.click()
                    password_field.clear()
                    password_field.send_keys(PASSWORD)
                except Exception as e2:
                    print(f"Direct send_keys also failed: {e2}")

            time.sleep(1)

            # Verify password was entered
            try:
                pwd_value = password_field.get_attribute("value")
                print(f"Password field value length: {len(pwd_value) if pwd_value else 0}")
            except:
                pass

            # Find and click Sign In button
            print("Looking for Sign In button...")
            buttons = driver.find_elements(By.TAG_NAME, "button")
            signin_btn = None
            for btn in buttons:
                try:
                    text = btn.text.lower()
                    if btn.is_displayed() and ('sign in' in text or 'login' in text or 'continue' in text):
                        signin_btn = btn
                        break
                except:
                    pass

            if signin_btn:
                print(f"Clicking Sign In button (text: '{signin_btn.text}')")
                signin_btn.click()
            else:
                print("No Sign In button found, pressing Enter...")
                password_field.send_keys(Keys.RETURN)

            time.sleep(5)

            print(f"After login - URL: {driver.current_url}")
            print(f"After login - Title: {driver.title}")

            if "mylowes" in driver.current_url or "account" in driver.current_url or driver.current_url == "https://www.lowes.com/":
                print("\n✓ LOGIN SUCCESSFUL!")

                # Try searching for a product
                print("\nTrying to search for 'Outdoor Bleach'...")
                driver.get("https://www.lowes.com/search?searchTerm=Outdoor+Bleach")
                time.sleep(5)

                print(f"Search page title: {driver.title}")

                if "Access Denied" in driver.title:
                    print("✗ Access Denied on search page")
                else:
                    print("✓ Search page loaded successfully!")

                    # Try to find products
                    body_text = driver.find_element(By.TAG_NAME, "body").text[:500]
                    print(f"Page content preview: {body_text[:300]}...")
            else:
                print("\n✗ Login may have failed")
                print(f"Current URL: {driver.current_url}")
        else:
            print("\n✗ Could not complete login - no password field found")

        input("\nPress Enter to close the browser...")

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to close the browser...")
    finally:
        driver.quit()

if __name__ == "__main__":
    test_lowes_login()
