"""
Local test script for Lowe's scraper using undetected-chromedriver
This library is specifically designed to bypass Cloudflare and bot detection

Usage:
    python test_lowes_undetected.py

Requirements:
    pip install undetected-chromedriver selenium
"""
import time
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys

# Your Lowe's credentials
EMAIL = "sraven0613@gmail.com"
PASSWORD = input("Enter your Lowe's password: ")

def test_lowes_login():
    print("Starting Lowe's login test with undetected-chromedriver...")

    # Initialize undetected Chrome - it handles all anti-detection automatically
    options = uc.ChromeOptions()
    options.add_argument('--window-size=1920,1080')

    # Don't use headless - more detectable
    # options.add_argument('--headless=new')

    print("Initializing undetected Chrome browser...")
    driver = uc.Chrome(options=options, use_subprocess=True)

    try:
        # First visit the homepage to establish cookies
        print("Visiting Lowe's homepage first...")
        driver.get("https://www.lowes.com")
        time.sleep(5)  # Give time for any challenges to complete

        print(f"Homepage title: {driver.title}")

        # Check if we got blocked
        page_source_lower = driver.page_source.lower()
        if "access denied" in driver.title.lower() or "something went wrong" in page_source_lower:
            print("WARNING: Got blocked on homepage!")
            driver.save_screenshot("lowes_blocked_undetected.png")
            print("Screenshot saved to lowes_blocked_undetected.png")
            input("Press Enter to continue anyway...")

        # Navigate to login via clicking Sign In (more natural than direct URL)
        print("Looking for Sign In link on homepage...")
        try:
            # Try to find and click the Sign In link
            sign_in_links = driver.find_elements(By.XPATH, "//a[contains(text(), 'Sign In') or contains(text(), 'sign in')]")
            if sign_in_links:
                print(f"Found {len(sign_in_links)} Sign In links")
                for link in sign_in_links:
                    if link.is_displayed():
                        print("Clicking Sign In link...")
                        link.click()
                        time.sleep(3)
                        break
            else:
                # Fallback to direct navigation
                print("No Sign In link found, navigating directly to login page...")
                driver.get("https://www.lowes.com/mylowes/login")
        except Exception as e:
            print(f"Could not click Sign In: {e}, navigating directly...")
            driver.get("https://www.lowes.com/mylowes/login")

        time.sleep(4)
        print(f"Current URL: {driver.current_url}")
        print(f"Page title: {driver.title}")

        wait = WebDriverWait(driver, 20)

        # Find email field with multiple selectors
        print("Looking for email field...")
        email_field = None
        email_selectors = [
            (By.ID, "email"),
            (By.NAME, "email"),
            (By.CSS_SELECTOR, "input[type='email']"),
            (By.CSS_SELECTOR, "input[autocomplete='email']"),
            (By.CSS_SELECTOR, "input[autocomplete='username']"),
            (By.XPATH, "//input[@type='email' or @name='email' or @id='email']"),
        ]

        for sel_type, sel_value in email_selectors:
            try:
                email_field = wait.until(EC.element_to_be_clickable((sel_type, sel_value)))
                print(f"Found email field with: {sel_type} = {sel_value}")
                break
            except:
                continue

        if not email_field:
            print("ERROR: Could not find email field!")
            driver.save_screenshot("lowes_no_email_field.png")
            input("Press Enter to close...")
            return

        # Enter email naturally
        print(f"Entering email: {EMAIL}")
        email_field.click()
        time.sleep(0.3)
        email_field.clear()
        for char in EMAIL:
            email_field.send_keys(char)
            time.sleep(0.02)  # Type like a human
        time.sleep(1)

        # Check if password field is already visible
        print("Checking for password field...")
        password_field = None
        try:
            pwd_elements = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
            for pwd in pwd_elements:
                if pwd.is_displayed():
                    password_field = pwd
                    print("Password field is already visible (single-page login)")
                    break
        except:
            pass

        # If no password field, we need to click Continue
        if not password_field:
            print("Password field not visible, looking for Continue/Next button...")

            # Debug: List all buttons
            all_buttons = driver.find_elements(By.TAG_NAME, "button")
            print(f"Found {len(all_buttons)} buttons:")
            for i, btn in enumerate(all_buttons[:8]):
                try:
                    txt = btn.text.strip()[:40] if btn.text else "(empty)"
                    vis = btn.is_displayed()
                    print(f"  Button {i}: '{txt}' visible={vis}")
                except:
                    pass

            # Find Continue button
            continue_btn = None
            for btn in all_buttons:
                try:
                    if btn.is_displayed():
                        btn_text = btn.text.lower()
                        if 'continue' in btn_text or 'next' in btn_text:
                            continue_btn = btn
                            print(f"Found continue button: '{btn.text}'")
                            break
                except:
                    pass

            # Also try submit type buttons
            if not continue_btn:
                try:
                    submit_btns = driver.find_elements(By.CSS_SELECTOR, "button[type='submit']")
                    for btn in submit_btns:
                        if btn.is_displayed():
                            continue_btn = btn
                            print(f"Found submit button: '{btn.text}'")
                            break
                except:
                    pass

            if continue_btn:
                print("Clicking continue button...")
                try:
                    continue_btn.click()
                except:
                    driver.execute_script("arguments[0].click();", continue_btn)
                time.sleep(5)

                print(f"After continue - URL: {driver.current_url}")

                # Now find password field
                print("Looking for password field after continue...")
                pwd_elements = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                for pwd in pwd_elements:
                    if pwd.is_displayed():
                        password_field = pwd
                        print("Found visible password field!")
                        break

                if not password_field:
                    try:
                        password_field = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type='password']")))
                        print("Found password field via wait!")
                    except:
                        print("Still no password field visible")
                        # Debug: show all inputs
                        inputs = driver.find_elements(By.TAG_NAME, "input")
                        print(f"All inputs ({len(inputs)}):")
                        for i, inp in enumerate(inputs):
                            try:
                                itype = inp.get_attribute("type")
                                iname = inp.get_attribute("name")
                                ivis = inp.is_displayed()
                                print(f"  Input {i}: type={itype}, name={iname}, visible={ivis}")
                            except:
                                pass
            else:
                print("No continue button found, trying Enter key...")
                email_field.send_keys(Keys.RETURN)
                time.sleep(4)

                pwd_elements = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                for pwd in pwd_elements:
                    if pwd.is_displayed():
                        password_field = pwd
                        break

        if not password_field:
            print("ERROR: Could not find password field!")
            driver.save_screenshot("lowes_no_password_field.png")
            print("Screenshot saved")
            input("Press Enter to close...")
            return

        # Enter password naturally
        print("Entering password...")
        time.sleep(1)
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", password_field)
        time.sleep(0.5)
        password_field.click()
        time.sleep(0.3)

        for char in PASSWORD:
            password_field.send_keys(char)
            time.sleep(0.03)  # Type like a human

        print(f"Password entered (length: {len(PASSWORD)})")
        time.sleep(1)

        # Find and click Sign In button
        print("Looking for Sign In button...")
        signin_btn = None
        all_buttons = driver.find_elements(By.TAG_NAME, "button")

        for btn in all_buttons:
            try:
                if btn.is_displayed():
                    btn_text = btn.text.lower()
                    if 'sign in' in btn_text or 'log in' in btn_text or 'login' in btn_text:
                        signin_btn = btn
                        print(f"Found sign in button: '{btn.text}'")
                        break
            except:
                pass

        # Fallback to submit button
        if not signin_btn:
            try:
                submit_btns = driver.find_elements(By.CSS_SELECTOR, "button[type='submit']")
                for btn in submit_btns:
                    if btn.is_displayed():
                        signin_btn = btn
                        print(f"Found submit button for login: '{btn.text}'")
                        break
            except:
                pass

        if signin_btn:
            print("Clicking sign in button...")
            try:
                signin_btn.click()
            except:
                driver.execute_script("arguments[0].click();", signin_btn)
        else:
            print("No sign in button found, pressing Enter...")
            password_field.send_keys(Keys.RETURN)

        time.sleep(6)

        # Check login result
        print(f"\nAfter login - URL: {driver.current_url}")
        print(f"After login - Title: {driver.title}")

        current_url = driver.current_url.lower()
        if "mylowes" in current_url or "account" in current_url or driver.current_url == "https://www.lowes.com/":
            print("\n" + "="*50)
            print("✓ LOGIN SUCCESSFUL!")
            print("="*50)

            # Test product search
            print("\nTesting product search for 'Outdoor Bleach'...")
            driver.get("https://www.lowes.com/search?searchTerm=Outdoor+Bleach")
            time.sleep(5)

            print(f"Search page title: {driver.title}")

            if "access denied" in driver.title.lower():
                print("✗ Access Denied on search page")
            else:
                print("✓ Search page loaded!")

                # Try to find product elements
                products = driver.find_elements(By.CSS_SELECTOR, "div[data-selector='splp-prd-grid-tile'], div.product-card, [class*='ProductCard']")
                print(f"Found {len(products)} product elements")

                if products:
                    print("\n✓ SCRAPING SHOULD WORK FROM THIS IP!")
                else:
                    body_text = driver.find_element(By.TAG_NAME, "body").text[:500]
                    print(f"Page content: {body_text[:300]}...")
        else:
            print("\n✗ Login may have failed")
            print(f"Current URL: {driver.current_url}")
            driver.save_screenshot("lowes_login_failed.png")
            print("Screenshot saved")

        input("\nPress Enter to close browser...")

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("lowes_error.png")
        print("Screenshot saved to lowes_error.png")
        input("\nPress Enter to close browser...")
    finally:
        driver.quit()

if __name__ == "__main__":
    test_lowes_login()
