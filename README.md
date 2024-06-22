# Defendify_v0.1
## Automated Web Vulnerability Scanner

## Overview
The Automated Web Vulnerability Scanner is a Python-based tool designed to automate the detection of security vulnerabilities in web applications. It leverages Selenium for web interaction and subprocess for running external tools like dirb for directory enumeration. This tool focuses on detecting XSS, SQL Injection (SQLi), and Local File Inclusion (LFI) / Remote File Inclusion (RFI) vulnerabilities.

## Features
- **XSS Testing**: Tests web pages for Cross-Site Scripting (XSS) vulnerabilities using predefined payloads.
- **SQL Injection (SQLi) Testing**: Checks input fields and parameters for SQL Injection vulnerabilities.
- **Local File Inclusion (LFI) / Remote File Inclusion (RFI) Testing**: Detects potential file inclusion vulnerabilities.
- **Directory Enumeration**: Utilizes dirb to discover subdirectories of the target URL.
- **Detailed Reporting**: Generates a CSV report listing detected vulnerabilities, including payload details and severity levels.
- **User Interaction**: Provides a command-line interface for users to input target URLs and select vulnerability tests.

## Requirements
- Python 3.x
- Selenium Python library (`pip install selenium`)
- Firefox web browser (geckodriver executable required)
- dirb tool for directory enumeration

## Installation
1. **Python Setup**: Ensure Python 3.x is installed on your system.
   
2. **Selenium Installation**: Install Selenium using pip:
   pip install selenium

3. **Geckodriver Setup**: Download geckodriver and ensure it's in your PATH.
- Download: [Geckodriver Releases](https://github.com/mozilla/geckodriver/releases)
- Add to PATH: [Instructions here](https://askubuntu.com/questions/870530/how-to-install-geckodriver-in-ubuntu)

4. **dirb Installation**: Install dirb for directory enumeration:
- **Linux**: 
  ```
  sudo apt-get install dirb
  ```
- **macOS**: 
  ```
  brew install dirb
  ```
- **Windows**: Download from [SourceForge](https://sourceforge.net/projects/dirb/)

## Usage
 **Run the Scanner**: Execute `python3 defendify.py` and follow the prompts.


