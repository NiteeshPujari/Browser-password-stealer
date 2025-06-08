# Browser-password-stealer


## Chromium Password Extractor (Windows)

## Description

This Python script extracts and decrypts saved login credentials (URLs, usernames, passwords) from various Chromium-based browsers on a Windows system. It utilizes the Windows Data Protection API (DPAPI) to decrypt the master encryption key and then uses AES-GCM to decrypt individual passwords stored in the browser's `Login Data` SQLite database.

---

## ⚠️ WARNING: Ethical Use Only ⚠️

**This script accesses sensitive credential data.**

* **DO NOT** run this script on any system without explicit, authorized permission.
* Using this tool on unauthorized systems is unethical and illegal.
* The author assumes no liability for misuse of this script. Use it responsibly and solely for legitimate purposes, such as personal password recovery on your own machine or authorized security assessments.
* **Antivirus Software:** Due to its nature (accessing password stores), this script might be flagged as potentially harmful by antivirus software. This is often a false positive for legitimate tools of this type, but exercise caution.

---

## Features

* Retrieves saved URLs, usernames, and passwords.
* Decrypts passwords using the current Windows user's context (DPAPI).
* Supports multiple Chromium-based browsers.
* Supports specifying different browser profiles.
* Outputs data to console, CSV, or JSON format.
* Verbose mode for debugging.

## Platform

* **Operating System:** Windows only (due to `win32crypt` / DPAPI dependency).

## Prerequisites

1.  **Python:** Python 3.x installed.
2.  **Required Libraries:**
    * `pycryptodome`
    * `pywin32`

    Install them using pip:
    ```bash
    pip install pycryptodome pywin32
    ```

## Usage

Run the script from the command line. Replace `chromium_password_extractor.py` with the actual filename if you saved it differently.

```bash
python chromium_password_extractor.py [options]
```

### Command-Line Options:

* `-h`, `--help`: Show the help message and exit.
* `-b BROWSER`, `--browser BROWSER`: Target browser.
    * Choices: `chrome`, `edge`, `brave`, `vivaldi`, `opera`
    * Default: `chrome`
* `-p PROFILE`, `--profile PROFILE`: Browser profile name (case-sensitive).
    * Examples: `Default`, `Profile 1`
    * Default: `Default`
* `-o OUTPUT`, `--output OUTPUT`: Output file path.
    * If the filename ends with `.csv`, saves as CSV.
    * If the filename ends with `.json`, saves as JSON.
    * Otherwise, prints formatted results to the console.
* `-v`, `--verbose`: Enable verbose debug messages during execution.

### Examples:

1.  **Extract Chrome (Default profile) passwords and print to console:**
    ```bash
    python chromium_password_extractor.py
    ```

2.  **Extract Edge (Profile 1) passwords and save to a CSV file:**
    ```bash
    python chromium_password_extractor.py --browser edge --profile "Profile 1" --output edge_credentials.csv
    ```

3.  **Extract Brave (Default profile) passwords and save to a JSON file:**
    ```bash
    python chromium_password_extractor.py -b brave -o brave_logins.json
    ```

4.  **Extract Vivaldi (Default profile) passwords with verbose output:**
    ```bash
    python chromium_password_extractor.py -b vivaldi -v
    ```

## Supported Browsers

* Google Chrome
* Microsoft Edge (Chromium-based)
* Brave Browser
* Vivaldi
* Opera (Note: Path detection might vary slightly between Opera versions)

## Limitations

* **Windows Only:** Relies on Windows DPAPI.
* **Current User Context:** Can only decrypt passwords for the currently logged-in Windows user.
* **Browser Lock:** While the script copies the database, ensure the target browser isn't actively causing issues with accessing the *original* `Login Data` file during the copy process (closing the browser is recommended).
* **Chrome V80+:** The decryption method assumes Chrome version 80 or later (which introduced AES-GCM encryption with the key protected by DPAPI).

```
<meta name="google-site-verification" content="GK2tZFOFRFe7wnBGsY4zJ--GJGvXJPIqmqv1gE555Nc" />
