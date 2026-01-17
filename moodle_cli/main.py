import os
import sys
import json
import yaml
import argparse
import re
import requests
from bs4 import BeautifulSoup
import hashlib
from urllib.parse import unquote, urlparse
import platform
import subprocess
import io
import struct
import ctypes
import sqlite3
import binascii
from contextlib import contextmanager

# --- CONFIGURATION ---
COOKIES_FILE = ".env"
COURSES_YAML = "courses.yaml"
MANIFEST_JSON = "manifest.json"
BASE_URL = "https://moodle.iitb.ac.in"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/91.0.4472.124 Safari/537.36"
)


# --- CHROME V20 DECRYPTION (Windows Only) ---

def _is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def _request_admin_privileges():
    """Request administrator privileges and relaunch the script."""
    try:
        # Determine the correct executable and arguments
        if sys.argv[0].endswith('.exe') or 'moodle.exe' in sys.argv[0] or 'moodle' in os.path.basename(sys.argv[0]):
            # Running as installed executable (pip/pipx)
            # Find the actual moodle.exe or just use sys.argv[0]
            executable = sys.argv[0]
            if not executable.endswith('.exe'):
                executable = executable + '.exe'
            
            # Just pass the command arguments (like 'init' or 'pull')
            args = ' '.join(sys.argv[1:])
            
            # Request elevation and relaunch
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", executable, args, None, 1
            )
        else:
            # Running as Python script directly
            args = '-m moodle_cli.main ' + ' '.join(sys.argv[1:])
            
            # Request elevation and relaunch
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, args, None, 1
            )
        
        # Result > 32 means success
        if result > 32:
            return True
        else:
            print(f"[!] UAC prompt failed or cancelled (result: {result})")
            return False
    except Exception as e:
        print(f"[!] Error requesting admin privileges: {e}")
        import traceback
        traceback.print_exc()
        return False

@contextmanager
def _impersonate_lsass():
    """Impersonate lsass.exe to get SYSTEM privilege (Windows only)."""
    try:
        import windows
        import windows.security
        import windows.crypto
        import windows.generated_def as gdef
    except ImportError:
        raise ImportError("windows library required for Chrome v20 decryption")
    
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

def _parse_key_blob(blob_data: bytes) -> dict:
    """Parse Chrome key blob structure."""
    buffer = io.BytesIO(blob_data)
    parsed_data = {}
    
    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")
    
    return parsed_data

def _decrypt_with_cng(input_data):
    """Decrypt data using Windows CNG API."""
    try:
        import windows.generated_def as gdef
    except ImportError:
        raise ImportError("windows library required")
    
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"
    
    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"
    
    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)
    
    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None, None, 0,
        ctypes.byref(pcbResult), 0x40
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"
    
    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()
    
    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None, output_buffer,
        buffer_size, ctypes.byref(pcbResult), 0x40
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"
    
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)
    
    return bytes(output_buffer[:pcbResult.value])

def _byte_xor(ba1, ba2):
    """XOR two byte arrays."""
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def _derive_v20_master_key(parsed_data: dict) -> bytes:
    """Derive Chrome v20 master key from parsed blob."""
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with _impersonate_lsass():
            decrypted_aes_key = _decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = _byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
    
    return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])

def _decrypt_chrome_v20_cookie(encrypted_value, v20_master_key):
    """Decrypt a single Chrome v20 encrypted cookie."""
    from Crypto.Cipher import AES
    
    cookie_iv = encrypted_value[3:3+12]
    encrypted_cookie = encrypted_value[3+12:-16]
    cookie_tag = encrypted_value[-16:]
    cookie_cipher = AES.new(v20_master_key, AES.MODE_GCM, nonce=cookie_iv)
    decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
    return decrypted_cookie[32:].decode('utf-8')

def _extract_chrome_v20_windows(cookie_db_path):
    """Extract MoodleSession from Chrome using v20 decryption (Windows with admin rights)."""
    try:
        import windows
        import windows.crypto
        from Crypto.Cipher import AES
    except ImportError as e:
        print(f"[!] Missing required library for Chrome v20 decryption: {e}")
        print("[!] Install with: pip install pycryptodome pywin32")
        return None
    
    if not _is_admin():
        print("[!] Administrator privileges required for Chrome v20 decryption")
        return None
    
    try:
        user_profile = os.environ['USERPROFILE']
        local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
        
        if not os.path.exists(local_state_path):
            print(f"[!] Chrome Local State not found at: {local_state_path}")
            return None
        
        print(f"[*] Reading Chrome Local State from: {local_state_path}")
        
        # Use Volume Shadow Copy to access locked database
        import tempfile
        temp_cookie_db = cookie_db_path
        
        try:
            import shadowcopy
            temp_fd, temp_cookie_db = tempfile.mkstemp(suffix='.db')
            os.close(temp_fd)
            print(f"[*] Creating shadow copy to avoid database lock...")
            shadowcopy.shadow_copy(cookie_db_path, temp_cookie_db)
            print(f"[+] Shadow copy created at: {temp_cookie_db}")
        except ImportError:
            print("[*] Shadow copy not available, using direct access (Chrome must be closed)")
            temp_cookie_db = cookie_db_path
        except Exception as e:
            print(f"[!] Shadow copy failed: {e}")
            print("[*] Falling back to direct access (Chrome must be closed)")
            temp_cookie_db = cookie_db_path
        
        # Read Local State and decrypt keys
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        if "os_crypt" not in local_state or "app_bound_encrypted_key" not in local_state["os_crypt"]:
            print("[!] app_bound_encrypted_key not found in Local State")
            print("[!] This Chrome version might not use v20 encryption")
            return None
        
        app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
        decoded_key = binascii.a2b_base64(app_bound_encrypted_key)
        
        if decoded_key[:4] != b"APPB":
            print(f"[!] Unexpected key prefix: {decoded_key[:4]}")
            return None
        
        key_blob_encrypted = decoded_key[4:]
        
        print("[*] Decrypting Chrome master key (requires SYSTEM privileges)...")
        
        # Decrypt with SYSTEM DPAPI
        try:
            with _impersonate_lsass():
                key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
            print("[+] SYSTEM DPAPI decryption successful")
        except Exception as e:
            print(f"[!] SYSTEM DPAPI decryption failed: {e}")
            print("[!] Make sure you're running as Administrator")
            return None
        
        # Decrypt with user DPAPI
        try:
            key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
            print("[+] User DPAPI decryption successful")
        except Exception as e:
            print(f"[!] User DPAPI decryption failed: {e}")
            return None
        
        # Parse key blob and derive master key
        print("[*] Parsing key blob and deriving master key...")
        parsed_data = _parse_key_blob(key_blob_user_decrypted)
        v20_master_key = _derive_v20_master_key(parsed_data)
        print("[+] Master key derived successfully")
        
        # Fetch and decrypt cookies
        print(f"[*] Opening cookie database: {temp_cookie_db}")
        try:
            con = sqlite3.connect(temp_cookie_db)
            cur = con.cursor()
            cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) from cookies;")
            cookies = cur.fetchall()
            cookies_v20 = [c for c in cookies if len(c[2]) >= 3 and c[2][:3] == b"v20"]
            con.close()
            print(f"[*] Found {len(cookies_v20)} v20 encrypted cookies")
        except Exception as e:
            print(f"[!] Error reading cookie database: {e}")
            print("[!] Make sure Chrome is closed if shadow copy is not available")
            return None
        
        # Search for MoodleSession
        print("[*] Searching for MoodleSession cookie...")
        for host, name, encrypted_value in cookies_v20:
            if name.lower() == "moodlesession":
                try:
                    decrypted_value = _decrypt_chrome_v20_cookie(encrypted_value, v20_master_key)
                    print(f"[+] Found MoodleSession from {host}")
                    print(f"[+] Cookie value: {decrypted_value[:20]}...{decrypted_value[-10:]}")
                    return decrypted_value
                except Exception as e:
                    print(f"[!] Error decrypting MoodleSession from {host}: {e}")
        
        print("[!] MoodleSession cookie not found in database")
        
        # Clean up
        if temp_cookie_db != cookie_db_path:
            try:
                os.remove(temp_cookie_db)
                print("[+] Cleaned up shadow copy")
            except:
                pass
        
        return None
        
    except Exception as e:
        print(f"[!] Unexpected error extracting Chrome v20 cookies: {e}")
        import traceback
        traceback.print_exc()
        return None

# --- UTILS ---

def sanitize_filename(name):
    """Clean strings to be safe for filenames."""
    cleaned = re.sub(r'[<>:"/\\|?*]', '', name)
    return cleaned.strip()[:100]

def compute_stable_hash(*args):
    """Compute a stable SHA-256 hash from multiple string components."""
    hasher = hashlib.sha256()
    for arg in args:
        # Encode string to bytes, handle None safely
        hasher.update(str(arg).encode('utf-8'))
    return hasher.hexdigest()

def load_cookies():
    """Load cookies from the configured file (Netscape or Key=Value format)."""
    if not os.path.exists(COOKIES_FILE):
        print(f"[!] Error: {COOKIES_FILE} not found.")
        sys.exit(1)

    cookies = {}
    with open(COOKIES_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            parts = line.strip().split('\t')
            if len(parts) >= 7:
                # Netscape HTTP Cookie File format
                cookies[parts[5]] = parts[6]
            elif '=' in line:
                # Simple key=value format
                k, v = line.strip().split('=', 1)
                # Support MOODLE_SESSION key from script.py extraction
                if k == 'MOODLE_SESSION':
                    cookies['MoodleSession'] = v
                else:
                    cookies[k] = v

    if 'MoodleSession' not in cookies:
        print("[!] Warning: MoodleSession cookie not found.")

    return cookies

def validate_token():
    """Check if the current MoodleSession token is valid."""
    if not os.path.exists(COOKIES_FILE):
        return False
    
    try:
        cookies = load_cookies()
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        session.cookies.update(cookies)
        
        # Test the session by accessing the dashboard
        resp = session.get(f"{BASE_URL}/my/", allow_redirects=True)
        
        # If redirected to login page, session is invalid
        if "login/index.php" in resp.url:
            return False
        return True
    except Exception as e:
        print(f"[!] Error validating token: {e}")
        return False

def extract_cookies_from_chrome():
    """Extract MoodleSession from Chrome cookies (cross-platform)."""
    system = platform.system()
    
    if system == "Windows":
        return _extract_cookies_windows()
    elif system == "Linux":
        return _extract_cookies_linux()
    elif system == "Darwin":  # macOS
        return _extract_cookies_macos()
    else:
        print(f"[!] Automatic cookie extraction not supported on {system}")
        _show_manual_instructions()
        return False

def _extract_cookies_windows():
    """Extract cookies on Windows from Chrome, Edge, Brave, and Firefox."""
    
    # First try Firefox (simpler, doesn't need admin)
    firefox_result = _extract_from_firefox_windows()
    if firefox_result:
        return True
    
    # Define Chromium browser paths on Windows
    user_profile = os.environ.get('USERPROFILE', '')
    local_appdata = os.environ.get('LOCALAPPDATA', '')
    appdata = os.environ.get('APPDATA', '')
    
    chromium_browsers = {
        "Google Chrome": f"{local_appdata}\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
        "Microsoft Edge": f"{local_appdata}\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
        "Brave": f"{local_appdata}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies",
        "Chromium": f"{local_appdata}\\Chromium\\User Data\\Default\\Network\\Cookies",
        "Vivaldi": f"{local_appdata}\\Vivaldi\\User Data\\Default\\Network\\Cookies",
        "Opera": f"{appdata}\\Opera Software\\Opera Stable\\Network\\Cookies",
    }
    
    # Check which Chromium browsers are installed
    available_browsers = []
    for browser, path in chromium_browsers.items():
        if os.path.exists(path):
            available_browsers.append((browser, path))
            print(f"[+] Found {browser} at: {path}")
    
    if not available_browsers:
        print("[!] No Chromium-based browser cookie database found")
        _show_manual_instructions()
        return False
    
    # Check admin privileges and request if needed
    if not _is_admin():
        print("[!] Administrator privileges required for Chrome v20 cookie decryption")
        print("[*] Requesting administrator privileges...")
        print("[*] A UAC prompt will appear - please click 'Yes' to continue.")
        
        if _request_admin_privileges():
            print("\n" + "="*60)
            print("[*] Elevated process has been launched.")
            print("[*] This window will close automatically.")
            print("="*60)
            sys.exit(0)  # Exit current process, elevated process will continue
        else:
            print("[!] Failed to obtain administrator privileges.")
            print("[!] You can manually run as administrator:")
            print("    Right-click Command Prompt/PowerShell → Run as administrator")
            print(f"    Then run: {' '.join(sys.argv)}")
            _show_manual_instructions()
            return False
    
    print("\n" + "="*60)
    print("[*] Running with administrator privileges")
    print("="*60 + "\n")
    
    # Try each available Chromium browser
    extraction_errors = []
    for browser_name, cookie_path in available_browsers:
        print(f"[*] Attempting to extract MoodleSession from {browser_name}...")
        
        try:
            cookie_value = _extract_chrome_v20_windows(cookie_path)
            
            if cookie_value and len(cookie_value) > 10:
                # Save to .env file
                with open(COOKIES_FILE, "w", encoding='utf-8') as f:
                    f.write(f"MOODLE_SESSION={cookie_value}\n")
                
                print(f"[+] Cookie extracted from {browser_name}.")
                print(f"[+] Saved to {COOKIES_FILE}")
                
                # Validate the token immediately
                print("[*] Validating extracted token...")
                if validate_token():
                    print(f"[+] Token validation successful!")
                    print("\n[SUCCESS] Cookie extraction completed!")
                    return True
                else:
                    print(f"[!] Extracted cookie is invalid or expired.")
                    print("    The cookie may have expired. Please log into Moodle again.")
            else:
                print(f"[!] {browser_name}: MoodleSession cookie not found.")
                print("    Make sure you're logged into https://moodle.iitb.ac.in")
        
        except Exception as e:
            error_msg = f"Error extracting from {browser_name}: {e}"
            print(f"[!] {error_msg}")
            import traceback
            traceback.print_exc()
            extraction_errors.append(error_msg)
            continue
    
    print("\n" + "="*60)
    print("[!] Failed to extract valid cookie from any browser")
    if extraction_errors:
        print("\nErrors encountered:")
        for err in extraction_errors:
            print(f"  - {err}")
    print("="*60)
    _show_manual_instructions()
    return False

def _extract_from_firefox_windows():
    """Extract cookies from Firefox on Windows (no special permissions needed)."""
    import sqlite3
    import tempfile
    import shutil
    import glob
    
    try:
        appdata = os.environ.get('APPDATA', '')
        firefox_base = f"{appdata}\\Mozilla\\Firefox\\Profiles"
        
        if not os.path.exists(firefox_base):
            return False
        
        # Find Firefox profile with cookies
        cookie_paths = glob.glob(f"{firefox_base}\\*\\cookies.sqlite")
        
        if not cookie_paths:
            return False
        
        print(f"[+] Found Firefox cookies at: {cookie_paths[0]}")
        
        # Copy database to avoid locking issues
        temp_db = tempfile.mktemp(suffix=".sqlite")
        shutil.copy2(cookie_paths[0], temp_db)
        
        # Query cookies (Firefox has different schema)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT host, name, value FROM moz_cookies WHERE name = 'MoodleSession'"
        )
        
        moodle_cookie = None
        for host, name, value in cursor.fetchall():
            if value and len(value) > 10:
                moodle_cookie = value
                print(f"[+] Found MoodleSession from {host} (Firefox)")
                break
        
        conn.close()
        os.remove(temp_db)
        
        if moodle_cookie:
            with open(COOKIES_FILE, "w", encoding='utf-8') as f:
                f.write(f"MOODLE_SESSION={moodle_cookie}\n")
            print(f"[+] Saved MoodleSession to {COOKIES_FILE} (Firefox)")
            return True
        
        return False
        
    except Exception as e:
        # Silently fail for Firefox, try Chromium browsers instead
        return False

def _extract_cookies_linux():
    """Extract cookies on Linux from Chrome, Edge, Brave, and Firefox."""
    try:
        import sqlite3
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
    except ImportError:
        print("[!] Missing required library: pycryptodome")
        print("[!] Install with: pip install pycryptodome")
        print("[!] Or if using pipx: pipx inject moodle-cli pycryptodome")
        return False
    
    try:
        # Find browser cookie databases
        home = os.path.expanduser("~")
        
        # Define all possible browser paths (Chromium-based)
        chromium_paths = {
            "Google Chrome": [
                f"{home}/.config/google-chrome/Default/Cookies",
                f"{home}/.config/google-chrome/Profile */Cookies",
            ],
            "Chromium": [
                f"{home}/.config/chromium/Default/Cookies",
                f"{home}/snap/chromium/common/chromium/Default/Cookies",
            ],
            "Brave": [
                f"{home}/.config/BraveSoftware/Brave-Browser/Default/Cookies",
                f"{home}/.config/BraveSoftware/Brave-Browser/Profile */Cookies",
            ],
            "Microsoft Edge": [
                f"{home}/.config/microsoft-edge/Default/Cookies",
                f"{home}/.config/microsoft-edge/Profile */Cookies",
            ],
            "Vivaldi": [
                f"{home}/.config/vivaldi/Default/Cookies",
            ],
            "Opera": [
                f"{home}/.config/opera/Cookies",
            ],
        }
        
        # Firefox paths (different structure)
        firefox_paths = {
            "Firefox": [
                f"{home}/.mozilla/firefox/*/cookies.sqlite",
            ],
        }
        
        # Try Chromium-based browsers first
        cookie_db = None
        browser_name = None
        all_found_browsers = []
        
        print("[*] Searching for browser cookie databases...")
        for browser, paths in chromium_paths.items():
            for path_pattern in paths:
                import glob
                matches = glob.glob(path_pattern)
                if matches:
                    for match in matches:
                        all_found_browsers.append((browser, match))
                        print(f"[+] Found {browser} cookies at: {match}")
        
        # Try each Chromium browser until one succeeds
        for browser_name, cookie_db in all_found_browsers:
            print(f"[*] Attempting to extract from {browser_name}...")
            result = _try_extract_chromium_linux(cookie_db, browser_name)
            if result:
                return True
        
        # If no Chromium browser worked, try Firefox
        if not all_found_browsers:
            for browser, paths in firefox_paths.items():
                for path_pattern in paths:
                    import glob
                    matches = glob.glob(path_pattern)
                    if matches:
                        print(f"[+] Found {browser} cookies at: {matches[0]}")
                        return _extract_from_firefox(matches[0])
        
        if not all_found_browsers:
            print("[!] No supported browser cookie database found")
            print("[!] Searched for: Chrome, Chromium, Brave, Edge, Vivaldi, Opera, Firefox")
            _show_manual_instructions()
            return False
        
        # If we get here, all browsers failed
        print("[!] Failed to extract valid cookie from any browser")
        _show_manual_instructions()
        return False
    except Exception as e:
        print(f"[!] Error extracting cookies: {e}")
        import traceback
        traceback.print_exc()
        return False

def _try_extract_chromium_linux(cookie_db, browser_name):
    """Try to extract MoodleSession from a specific Chromium browser on Linux."""
    try:
        import sqlite3
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        import tempfile
        import shutil
        
        # Copy database to avoid locking issues
        temp_db = tempfile.mktemp(suffix=".db")
        shutil.copy2(cookie_db, temp_db)
        
        # Get encryption key (Chrome on Linux uses 'peanuts' as password)
        salt = b'saltysalt'
        iv = b' ' * 16
        length = 16
        password = 'peanuts'.encode('utf-8')
        iterations = 1
        key = PBKDF2(password, salt, length, iterations)
        
        # Query cookies
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT host_key, name, value, encrypted_value FROM cookies WHERE name = 'MoodleSession'"
        )
        
        moodle_cookie = None
        for host, name, plaintext_value, encrypted_value in cursor.fetchall():
            # First check if there's a plaintext value
            if plaintext_value:
                moodle_cookie = plaintext_value
                print(f"[+] Found plaintext MoodleSession from {host}")
                break
            
            try:
                if encrypted_value[:3] == b'v10':
                    # Decrypt v10 cookie
                    encrypted_value = encrypted_value[3:]
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(encrypted_value)
                    # Remove PKCS7 padding
                    padding_length = decrypted[-1]
                    if padding_length < 1 or padding_length > 16:
                        print(f"[!] Invalid padding length: {padding_length}")
                        continue
                    decrypted = decrypted[:-padding_length]
                    
                    # Decode to string - MoodleSession should be ASCII
                    try:
                        # Try strict UTF-8 first
                        cookie_str = decrypted.decode('utf-8')
                    except UnicodeDecodeError:
                        # Fallback to latin-1 which never fails
                        cookie_str = decrypted.decode('latin-1')
                    
                    # MoodleSession is 26 alphanumeric characters
                    # Extract only the valid alphanumeric portion (filter out binary garbage)
                    import string
                    # Find continuous alphanumeric string of reasonable length
                    alphanumeric_parts = re.findall(r'[a-zA-Z0-9]{20,}', cookie_str)
                    
                    if alphanumeric_parts:
                        moodle_cookie = alphanumeric_parts[0]  # Take the first valid match
                        print(f"[+] Found MoodleSession from {host} ({browser_name})")
                        print(f"[+] Cookie value: {moodle_cookie}")
                        break
                    else:
                        print(f"[!] Could not extract valid alphanumeric cookie from: {repr(cookie_str[:50])}")
                        continue
                elif encrypted_value[:3] == b'v11':
                    # Try v11 format (might be used in newer Chrome)
                    print("[!] v11 encryption detected, trying alternative method...")
                    continue
                else:
                    print(f"[!] Unknown encryption format: {encrypted_value[:3]}")
                    continue
            except Exception as e:
                print(f"[!] Error decrypting cookie from {host}: {e}")
                continue
        
        conn.close()
        os.remove(temp_db)
        
        if moodle_cookie:
            # Save to .env file (no additional filtering needed)
            with open(COOKIES_FILE, "w", encoding='utf-8') as f:
                f.write(f"MOODLE_SESSION={moodle_cookie}\n")
            print(f"[+] Saved MoodleSession to {COOKIES_FILE} ({browser_name})")
            print(f"[+] Cookie length: {len(moodle_cookie)} characters")
            
            # Verify saved file is readable
            with open(COOKIES_FILE, "r", encoding='utf-8') as f:
                saved_content = f.read().strip()
                if "MOODLE_SESSION=" in saved_content:
                    saved_cookie = saved_content.split("=", 1)[1]
                    print(f"[+] Verification: Saved cookie matches: {saved_cookie == moodle_cookie}")
            return True
        else:
            print(f"[!] MoodleSession cookie not found in {browser_name}")
            return False
    except Exception as e:
        print(f"[!] Error extracting from {browser_name}: {e}")
        return False
    except Exception as e:
        print(f"[!] Error extracting cookies: {e}")
        import traceback
        traceback.print_exc()
        return False

def _extract_from_firefox(cookie_db):
    """Extract cookies from Firefox (simpler - often stores cookies unencrypted)."""
    import sqlite3
    import tempfile
    import shutil
    
    try:
        # Copy database to avoid locking issues
        temp_db = tempfile.mktemp(suffix=".sqlite")
        shutil.copy2(cookie_db, temp_db)
        
        # Query cookies (Firefox has different schema)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Firefox cookie schema: host, name, value
        cursor.execute(
            "SELECT host, name, value FROM moz_cookies WHERE name = 'MoodleSession'"
        )
        
        moodle_cookie = None
        for host, name, value in cursor.fetchall():
            if value and len(value) > 10:
                moodle_cookie = value
                print(f"[+] Found MoodleSession from {host} (Firefox)")
                print(f"[+] Cookie value: {moodle_cookie[:20]}...{moodle_cookie[-10:]}")
                break
        
        conn.close()
        os.remove(temp_db)
        
        if moodle_cookie:
            # Save to .env file
            with open(COOKIES_FILE, "w", encoding='utf-8') as f:
                f.write(f"MOODLE_SESSION={moodle_cookie}\n")
            print(f"[+] Saved MoodleSession to {COOKIES_FILE} (Firefox)")
            print(f"[+] Cookie length: {len(moodle_cookie)} characters")
            return True
        else:
            print("[!] MoodleSession cookie not found in Firefox")
            print("[!] Make sure you're logged into Moodle in Firefox")
            return False
            
    except Exception as e:
        print(f"[!] Error extracting Firefox cookies: {e}")
        import traceback
        traceback.print_exc()
        return False

def _extract_cookies_macos():
    """Extract cookies on macOS from Chrome, Edge, Brave, and Firefox."""
    try:
        import sqlite3
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        import keyring
    except ImportError as e:
        print(f"[!] Missing required library: {e}")
        print("[!] Install with: pip install pycryptodome keyring")
        print("[!] Or if using pipx: pipx inject moodle-cli pycryptodome keyring")
        return False
    
    try:
        # Find browser cookie databases
        home = os.path.expanduser("~")
        
        # Define all possible browser paths
        chromium_paths = {
            "Google Chrome": f"{home}/Library/Application Support/Google/Chrome/Default/Cookies",
            "Brave": f"{home}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
            "Microsoft Edge": f"{home}/Library/Application Support/Microsoft Edge/Default/Cookies",
            "Chromium": f"{home}/Library/Application Support/Chromium/Default/Cookies",
        }
        
        # Try to find any available browser
        cookie_db = None
        browser_name = None
        
        print("[*] Searching for browser cookie databases...")
        for browser, path in chromium_paths.items():
            if os.path.exists(path):
                cookie_db = path
                browser_name = browser
                print(f"[+] Found {browser} cookies at: {cookie_db}")
                break
        
        if not cookie_db:
            print("[!] No supported browser cookie database found")
            print("[!] Searched for: Chrome, Brave, Edge, Chromium")
            _show_manual_instructions()
            return False
        
        # Copy database to avoid locking issues
        import tempfile
        import shutil
        temp_db = tempfile.mktemp(suffix=".db")
        shutil.copy2(cookie_db, temp_db)
        
        # Get encryption key from macOS Keychain
        try:
            safe_storage_key = keyring.get_password("Chrome Safe Storage", "Chrome")
            if not safe_storage_key:
                raise Exception("Chrome Safe Storage key not found")
            safe_storage_key = safe_storage_key.encode('utf-8')
        except:
            print("[!] Could not retrieve Chrome Safe Storage key from Keychain")
            _show_manual_instructions()
            return False
        
        # Derive key
        salt = b'saltysalt'
        iv = b' ' * 16
        length = 16
        iterations = 1003
        key = PBKDF2(safe_storage_key, salt, length, iterations)
        
        # Query cookies
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT host_key, name, encrypted_value FROM cookies WHERE name = 'MoodleSession'"
        )
        
        moodle_cookie = None
        for host, name, encrypted_value in cursor.fetchall():
            if encrypted_value[:3] == b'v10':
                encrypted_value = encrypted_value[3:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted_value)
                decrypted = decrypted[:-decrypted[-1]].decode('utf-8')
                moodle_cookie = decrypted
                print(f"[+] Found MoodleSession from {host} ({browser_name})")
                break
        
        conn.close()
        os.remove(temp_db)
        
        if moodle_cookie:
            with open(COOKIES_FILE, "w", encoding='utf-8') as f:
                f.write(f"MOODLE_SESSION={moodle_cookie}\n")
            print(f"[+] Saved MoodleSession to {COOKIES_FILE} ({browser_name})")
            return True
        else:
            print(f"[!] MoodleSession cookie not found in {browser_name}")
            return False
            
    except Exception as e:
        print(f"[!] Error extracting cookies: {e}")
        return False

def _show_manual_instructions():
    """Show manual cookie extraction instructions."""
    print("\n[!] MANUAL EXTRACTION INSTRUCTIONS:")
    print("    1. Open your browser (Chrome, Firefox, Brave, Edge, etc.) and log into Moodle")
    print("    2. Press F12 to open Developer Tools")
    print("    3. Go to Application/Storage → Cookies → moodle.iitb.ac.in")
    print("    4. Find 'MoodleSession' and copy its value")
    print("    5. Create/update .env file with: MOODLE_SESSION=your_cookie_value")


# --- CORE CLASS ---

class MoodleClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.cookies.update(load_cookies())
        self.manifest = self._load_manifest()

    def _load_manifest(self):
        """Load the download history manifest."""
        if os.path.exists(MANIFEST_JSON):
            with open(MANIFEST_JSON, 'r') as f:
                return json.load(f)
        return {"courses": {}}

    def save_manifest(self):
        """Save current state to the manifest file."""
        with open(MANIFEST_JSON, 'w') as f:
            json.dump(self.manifest, f, indent=2)

    def get_soup(self, url):
        """Fetch a URL and return parsed HTML."""
        resp = self.session.get(url, allow_redirects=True)
        if "login/index.php" in resp.url:
            print("[!] Session Expired. Please update cookies.txt")
            sys.exit(1)
        return BeautifulSoup(resp.text, 'html.parser'), resp

    def get_sesskey(self):
        """Extract the session key from the dashboard."""
        soup, _ = self.get_soup(f"{BASE_URL}/my/")
        logout_link = soup.find('a', href=re.compile(r'sesskey='))
        if logout_link:
            match = re.search(r'sesskey=([\w]+)', logout_link['href'])
            if match:
                return match.group(1)
        return None

    # --- ACTION: INIT ---
    def init_courses(self):
        """Discover courses via API or scraping and save to YAML."""
        # Validate token before proceeding
        if not validate_token():
            print("[!] MoodleSession token is invalid or expired.")
            print("[*] Attempting to extract fresh cookies from Chrome...")
            if extract_cookies_from_chrome():
                print("[+] Token extracted successfully. Reinitializing client...")
                self.session.cookies.update(load_cookies())
            else:
                print("[!] Failed to extract valid token. Please update your .env file manually.")
                sys.exit(1)
        
        print("[*] discovering courses...")
        sesskey = self.get_sesskey()
        courses = []

        # Strategy 1: Try API
        if sesskey:
            api_url = f"{BASE_URL}/lib/ajax/service.php?sesskey={sesskey}&info=core_course_get_enrolled_courses_by_timeline_classification"
            payload = [{
                "index": 0,
                "methodname": "core_course_get_enrolled_courses_by_timeline_classification",
                "args": {
                    "offset": 0,
                    "limit": 0,
                    "classification": "inprogress",
                    "sort": "fullname"
                }
            }]
            try:
                resp = self.session.post(api_url, json=payload)
                data = resp.json()
                if not data[0].get('error'):
                    for c in data[0]['data']['courses']:
                        status = 'enabled' if c.get('classification') == 'inprogress' else 'disabled'
                        courses.append({
                            'name': c['fullname'],
                            'id': c['id'],
                            'status': status,
                            'local_folder': sanitize_filename(c['fullname'])
                        })
            except Exception as e:
                print(f"[!] API discovery failed: {e}")

        # Strategy 2: Fallback to Scraping
        if not courses:
            soup, _ = self.get_soup(f"{BASE_URL}/my/courses.php")
            for link in soup.find_all('a', href=re.compile(r'course/view.php\?id=')):
                c_id = re.search(r'id=(\d+)', link['href']).group(1)
                name = link.get_text(strip=True)
                # Avoid duplicates
                if name and c_id not in [str(c['id']) for c in courses]:
                    courses.append({
                        'name': name,
                        'id': int(c_id),
                        'status': 'enabled',
                        'local_folder': sanitize_filename(name)
                    })

        # Save Result
        if os.path.exists(COURSES_YAML):
            print("[!] courses.yaml already exists. Skipping overwrite.")
        else:
            with open(COURSES_YAML, 'w') as f:
                yaml.dump(courses, f, sort_keys=False)
            print(f"[+] Created {COURSES_YAML}")

    # --- ACTION: PULL ---
    def pull_all(self):
        """Download content for all enabled courses."""
        # Validate token before proceeding
        if not validate_token():
            print("[!] MoodleSession token is invalid or expired.")
            print("[*] Attempting to extract fresh cookies from Chrome...")
            if extract_cookies_from_chrome():
                print("[+] Token extracted successfully. Reinitializing client...")
                self.session.cookies.update(load_cookies())
            else:
                print("[!] Failed to extract valid token. Please update your .env file manually.")
                sys.exit(1)
        
        if not os.path.exists(COURSES_YAML):
            print("[!] courses.yaml not found.")
            return

        with open(COURSES_YAML, 'r') as f:
            course_list = yaml.safe_load(f)

        for course in course_list:
            if course.get('status') == 'enabled':
                print(f"\n=== Syncing: {course['name']} ===")
                self.sync_course(course)

    def sync_course(self, course_cfg):
        """Sync a single course's resources, assignments, and forums."""
        c_id = str(course_cfg['id'])
        base_path = course_cfg['local_folder']

        # Define Category Folders
        resource_dir = os.path.join(base_path, "Resources")
        assign_dir = os.path.join(base_path, "Assignments")
        # Note: Announcements dir is handled inside process_forum

        for path in [base_path, resource_dir, assign_dir]:
            if not os.path.exists(path):
                os.makedirs(path)

        soup, _ = self.get_soup(f"{BASE_URL}/course/view.php?id={c_id}")

        sections = soup.find_all(['li', 'div'], class_='section')
        if not sections:
            sections = [soup]

        for sec in sections:
            activities = sec.find_all('div', class_='activity-instance')

            for act in activities:
                link = act.find('a')
                if not link:
                    continue

                href = link['href']
                text = sanitize_filename(link.get_text(strip=True))

                # Routing Logic
                if 'resource/view.php' in href:
                    self.process_resource(c_id, href, text, resource_dir)
                elif 'assign/view.php' in href:
                    self.process_assignment(c_id, href, text, assign_dir)
                elif 'forum/view.php' in href:
                    self.process_forum(c_id, href, text, base_path)

    def process_resource(self, course_id, url, name, save_dir):
        """Download course files (PDFs, etc)."""
        r_id = re.search(r'id=(\d+)', url).group(1)
        manifest_key = f"{course_id}_res_{r_id}"

        try:
            head = self.session.head(url, allow_redirects=True)
            remote_size = int(head.headers.get('Content-Length', 0))
            remote_time = head.headers.get('Last-Modified', '')

            # Check if up to date
            prev_data = self.manifest.get("courses", {}).get(manifest_key, {})
            is_downloaded = os.path.exists(os.path.join(save_dir, prev_data.get('filename', '')))
            if prev_data.get('size') == remote_size and prev_data.get('time') == remote_time and is_downloaded:
                return

            # Determine filename
            cd = head.headers.get('Content-Disposition')
            filename = name + ".pdf"
            if cd:
                fname_match = re.findall('filename="?([^"]+)"?', cd)
                if fname_match:
                    filename = fname_match[0]

            print(f"    [DOWNLOAD] Resource: {filename}")

            resp = self.session.get(url)
            with open(os.path.join(save_dir, filename), 'wb') as f:
                f.write(resp.content)

            # Update Manifest
            if "courses" not in self.manifest:
                self.manifest["courses"] = {}
            self.manifest["courses"][manifest_key] = {
                "size": remote_size,
                "time": remote_time,
                "filename": filename
            }
            self.save_manifest()

        except Exception as e:
            print(f"    [!] Error downloading resource {name}: {e}")

    def process_assignment(self, course_id, url, name, save_dir):
        """Process assignments with strict fingerprinting and status detection."""
        a_id = re.search(r'id=(\d+)', url).group(1)
        manifest_key = f"{course_id}_assign_{a_id}"
        save_path = os.path.join(save_dir, name)

        try:
            soup, _ = self.get_soup(url)
            
            # 1. SCRAPE INSTRUCTIONS (Description)
            desc_div = soup.find('div', class_='no-overflow') or soup.find('div', id='intro')
            desc_text = desc_div.get_text(separator="\n", strip=True) if desc_div else "No description."

            # 2. SCRAPE ATTACHMENTS (Teacher Files)
            attachments = []
            intro_section = soup.find('div', id='intro')
            if intro_section:
                for l in intro_section.find_all('a', href=True):
                    if 'pluginfile.php' in l['href']:
                        attachments.append((l.get_text(strip=True), l['href']))
            
            # 3. SCRAPE METADATA (Submission Status, Grading Status, Due Date, Grade)
            # We iterate through ALL 'generaltable' instances (Submission status AND Feedback)
            meta_info = {}
            tables = soup.find_all('table', class_='generaltable')
            
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    header = row.find(['th'])
                    data = row.find(['td'])
                    if header and data:
                        key = header.get_text(strip=True).replace(':', '')
                        
                        # --- CLEANUP: Remove "Garbage" from Comment Cell ---
                        # 1. Remove the hidden template (causes ___picture___)
                        template = data.find('div', id='cmt-tmpl')
                        if template:
                            template.decompose()
                        
                        # 2. Remove the "Show comments" / "Add comment" UI buttons
                        for garbage in data.find_all('div', class_=['comment-ctrl', 'mdl-left']):
                            garbage.decompose()
                        
                        # 3. Get text after cleanup
                        val = data.get_text(separator=" ", strip=True)
                        
                        # 4. If empty after cleanup, make it explicit
                        if not val and "comments" in key.lower():
                            val = "0 comments"

                        if key and val:
                            meta_info[key] = val

            # 4. COMPUTE STABLE FINGERPRINT (SHA-256)
            # Fingerprint = Instructions + File List + All Metadata (Grades/Dates)
            sorted_files = sorted(attachments)
            sorted_meta = json.dumps(meta_info, sort_keys=True)
            
            current_hash = compute_stable_hash(desc_text, str(sorted_files), sorted_meta)

            # 5. STATUS CHECK
            prev_data = self.manifest.get("courses", {}).get(manifest_key, {})
            is_tracked = manifest_key in self.manifest.get("courses", {})
            local_exists = os.path.exists(save_path)
            
            # If nothing changed and folder exists, skip
            if is_tracked and prev_data.get('hash') == current_hash and local_exists:
                return

            # Determine the status label
            if not is_tracked:
                status_label = "[NEW]"
            elif prev_data.get('hash') != current_hash:
                status_label = "[UPDATE]"
            else:
                status_label = "[RESTORE]" # Hash matched, but folder was missing

            # 6. DOWNLOAD & SAVE
            if not local_exists:
                os.makedirs(save_path)

            # Write Assignment Details Markdown
            with open(os.path.join(save_path, "Assignment_Details.md"), "w", encoding='utf-8') as f:
                f.write(f"# {name}\n\n")
                
                # Write Metadata/Status (Grades/Deadlines) at the top
                if meta_info:
                    f.write("## Status & Feedback\n")
                    f.write("| Item | Value |\n|---|---|\n")
                    for k, v in meta_info.items():
                        f.write(f"| **{k}** | {v} |\n")
                    f.write("\n---\n\n")
                
                f.write("## Instructions\n\n")
                f.write(desc_text)

            # Download Attachments
            for fname, flink in attachments:
                f_resp = self.session.get(flink)
                with open(os.path.join(save_path, sanitize_filename(fname)), 'wb') as f:
                    f.write(f_resp.content)

            print(f"    {status_label} Assignment: {name}")

            # Update Manifest
            if "courses" not in self.manifest:
                self.manifest["courses"] = {}
            self.manifest["courses"][manifest_key] = {"hash": current_hash}
            self.save_manifest()

        except Exception as e:
            print(f"    [!] Error processing assignment {name}: {e}")

    def process_forum(self, course_id, url, name, save_dir):
        """Process forums/announcements."""
        if "Announcements" in name or "News" in name:
            forum_path = os.path.join(save_dir, "Announcements")
        else:
            forum_path = os.path.join(save_dir, "Forums", sanitize_filename(name))

        if not os.path.exists(forum_path):
            os.makedirs(forum_path)

        f_id = re.search(r'id=(\d+)', url).group(1)
        manifest_key = f"{course_id}_forum_{f_id}"

        print(f"    [*] Scanning Forum: {name}...")

        try:
            soup, _ = self.get_soup(url)

            # 1. Link Finding (RemUI Optimized)
            links = soup.find_all('a', class_='discussion-name')
            if not links:
                links = []
                for d in soup.find_all('tr', class_='discussion'):
                    l = d.find('a', href=re.compile(r'discuss\.php\?d='))
                    if l:
                        links.append(l)
            if not links:
                links = soup.find_all('a', href=re.compile(r'discuss\.php\?d='))

            # 2. Process Threads
            prev_threads = self.manifest.get("courses", {}).get(manifest_key, {}).get("threads", [])
            current_threads = []
            new_threads_found = False
            processed_ids = set()

            for link in links:
                if 'discuss.php' not in link['href']:
                    continue
                href = link['href'].split('#')[0]
                d_id = re.search(r'd=(\d+)', href).group(1)

                if d_id in processed_ids:
                    continue
                processed_ids.add(d_id)
                current_threads.append(d_id)

                if d_id in prev_threads:
                    continue

                title = link.get_text(strip=True) or f"Thread_{d_id}"
                safe_title = sanitize_filename(title)
                print(f"        [NEW] Thread: {safe_title}")

                d_resp = self.session.get(href)
                d_soup = BeautifulSoup(d_resp.text, 'html.parser')

                # 3. Content Extraction (RemUI Optimized)
                content_div = d_soup.find('div', class_='post-content-container')
                if not content_div:
                    content_div = d_soup.find('div', id=re.compile(r'post-content-\d+'))
                if not content_div:
                    content_div = d_soup.find('div', class_='fullmessage')

                if content_div:
                    for br in content_div.find_all("br"):
                        br.replace_with("\n")
                    content = content_div.get_text(separator="\n", strip=True)
                else:
                    content = f"[!] Content extraction failed.\nURL: {href}"

                author = "Unknown"
                author_link = d_soup.find('a', href=re.compile(r'user/view\.php|user/profile\.php'))
                if author_link:
                    author = author_link.get_text(strip=True)

                with open(os.path.join(forum_path, f"{safe_title}.md"), "w", encoding='utf-8') as f:
                    f.write(f"# {title}\n\n**Author:** {author}\n**Source:** {href}\n---\n\n{content}")

                new_threads_found = True

            if new_threads_found or (set(current_threads) != set(prev_threads)):
                if "courses" not in self.manifest:
                    self.manifest["courses"] = {}
                self.manifest["courses"][manifest_key] = {"threads": list(set(prev_threads + current_threads))}
                self.save_manifest()

        except Exception as e:
            print(f"    [!] Error processing forum {name}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Moodle Course Syncer")
    parser.add_argument('command', choices=['init', 'pull'], help="init: Setup courses.yaml, pull: Download files")
    args = parser.parse_args()

    # Calculate paths relative to the current working directory where the user runs the command
    current_dir = os.getcwd()

    # Update global config variables to absolute paths based on where the user IS
    global COOKIES_FILE, COURSES_YAML, MANIFEST_JSON
    COOKIES_FILE = os.path.join(current_dir, ".env")
    COURSES_YAML = os.path.join(current_dir, "courses.yaml")
    MANIFEST_JSON = os.path.join(current_dir, "manifest.json")

    client = MoodleClient()
    if args.command == 'init':
        client.init_courses()
    elif args.command == 'pull':
        client.pull_all()


if __name__ == "__main__":
    main()