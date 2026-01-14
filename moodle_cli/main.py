import os
import sys
import json
import yaml
import argparse
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import unquote, urlparse

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


# --- UTILS ---

def sanitize_filename(name):
    """Clean strings to be safe for filenames."""
    cleaned = re.sub(r'[<>:"/\\|?*]', '', name)
    return cleaned.strip()[:100]


def load_cookies():
    """Load cookies from the configured file (Netscape or Key=Value format)."""
    if not os.path.exists(COOKIES_FILE):
        print(f"[!] Error: {COOKIES_FILE} not found.")
        sys.exit(1)

    cookies = {}
    with open(COOKIES_FILE, 'r') as f:
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
                cookies[k] = v

    if 'MoodleSession' not in cookies:
        print("[!] Warning: MoodleSession cookie not found.")

    return cookies


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
        """Process assignments: fetch description and attachments."""
        a_id = re.search(r'id=(\d+)', url).group(1)
        manifest_key = f"{course_id}_assign_{a_id}"
        save_path = os.path.join(save_dir, name)

        try:
            soup, _ = self.get_soup(url)
            desc_div = soup.find('div', class_='no-overflow') or soup.find('div', id='intro')
            desc_text = desc_div.get_text(separator="\n", strip=True) if desc_div else "No description."

            attachments = []
            for l in soup.find_all('a', href=True):
                if 'pluginfile.php' in l['href'] and 'assign/intro' in l['href']:
                    attachments.append((l.get_text(strip=True), l['href']))

            # Hash check for updates
            prev_data = self.manifest.get("courses", {}).get(manifest_key, {})
            current_hash = hash(desc_text + str(len(attachments)))

            if prev_data.get('hash') == current_hash and os.path.exists(save_path):
                return

            if not os.path.exists(save_path):
                os.makedirs(save_path)

            # Write Description
            with open(os.path.join(save_path, "Assignment_Details.md"), "w", encoding='utf-8') as f:
                f.write(f"# {name}\n\n{desc_text}\n")

            # Download Attachments
            for fname, flink in attachments:
                f_resp = self.session.get(flink)
                with open(os.path.join(save_path, sanitize_filename(fname)), 'wb') as f:
                    f.write(f_resp.content)

            print(f"    [UPDATE] Assignment: {name}")

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