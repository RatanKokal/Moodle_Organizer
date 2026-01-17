# Moodle CLI

A command-line tool to download course materials from Moodle (IIT Bombay).

## Features

- Download all course materials automatically
- **Automatic cookie extraction** from your browser (Chrome, Firefox, Brave, Edge, etc.)
- Track downloaded files to avoid re-downloading
- Support for multiple file types (PDFs, videos, documents, etc.)
- Resume interrupted downloads
- Organize files by course and section
- **Cross-platform support**: Windows, Linux, and macOS
- **Multi-browser support**: Chrome, Edge, Brave, Firefox, Opera, Vivaldi, Chromium

## Prerequisites

- Python 3.7 or higher
- pipx (recommended for installation)
- A supported browser with an active Moodle session

## Dependencies

This project requires the following Python packages (automatically installed via pipx):

- `requests` - HTTP library for API calls
- `beautifulsoup4` - HTML parsing
- `pyyaml` - YAML configuration file handling
- `tqdm` - Progress bars for downloads
- `pycryptodome` - Cookie decryption for automatic extraction

These are listed in `requirements.txt` and will be installed automatically when you install the CLI tool.

## Installation

### Step 1: Install pipx

**On Linux/macOS:**
```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

**On Windows:**
```bash
python -m pip install --user pipx
python -m pipx ensurepath
```

After installation, **close and reopen your terminal** for the PATH changes to take effect.

To verify pipx is installed correctly:
```bash
pipx --version
```

### Step 2: Install Moodle CLI

Navigate to the project directory and install:
```bash
cd /path/to/moodle
pipx install . --force
```

This will automatically install all dependencies from `requirements.txt`. The `--force` flag ensures a clean installation if you're reinstalling.

**Alternative: Install with pip (not recommended)**
```bash
pip install -r requirements.txt
pip install -e .
```
Note: Using pipx is recommended as it creates an isolated environment.

### Step 3: Verify Installation

```bash
moodle --help
```

You should see the help menu with available commands.

## Configuration

### Authentication

The tool requires authentication with Moodle. You have **two options**:

#### Option 1: Automatic Cookie Extraction (

1. **Open Moodle** in your browser and log in: https://moodle.iitb.ac.in
2. **Open Developer Tools:**
   - Chrome/Edge/Brave: Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac)
   - Firefox: Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac)
   - Safari: Enable Developer menu in Preferences, then press `Cmd+Option+I`

3. **Go to the Application/Storage tab:**
   - Chrome/Edge/Brave: Click on "Application" tab → "Cookies" → "https://moodle.iitb.ac.in"
   - Firefox: Click on "Storage" tab → "Cookies" → "https://moodle.iitb.ac.in"
   - Safari: Click on "Storage" tab → "Cookies" → "moodle.iitb.ac.in"

4. **Find the MoodleSession cookie:**
   - Look for a cookie named `MoodleSession`
   - Copy its **Value** (typically a 26-character alphanumeric string
   - Validate and use it

**Requirements:**
- **Linux/macOS**: No special permissions needed for most browsers
- **Windows**: Administrator privileges required for Chromium browsers (Chrome, Edge, Brave), but not for Firefox

If extraction fails, the tool will automatically try other browsers and provide manual instructions as a fallback.

#### Option 2: Manual Cookie Extraction

If automatic extraction doesn't work, you can manually extract the cookie:

### Step 1: Get Your Moodle Cookie (Manual Method)

To authenticate with Moodle, you need to extract your session cookie:

#### Method 1: Using Browser Developer Tools (Recommended)

1. **Open Moodle** in your browser and log in: https://moodle.iitb.ac.in
2. **Open Developer Tools:**
   - Chrome/Edge: Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac)
   - Firefox: Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac)
   - Safari: Enable Developer menu in Preferences, then press `Cmd+Option+I`

3. **Go to the Application/Storage tab:**
   - Chrome/Edge: Click on "Application" tab → "Cookies" → "https://moodle.iitb.ac.in"
   - Firefox: Click on "Storage" tab → "Cookies" → "https://moodle.iitb.ac.in"
   - Safari: Click on "Storage" tab → "Cookies" → "moodle.iitb.ac.in"

4. **Find the MoodleSession cookie:**
   - Look for a cookie named `MoodleSession`
   - Copy its **Value** (a long string of random characters)

#### Method 2: Export Cookies (Alternative)

1. Install a browser extension to export cookies:
   - Chrome: "Get cookies.txt LOCALLY" or "EditThisCookie"
   - Firefox: "cookies.txt"
   
2. Export cookies for `moodle.iitb.ac.in` in Netscape format
3. Save the exported file as `.env` in the project directory

### Step 2: Create .env File (Manual Method Only)

**Note:** If you're using automatic extraction, skip this step - the `.env` file is created automatically.

For manual configuration, create a file named `.env` in your working directory:

**Recommended format:**
```
MOODLE_SESSION=your_session_cookie_value_here
```

**Alternative format (Netscape cookies):**
```
# Netscape HTTP Cookie File
.moodle.iitb.ac.in	TRUE	/	TRUE	1234567890	MoodleSession	your_session_cookie_value_here
```

Replace `your_session_cookie_value_here` with the actual cookie value you copied (should be alphanumeric, about 26 characters).
is created automatically if you use automatic cookie extraction
- The file must be in the directory where you run the `moodle` command
- Keep this file secure and don't share it (it contains your authentication token)
- The session expires periodically; the tool will automatically re-extract when needed
- Add `.env` to your `.gitignore` if using version control

### Step 3: Initialize Courses

Run the init command to discover and configure your courses:

```bash
moodle init
```

**What happens:**
- The tool checks if your cookie is valid
- If invalid or missing, it automatically extracts a fresh cookie from your browser
- Connects to Moodle using your cookie
- Discovers all enrolled courses
- Createst to Moodle using your cookie
- Discover all enrolled courses
- Create a `courses.yaml` file with your courses

### Step 4: Configure courses.yaml (Optional)

Edit `courses.yaml` to customize which courses to download:

```yaml
- name: Course Name
  id: 1234
  status: enabled        # Change to 'disabled' to skip this course
  local_folder: Course Name
```

- Set `status: enabled` for courses you want to download
- Set `status: disabled` for courses you want to skip
- Customize `local_folder` to change the download directory name

## Usage

### Download Course Materials

Download all enabled courses:
```bash
**What happens:**
- The tool validates your session cookie
- If expired, automatically extracts a fresh cookie from your browser
- Downloads all files from enabled courses
- Skips files that have already been downloaded
- Organizes files by course and section
- Shows progress for each downloadourses
- Skip files that have already been downloaded
- Organize files by course and section
- Show progress with a progress bar

### Reinitialize Courses

If you need to refresh your course list:
```bash
moodle init
```

### Update Installation

To update to the latest version:
```bash
cd /path/to/moodle
git pull  # if using git
pipx install . --force
```

## File Structure

After running the tool, your directory structure will look like:

```
your-working-directory/
├── .env                    # Your Moodle session cookie (keep secure!)
├── courses.yaml            # Course configuration
├── manifest.json           # Tracks downloaded files
└── Course Name/            # Downloaded course materials
    ├── Section 1/
    │   ├── lecture1.pdf
    │   └── notes.pdf
    └── Section 2/
        └── assignment.pdf
```

## Troubleshooting

### "Session Expired" ErrorThe tool should automatically re-extract it from your browser. If automatic extraction fails:

**Solution 1:** Make sure you're logged into Moodle in one of the supported browsers, then run the command again.

**Solution 2:** Manually extract a new cookie (see Configuration section) and update your `.env` file.

### "MoodleSession cookie not found"

The tool couldn't find a valid cookie in any browser.

**Solutions:**
1. Make sure you're logged into https://moodle.iitb.ac.in in your browser
2. Try a different browser from the supported list
3. Close and reopen your browser, then log in again
4. Use manual cookie extraction (see Configuration section)

### "Failed to extract valid token from any browser"

The tool found browsers but couldn't extract a valid cookie.

**Common causes:**
- Not logged into Moodle in any browser
- Browser encryption  on Windows

On Windows, automatic extraction from Chromium browsers (Chrome, Edge, Brave) requires administrator privileges.

**Solutions:**
1. Run Command Prompt/PowerShell as Administrator, then run `moodle pull`
2. Use Firefox instead (doesn't require admin privileges)
3. Use manual cookie extraction method

### Permission Errors on Linux/macOS

Ensure the installation directory has proper permissions:
```bash
chmod +x ~/.local/bin/moodle
```

If browser database access fails:
- Close the browser completely
- Some snap-installed browsers may have restricted access
- Try Firefox or manually extract the cookie

### Missing pycryptodome Library

If you see `ModuleNotFoundError: No module named 'Crypto'`:

```bash
pipx install --force .
# or
pipx inject moodle-cli pycryptodombrowser: https://moodle.iitb.ac.in
2. Close your browser completely and try again
3. Try a different browser (Firefox is often easiest on Linux)
4. Use manual extraction method
- Contains the `MoodleSession` cookie
- Has the correct format (see Configuration se (auto-generated or manual)
- `courses.yaml` - Course configuration (generated by `moodle init`)
- `manifest.json` - Tracks downloaded files (auto-generated)

## How Automatic Cookie Extraction Works

### Linux/macOS (Chromium browsers)
- Uses v10 AES-CBC encryption with PBKDF2
- Key derived from password "peanuts" (Chrome's default)
- The tool validates and refreshes cookies automatically
- Cookies are extracted locally and never sent to third parties
- The cookie typically expires after a period of inactivity
- On Windows, administrator privileges are used only for local decryption

### Windows (Chromium browsers)
- Uses v20 app-bound encryption with DPAPI
- Requires SYSTEM privileges for decryption
- Needs administrator rights
- Uses Windows Cryptography APIs

### Firefox (All platforms)
- Cookies often stored unencrypted
- Simple SQLite database access
- No special permissions needed
- Works as fallback option

### Fallback Chain
1. Try all Chromium browsers (Chrome, Edge, Brave, etc.)
2. Try Firefox if Chromium extraction fails
3. Show manual extraction instructions if all fail

If `moodle` command is not found after installation:
1. Run `pipx ensurepath` again
2. Close and reopen your terminal
3. Check if pipx bin directory is in PATH:
   ```bash
   echo $PATH  # Linux/macOS
   echo %PATH% # Windows
   ```

### Permission Errors

On Linux/macOS, ensure the installation directory has proper permissions:
```bash
chmod +x ~/.local/bin/moodle
```

## Environment Variables

The tool looks for these files in the current working directory:

- `.env` - Contains your Moodle session cookie
- `courses.yaml` - Course configuration (generated by `moodle init`)
- `manifest.json` - Tracks downloaded files (auto-generated)

## Security Notes

- **Never commit your `.env` file to version control**
- Add `.env` to your `.gitignore` file
- The session cookie grants access to your Moodle account
- Regenerate your cookie if you suspect it has been compromised
- The cookie typically expires after a period of inactivity

## License

This tool is for educational purposes. Use responsibly and in accordance with your institution's policies.

## Support

For issues or questions:
1. Check the Troubleshooting section above
2. Ensure you're using the latest version
3. Verify your `.env` file is configured correctly
