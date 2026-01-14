# Moodle CLI

A command-line tool to download course materials from Moodle (IIT Bombay).

## Features

- Download all course materials automatically
- Track downloaded files to avoid re-downloading
- Support for multiple file types (PDFs, videos, documents, etc.)
- Resume interrupted downloads
- Organize files by course and section

## Prerequisites

- Python 3.7 or higher
- pipx (recommended for installation)

## Dependencies

This project requires the following Python packages (automatically installed via pipx):

- `requests` - HTTP library for API calls
- `beautifulsoup4` - HTML parsing
- `pyyaml` - YAML configuration file handling
- `tqdm` - Progress bars for downloads

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

### Step 1: Get Your Moodle Cookie

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

### Step 2: Create .env File

Create a file named `.env` in your working directory (the directory where you run the `moodle` command):

**Option A: Simple format (easiest)**
```
MoodleSession=your_session_cookie_value_here
```

**Option B: Netscape cookie format**
```
# Netscape HTTP Cookie File
.moodle.iitb.ac.in	TRUE	/	TRUE	1234567890	MoodleSession	your_session_cookie_value_here
```

Replace `your_session_cookie_value_here` with the actual cookie value you copied.

**Important Notes:**
- The `.env` file must be in the directory where you run the `moodle` command
- Keep this file secure and don't share it (it contains your authentication token)
- The session expires periodically; you'll need to update the cookie when it expires
- Add `.env` to your `.gitignore` if using version control

### Step 3: Initialize Courses

Run the init command to discover and configure your courses:

```bash
moodle init
```

This will:
- Connect to Moodle using your cookie
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
moodle pull
```

This will:
- Download all files from enabled courses
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

### "Session Expired" Error

Your Moodle session cookie has expired. Follow the steps in "Get Your Moodle Cookie" to get a new cookie and update your `.env` file.

### "MoodleSession cookie not found"

Make sure your `.env` file:
- Is in the current working directory
- Contains the `MoodleSession` cookie
- Has the correct format (see Configuration section)

### Command Not Found

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
