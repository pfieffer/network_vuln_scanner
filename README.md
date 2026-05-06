# Network Vulnerability Scanner

## Setup

1. Install Python 3.
   - Windows: download from https://www.python.org/downloads/ and follow the installer.
   - macOS: use Homebrew (`brew install python`) or download from https://www.python.org/downloads/.
   - Linux: use your distribution package manager, for example `sudo apt install python3` on Debian/Ubuntu.

2. Verify Python is installed:

```bash
python3 --version
```

3. (Optional) Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
venv\Scripts\activate     # Windows
```

4. Install required packages if any are added later. Currently the scanner uses only the Python standard library.

## Run

From the project root, run:

```bash
python3 scripts/run_scan.py <target>
```

Example for localhost:

```bash
python3 -m scripts.run_scan localhost
```

## Notes

- Only run this scanner on systems you own or have permission to test.
- Good targets are localhost, local lab VMs, or permitted networks.
- A simple local test server can be started for HTTP on localhost with:

```bash
python3 -m http.server 8000
```

Then scan `localhost` or `127.0.0.1`.
