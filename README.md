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

3. Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
venv\Scripts\activate     # Windows
```

4. Install required packages:

```bash
pip install requests
```

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

## HTTPS Localhost Scan

To test HTTPS scanning locally, create a self-signed certificate and key using OpenSSL:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Accept the prompts or leave the fields blank as needed. Then start a local HTTPS server from the project root:

```bash
python3 scripts/https_server.py
```

This serves HTTPS on `https://127.0.0.1:4443` by default. Run the scanner against localhost or `127.0.0.1`:

```bash
python3 scripts/run_scan.py localhost
```

If port `4443` is open, the scanner will perform TLS checks on that service.


## Testing Default Credentials

To test the credential checker locally, start the basic auth server in one terminal:

```bash
python3 scripts/basic_auth_server.py
```

This starts a server on `http://localhost:8081` with default credentials:
- Username: `admin`
- Password: `admin`

In another terminal, run the scanner:

```bash
python3 scripts/run_scan.py localhost
```

The scanner will detect port 8081, identify it as HTTP, and test the default credentials. If successful, you'll see the found credentials in the output.
