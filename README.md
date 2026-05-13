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
pip install -r requirements.txt
```

## Web Application

The scanner includes a Flask web application with authentication and role-based access control (RBAC).

### Starting the Web App

From the project root, run:

```bash
flask --app app run
```

This starts the Flask development server on `http://localhost:5000`.

### User Management

The application supports three user roles:

- **admin**: Full access (read, write, delete, scan, export)
- **analyst**: Can perform scans and export reports (read, write, scan, export)
- **viewer**: Read-only access (read)

#### Create a New User

To create a user with a specific role:

```bash
flask --app app create-user
```

You will be prompted to enter:
- Username
- Email
- Password
- Role (admin, analyst, or viewer)

Example:

```bash
flask --app app create-user --username admin1 --email admin@example.com --password securepass123 --role admin
flask --app app create-user --username analyst1 --email analyst@example.com --password securepass456 --role analyst
flask --app app create-user --username viewer1 --email viewer@example.com --password securepass789 --role viewer
```

#### List All Users

To view all users and their assigned roles:

```bash
flask --app app list-users
```

### 2FA Setup (Optional)

Users can optionally enable Two-Factor Authentication (2FA) on their accounts. After logging in, users can set up 2FA by scanning a QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, etc.).

## Command-Line Scanner

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


## Encrypted Credential Store

The scanner now loads default credentials from an encrypted file at runtime and decrypts it with a user-provided password.

Create the encrypted credential store before scanning:

```bash
python3 scripts/create_credential_store.py --password <your-password>
```

This writes `scanner/default_creds.enc` and secures the credential dictionary with AES-256-GCM.

## Testing Default Credentials

To test the credential checker locally, start the basic auth server in one terminal. The auth server loads credentials from the encrypted credential store, so provide the same password used to encrypt it:

```bash
python3 scripts/basic_auth_server.py --cred-password <your-password>
```

This starts a server on `http://localhost:8081` with the selected credential pair from `scanner/default_creds.enc`.

In another terminal, run the scanner and provide the decryption password:

```bash
python3 scripts/run_scan.py localhost --cred-password <your-password>
```

If you omit `--cred-password`, the scanner will prompt for the password interactively.

The scanner will detect port 8081, identify it as HTTP, and test the default credentials. If successful, you'll see the found credentials in the output.
