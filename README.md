# Krault

Krault is a local-first desktop password manager built with Python and Tkinter. It stores credentials in an encrypted vault on the user's device and includes tools for password generation, two-factor authentication, session protection, backups, and vault integrity checks.

> **Security notice:** Krault is a software project, not a formally audited security product. Review the implementation and assess your own threat model before relying on it for sensitive or production use.

## Features

- **AES-256-GCM encryption** for vault data, providing authenticated encryption.
- **Argon2id key derivation** for master-password keys.
- **TOTP two-factor authentication (2FA)** with QR-code setup for authenticator apps.
- **Automatic vault locking** after inactivity.
- **Login-attempt throttling and account lockout** after repeated failed authentication attempts.
- **Local encrypted storage** with database integrity checks.
- **Multi-user profiles** with separate encrypted vaults.
- **Password generator** with configurable character sets and ambiguous-character exclusion.
- **Password-strength indicators and configurable password policy**.
- **Automatic clipboard clearing** after copied secrets are exposed temporarily.
- **Encrypted backup and restore** of the application data directory.
- **CSV and JSON export** for vault entries.
- **Audit logging** for authentication, security, database, and credential-access events.
- **Custom themes and appearance settings**.
- **Custom data-storage location** support.
- Additional macOS-specific handling for Application Support paths and file monitoring.

## Requirements

- Python **3.10+** recommended
- Tkinter
- Dependencies listed in `requirements.txt`:
  - `cryptography`
  - `argon2-cffi`
  - `pyotp`
  - `qrcode[pil]`
  - `Pillow`
  - `watchdog`

Tkinter is commonly included with Python on Windows and macOS. On some Linux distributions it must be installed separately, for example:

```bash
sudo apt install python3-tk
```

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/Krault.git
cd Krault
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

**Windows:**

```powershell
.venv\Scripts\activate
```

**macOS / Linux:**

```bash
source .venv/bin/activate
```

Install the dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Running Krault

Start the application with:

```bash
python run.py
```

You can also run the main entry point directly:

```bash
python main.py
```

## First use

1. Open Krault.
2. Select **Create account**.
3. Choose a username and a strong master password.
4. Optionally enable TOTP-based two-factor authentication.
5. Add entries to your encrypted vault.

The master password is used to derive the encryption key and is not stored as plaintext. **There is no master-password recovery mechanism.** If you lose the master password, the encrypted vault cannot be recovered through the application.

## Data storage

Krault stores application data locally.

Typical default locations are:

- **Windows:** `%APPDATA%\SecurePasswordManager`
- **macOS:** `~/Library/Application Support/SecurePasswordManager`
- **Linux and other Unix-like systems:** `~/.secure_password_manager`

The storage location can also be changed from the application's settings.

## Security architecture

### Encryption

Vault entries are encrypted using **AES-256-GCM** with a randomly generated 96-bit nonce for each encryption operation. GCM provides confidentiality and authentication, allowing modified or corrupted ciphertext to be rejected during decryption.

### Master-password key derivation

New keys are derived with **Argon2id**. The current configuration uses:

- Time cost: `3`
- Memory cost: `65536 KiB` (64 MiB)
- Parallelism: `4`
- Output length: `32 bytes`

### Session protection

Krault includes:

- automatic locking after inactivity;
- failed-login tracking;
- temporary account lockout after repeated failures;
- best-effort clearing of sensitive in-memory values;
- automatic clipboard clearing after copied credentials;
- security audit events.

### Two-factor authentication

Krault supports time-based one-time passwords (**TOTP**) compatible with common authenticator applications. The TOTP secret is protected by the vault's encryption layer.

## Backup and export

From **Settings → Backup & Export**, Krault can:

- create a full backup of the application data directory;
- restore an existing backup;
- export vault entries as CSV;
- export vault entries as JSON.

> **Important:** CSV and JSON exports contain **decrypted credentials**. Treat exported files as highly sensitive, protect them appropriately, and remove them securely when they are no longer needed.

## Project structure

```text
Krault/
├── config/
│   ├── constants.py
│   └── themes.py
├── core/
│   ├── audit_logger.py
│   ├── database_manager.py
│   ├── password_policy.py
│   ├── security_manager.py
│   ├── security_service.py
│   └── session_manager.py
├── models/
│   └── secure_string.py
├── ui/
│   ├── dialogs.py
│   ├── modern_widgets.py
│   ├── screens.py
│   ├── theme_manager.py
│   └── widgets.py
├── utils/
│   ├── helpers.py
│   └── macos_helper.py
├── build.spec
├── main.py
├── requirements.txt
└── run.py
```

## Building an executable

A PyInstaller specification file is included as `build.spec`.

Install PyInstaller:

```bash
pip install pyinstaller
```

Then build with:

```bash
pyinstaller build.spec
```

The current `build.spec` references `icon.ico`. Add that file to the project root or remove the `icon='icon.ico'` setting before building if the icon is not present.

## Development notes

A basic syntax check can be run with:

```bash
python -m compileall .
```

When changing cryptographic or authentication code, consider adding automated tests and obtaining an independent security review before distributing the application for sensitive use.

## Contributing

Contributions, bug reports, and security improvements are welcome. For substantial changes, open an issue first to discuss the proposed implementation and its security implications.

When submitting code:

1. Keep security-sensitive changes small and reviewable.
2. Avoid logging passwords, encryption keys, TOTP secrets, or decrypted vault contents.
3. Document changes to storage formats or cryptographic parameters.
4. Preserve compatibility or provide an explicit migration path when changing encrypted data formats.

## License

Krault is available under the [MIT License](LICENSE.md).
