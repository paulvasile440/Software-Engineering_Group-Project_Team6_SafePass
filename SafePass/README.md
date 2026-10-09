# SafePass Desktop Password Manager

SafePass is a small desktop password manager created for a software engineering and project management assignment.

## Main Features

- First-time master password setup
- Secure login using a master password
- Add password records
- View saved records
- Edit password records
- Delete password records
- Hide stored passwords by default
- View or copy a selected password
- Generate random passwords
- Store data locally with SQLite
- Encrypt saved passwords and notes
- Logout and return to the login screen

## Technology

- Python 3
- Tkinter
- SQLite
- `cryptography` / Fernet encryption

## Project Structure

```text
SafePass/
├── main.py
├── database.py
├── security.py
├── README.md
```

## Setup

1. Install Python 3.10 or newer.
2. Open a terminal in the SafePass folder.
3. Install the dependency:

```bash
pip install -r requirements.txt
```

4. Run the application:

```bash
python main.py
```

## First Run

On the first run, SafePass asks you to create a master password.

Use at least 8 characters.

The master password is not stored as normal readable text. SafePass stores a derived verifier and uses the entered master password to derive the encryption key for the password vault.

