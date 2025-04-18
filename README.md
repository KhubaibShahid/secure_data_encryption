# Secure Data Encryption System

A secure web application built with Streamlit that allows users to encrypt and decrypt data using unique passkeys. The system uses Fernet symmetric encryption and includes security features like failed attempt tracking and master password protection.

## Features

- 🔒 Secure data encryption using Fernet (symmetric encryption)
- 🔑 Unique passkey-based data storage and retrieval
- 👤 User authentication system
- ⚠️ Failed attempt tracking and account lockout
- 🔐 Master password protection
- 💾 Persistent data storage

## Requirements

- Python 3.x
- Streamlit
- cryptography
- python-dotenv

## Setup

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Create a `.env` file with your secret key:
   ```
   SECRET_KEY=your_fernet_key_here
   ```
4. Run the application:
   ```
   streamlit run main.py
   ```

## Security Features

- SHA-256 hashing for passkeys
- Fernet symmetric encryption for data
- Account lockout after 3 failed attempts
- Secure password input fields
- Environment variable-based key management

## Usage

1. **Store Data**: Enter your data and create a unique passkey
2. **Retrieve Data**: Use your passkey to decrypt and view stored data
3. **Login**: Master password required after 3 failed attempts

## Note

This is a demonstration project. For production use, implement additional security measures and proper password management.
