# Steganography and Cryptography Web Application

This project is a secure, web-based app built with [Streamlit](https://streamlit.io/) that combines **steganography** and **cryptography** functionalities. It allows users to hide messages within PNG images (steganography) and perform a variety of cryptographic operations including encryption, decryption, hashing, and key management. The application integrates with [Google Cloud Storage](https://cloud.google.com/storage) for secure file management with [Google Cloud Storage Buckets](https://docs.streamlit.io/develop/tutorials/databases/gcs) and uses [Google OAuth 2.0](https://docs.streamlit.io/develop/api-reference/user/st.login) for user authentication.

**NOTE: The app is hosted publicly at [https://imgstego.streamlit.app/](https://imgstego.streamlit.app/), where anyone can view steganography images, but only authenticated users can access full features.**

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Developer Instructions](#developer-instructions)
- [Usage](#usage)
- [Security Considerations](#security-considerations)

## Overview
**Steganography** involves concealing a message within another object (e.g., an image) such that the hidden message is imperceptible to an unsuspecting observer. **Cryptography** secures information through techniques like encryption and hashing. This application provides a user-friendly interface for both:

- **Steganography**: Embed and extract ASCII messages in PNG images by modifying least significant bits (LSBs).
- **Cryptography**: Perform symmetric and asymmetric encryption/decryption, compute file hashes, generate keys, and create secure passwords.

## Features
### General
- **User Authentication**: Secure login via Google OAuth 2.0.
- **File Management**: Upload, download, and delete files stored in Google Cloud Storage.
- **Public Access**: Anyone can view steganography images without logging in.
- **User Help**: Helpful tips have been added to both Steganography and Cryptography pages.

### Steganography
- **Embed Messages**: Hide ASCII messages in PNG images with customizable start bit (S) and periodicity (C).
- **Extract Messages**: Retrieve hidden messages using the correct S, C, and message length parameters.
- **Image Support**: Handles PNG files with transparency, modifying only RGB data.

### Cryptography
- **Key Management**:
  - Generate symmetric keys (AES-128, AES-256, 3-DES).
  - Generate RSA-2048 key pairs.
  - Download or delete stored keys.
- **Symmetric Encryption/Decryption**:
  - Algorithms: AES-128, AES-256, 3-DES.
  - Block Modes: CBC (all), GCM (AES only).
- **Asymmetric Encryption/Decryption**:
  - RSA-2048 with hybrid encryption (AES-256-GCM + RSA-OAEP).
- **Hashing**:
  - Algorithms: SHA-2 (256-bit), SHA-3 (256-bit).
  - Compute and compare file hashes.
- **Password Generation**:
  - Customizable character sets (lowercase, uppercase, digits, special characters) and length (8–128).

## Developer Instructions
To run the app locally, follow these steps:

### Prerequisites
- **Python**: 3.12 or higher ([Download](https://www.python.org/downloads/)).
- **Google Cloud Account**: Sign up for a [trial account](https://console.cloud.google.com/).
- **Dependencies**: Listed in `requirements.txt`.

### Installation
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   # Create
   python -m venv myenv
   # Activate (Windows)
   myenv\Scripts\activate
   # Activate (macOS/Linux)
   source myenv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Google Cloud**:
   - Set up a [Google Cloud Storage Bucket](https://docs.streamlit.io/develop/tutorials/databases/gcs).
   - Configure [Google Cloud OAuth 2.0](https://docs.streamlit.io/develop/api-reference/user/st.login) for authentication.
   - Create a `.streamlit/secrets.toml` file:
     ```bash
     mkdir .streamlit
     touch .streamlit/secrets.toml
     ```
   - Add secrets:
     ```toml
     # Only a sample, see Google and Streamlit for actual requirements
     [gcp_service_account]
     client_email = "your-service-account-email"
     private_key = "your-private-key"
     project_id = "your-project-id"

     [app_data]
     bucket_name = "your-bucket-name"
     master_key = "base64-encoded-32-byte-master-key"
     ```

5. **Run the Application**:
   ```bash
   streamlit run app.py
   ```
   - Access it at `http://localhost:8501`.
   - To stop, press `Ctrl+C` in the terminal, then close the browser.

## Usage
### Public Access
- Visit [https://imgstego.streamlit.app/](https://imgstego.streamlit.app/).
- View steganography images without logging in.
- Log in with Google to access all features.

### Steganography
1. **Insert Message**:
   - Upload a PNG image.
   - Enter a message (A-Z, a-z, 0-9, space, !, comma, period).
   - Set start bit (S) and mode (C) (e.g., S=7, C=8 for LSB).
   - Download the modified image.
2. **Extract Message**:
   - Select a modified image.
   - Input S, C, and message length (in bytes).
   - View the extracted message.

### Cryptography
1. **File Management**:
   - Upload files to your account.
   - View, download, or delete existing files.
2. **Key Management**:
   - Generate symmetric keys (select algorithm).
   - Generate RSA key pairs.
   - View, download, or delete stored keys.
3. **Symmetric Files**:
   - Encrypt: Choose a file, algorithm, mode, and key; specify output filename.
   - Decrypt: Select an encrypted file, matching key, and mode; specify output filename.
4. **Asymmetric Files**:
   - Encrypt: Select a file and public key; specify output filename.
   - Decrypt: Select an encrypted file and private key; specify output filename.
5. **Hashing**:
   - Compute: Select a file and algorithm (SHA-2/SHA-3) to get a hash.
   - Compare: Enter a hash to verify against the computed hash.
6. **Passwords**:
   - Customize character sets and length.
   - Generate a secure password.

## Security Considerations
- **Authentication**: Google OAuth ensures secure user access.
- **Storage**: Files and keys are stored in Google Cloud Storage; keys are encrypted with a master key.
- **Encryption**: Uses the `cryptography` library for secure operations.
- **Input Sanitization**: File names and hashes are validated to prevent injection attacks.
- **Error Handling**: Generic error messages avoid leaking sensitive data.

---
