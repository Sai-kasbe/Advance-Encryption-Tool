# 🔐 Advanced Encryption Tool

## 📌 Project Overview

The **Advanced Encryption Tool** is a cybersecurity application developed using Python that enables users to securely encrypt and decrypt sensitive data using modern cryptographic algorithms. The tool provides a user-friendly interface for protecting text, files, and confidential information against unauthorized access.

The system implements strong encryption techniques such as AES, Fernet, RSA, and SHA-256 hashing to ensure data confidentiality, integrity, and security.

---

## 🎯 Objectives

* Protect sensitive information from unauthorized access.
* Provide secure encryption and decryption mechanisms.
* Support multiple encryption algorithms.
* Ensure data integrity through hashing.
* Offer an easy-to-use graphical interface.
* Demonstrate practical cryptography concepts.

---

## ✨ Features

### 🔒 Text Encryption

* Encrypt plain text instantly.
* Decrypt encrypted text securely.

### 📂 File Encryption

* Encrypt files before storage or sharing.
* Decrypt files only with authorized keys.

### 🔑 Key Management

* Generate secure encryption keys.
* Store keys securely.
* Import existing keys.

### 🛡️ Hash Generation

* SHA-256 Hashing
* MD5 Hashing
* File Integrity Verification

### 🔐 Multiple Encryption Algorithms

* AES Encryption
* Fernet Encryption
* RSA Encryption
* SHA-256 Hashing

### 📊 Activity Monitoring

* Encryption logs
* Decryption logs
* Timestamp records

---

## 🏗️ System Architecture

```text
User
 │
 ▼
Graphical User Interface
 │
 ▼
Encryption Engine
 │
 ├── AES Module
 ├── RSA Module
 ├── Fernet Module
 └── Hashing Module
 │
 ▼
Encrypted Output
```

---

## 🔒 Security Features

### AES Encryption

Advanced Encryption Standard (AES) is used for high-speed symmetric encryption.

### RSA Encryption

Public-Key Cryptography is used for secure key exchange.

### Fernet Encryption

Provides authenticated encryption and prevents data tampering.

### SHA-256 Hashing

Ensures data integrity and password protection.

### Secure Key Generation

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
```

### Encryption Example

```python
from cryptography.fernet import Fernet

cipher = Fernet(key)

encrypted = cipher.encrypt(
message.encode()
)
```

### Decryption Example

```python
decrypted = cipher.decrypt(
encrypted
).decode()
```

---

## 💻 Technologies Used

### Frontend

* Streamlit
* HTML
* CSS

### Backend

* Python

### Libraries

* cryptography
* hashlib
* base64
* secrets
* os

---

## 📂 Project Structure

```text
Advanced_Encryption_Tool/
│
├── app.py
├── encryption.py
├── decryption.py
├── key_manager.py
├── hashing.py
│
├── encrypted_files/
├── decrypted_files/
├── keys/
│
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/advanced-encryption-tool.git
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
streamlit run app.py
```

---

## 📦 Required Packages

```text
streamlit
cryptography
hashlib
base64
pandas
Pillow
```

---

## 🔄 Workflow

```text
User Input
    ↓
Select Algorithm
    ↓
Generate Key
    ↓
Encrypt Data
    ↓
Store Securely
    ↓
Decrypt When Needed
```

---

## 📈 Applications

* Secure File Storage
* Password Protection
* Secure Data Transfer
* Academic Cryptography Projects
* Cybersecurity Demonstrations
* Confidential Document Protection

---

## 🚀 Future Enhancements

* AES-256 Support
* Multi-Factor Authentication
* Cloud Key Vault Integration
* QR-Based Key Sharing
* Biometric Authentication
* Blockchain-Based Key Management

---

## 👨‍💻 Developer

**Sai Krishna**

B.Tech – Computer Science and Engineering (Data Science)

Project Title:

**Advanced Encryption Tool Using AES, RSA, Fernet, and SHA-256 Cryptographic Algorithms**

---

## 📜 License

This project is developed for educational, research, and cybersecurity learning purposes.

---

One note: if this is for a **final-year or resume project**, an "Advanced Encryption Tool" by itself is often considered a small project. Adding **file encryption, password manager, secure key vault, digital signatures, and ransomware detection** would make it much stronger for software or cybersecurity job applications.
