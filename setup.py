#!/usr/bin/env python3
import keyring
import getpass

print("🔐 Secure Credential Setup for Password Recovery Tool")

# Store email
email = input("Enter your email: ")
keyring.set_password("flash2msg", "email", email)

# Store app password (use an app-specific password for Gmail)
password = getpass.getpass("Enter your email app password: ")
keyring.set_password("flash2msg", "password", password)

# Store recipient
recipient = input("Enter recipient email: ")
keyring.set_password("flash2msg", "recipient", recipient)

print("✅ Credentials stored securely in system keyring")