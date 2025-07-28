#!/usr/bin/env python3
import keyring
import getpass

print("🔐 Secure Credential Setup")
print("\nNOTE: For Gmail, use an App Password (https://myaccount.google.com/apppasswords)\n")

# Store email
email = input("Your email: ")
keyring.set_password("flash2msg", "email", email)

# Store app password securely
while True:
    pw1 = getpass.getpass("App password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 == pw2:
        keyring.set_password("flash2msg", "password", pw1)
        break
    print("Passwords don't match! Try again")

# Store recipient
recipient = input("Recipient email: ")
keyring.set_password("flash2msg", "recipient", recipient)

print("\n✅ Credentials stored in system keyring")
print(f"Service: 'flash2msg' | Keys: email, password, recipient")
