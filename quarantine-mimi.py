import sys
import json
import os
import shutil
import hashlib
import subprocess
from datetime import datetime

QUARANTINE_DIR = r"C:\Quarantine"
LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} Active Response [quarantine_mimi]: {message}\n")

def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "BŁĄD_OBLICZANIA_HASHA"

def quarantine_file(alert_path):
    try:
        with open(alert_path, 'r') as f:
            alert = json.loads(f.read())
        
        # Wyciągnięcie ścieżki złośliwego pliku z alertu JSON wygenerowanego przez Sysmon
        win_data = alert.get("data", {}).get("win", {}).get("eventdata", {})
        malicious_file = win_data.get("image") or win_data.get("sourceImage")

        if not malicious_file or not os.path.exists(malicious_file):
            log_action("Brak złośliwego pliku lub plik już nie istnieje.")
            return

        # 1. Utworzenie bezpiecznego katalogu kwarantanny
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)

        # 2. Przeniesienie pliku do kwarantanny z nowym rozszerzeniem
        filename = os.path.basename(malicious_file)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{filename}.locked")
        shutil.move(malicious_file, quarantine_path)

        # 3. Zabezpieczenie dowodów (SHA256)
        file_hash = get_file_hash(quarantine_path)

        # 4. Odebranie uprawnień (icacls) - tylko system ma pełen dostęp, nikt tego pliku nie kliknie
        subprocess.run(["icacls", quarantine_path, "/inheritance:r", "/grant:r", "SYSTEM:(F)"], capture_output=True)

        log_action(f"ZABEZPIECZONO DOWODY. Źródło: {malicious_file} | Kwarantanna: {quarantine_path} | SHA256: {file_hash}")

    except Exception as e:
        log_action(f"Błąd krytyczny podczas kwarantanny: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        quarantine_file(sys.argv[1])
