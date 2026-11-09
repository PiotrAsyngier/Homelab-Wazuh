import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

QUARANTINE_DIR = r"C:\Quarantine"
LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"


def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(
            f"{timestamp} Active Response [quarantine_mimi]: {message}\n"
        )


def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as file_handle:
        for byte_block in iter(lambda: file_handle.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_alert(message):
    parameters = message.get("parameters", {})
    return parameters.get("alert") or message.get("alert") or message


def stop_malicious_process(event_data):
    process_id = event_data.get("processId")
    if process_id and str(process_id).isdigit():
        command = ["taskkill", "/F", "/PID", str(process_id), "/T"]
    else:
        command = ["taskkill", "/F", "/IM", "mimikatz.exe", "/T"]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode not in (0, 128):
        error = result.stderr.strip() or f"exit code {result.returncode}"
        log_action(f"Nie udało się zakończyć procesu: {error}")


def quarantine_file(alert):
    event_data = alert.get("data", {}).get("win", {}).get("eventdata", {})
    malicious_file = (
        event_data.get("image")
        or event_data.get("sourceImage")
        or event_data.get("targetFilename")
    )

    if not malicious_file:
        raise ValueError("Alert nie zawiera ścieżki złośliwego pliku.")

    stop_malicious_process(event_data)

    if not os.path.isfile(malicious_file):
        log_action("Brak złośliwego pliku lub plik już nie istnieje.")
        return

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    filename = os.path.basename(malicious_file)
    quarantine_path = os.path.join(
        QUARANTINE_DIR,
        f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{filename}.locked",
    )
    shutil.move(malicious_file, quarantine_path)

    file_hash = get_file_hash(quarantine_path)
    acl_result = subprocess.run(
        ["icacls", quarantine_path, "/inheritance:r", "/grant:r", "SYSTEM:(F)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if acl_result.returncode != 0:
        error = acl_result.stderr.strip() or f"exit code {acl_result.returncode}"
        raise RuntimeError(f"Nie udało się zabezpieczyć uprawnień pliku: {error}")

    log_action(
        f"ZABEZPIECZONO DOWODY. Źródło: {malicious_file} | "
        f"Kwarantanna: {quarantine_path} | SHA256: {file_hash}"
    )


def main():
    try:
        message = json.load(sys.stdin)
        command = message.get("command")
        if command not in ("add", "enable"):
            log_action(f"Pominięto nieobsługiwaną komendę Active Response: {command}")
            return 0

        quarantine_file(get_alert(message))
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        log_action(f"Błąd krytyczny podczas kwarantanny: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
