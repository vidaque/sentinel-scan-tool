import os
import time
from datetime import datetime, timedelta

# Define suspicious extensions and size limit (in bytes)
SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".sh", ".vbs", ".js", ".ps1"]
SIZE_LIMIT = 100 * 1024 * 1024  # 100MB
RECENT_DAYS = 7  # Files modified in the last 7 days

def run(directory_path, is_running_callback):
    if not os.path.exists(directory_path):
        return f"[✘] Path '{directory_path}' not found."

    if not os.path.isdir(directory_path):
        return f"[✘] '{directory_path}' is not a directory."

    results = []
    results.append(f"[→] Scanning files in: {directory_path}")
    recent_threshold = time.time() - RECENT_DAYS * 86400  # seconds in RECENT_DAYS

    try:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if not is_running_callback():
                    return "[!] File scan interrupted by user."

                filepath = os.path.join(root, file)
                try:
                    file_stats = os.stat(filepath)
                    file_ext = os.path.splitext(file)[1].lower()

                    if file_ext in SUSPICIOUS_EXTENSIONS:
                        results.append(f"[!] Suspicious file type found: {filepath}")

                    if file_stats.st_size > SIZE_LIMIT:
                        results.append(f"[!] Large file detected: {filepath} ({file_stats.st_size // (1024 * 1024)}MB)")

                    if file_stats.st_mtime > recent_threshold:
                        modified_time = datetime.fromtimestamp(file_stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        results.append(f"[~] Recently modified: {filepath} at {modified_time}")

                except Exception as e:
                    results.append(f"[!] Error scanning {filepath}: {e}")

    except Exception as scan_error:
        return f"[!] Error during file scan: {str(scan_error)}"

    if len(results) == 1:
        results.append("[✓] No suspicious files found.")
    else:
        results.append("[✓] File scan complete.")

    return "\n".join(results)

