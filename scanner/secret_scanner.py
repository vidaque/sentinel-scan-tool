import os
import re

# Define common secret patterns (add more as needed)
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Generic API Key": r"[a-zA-Z0-9]{32,45}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
    "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
}

def run(directory_path, is_running_callback):
    if not os.path.exists(directory_path):
        return f"[✘] Path '{directory_path}' not found."

    if not os.path.isdir(directory_path):
        return f"[✘] '{directory_path}' is not a directory."

    results = []
    results.append(f"[→] Scanning for secrets in: {directory_path}")

    try:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if not is_running_callback():
                    return "[!] Secret scan interrupted by user."

                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for name, pattern in SECRET_PATTERNS.items():
                            matches = re.findall(pattern, content)
                            for match in matches:
                                results.append(f"[!] Potential {name} found in {filepath}: {match}")
                except Exception as e:
                    results.append(f"[!] Error reading {filepath}: {e}")

    except Exception as scan_error:
        return f"[!] Error during secret scan: {str(scan_error)}"

    if len(results) == 1:
        results.append("[✓] No secrets found.")
    else:
        results.append("[✓] Secret scan complete.")

    return "\n".join(results)
