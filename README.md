# 🛡️ Sentinel Scan Tool

A professional GUI-based cybersecurity scanner built with Python and CustomTkinter. Sentinel helps you perform:

* 🔍 Port Scans (with service detection)
* 🔐 Secret Scans (detect secrets or sensitive tokens in code/files)
* 📁 File Scans (basic malware or file-type scans)

Designed to look and feel like a polished desktop app, this tool is perfect for ethical hackers, developers, and sysadmins.

---

## 🚀 Features

* Intuitive GUI built with CustomTkinter
* Dark/Light theme toggle 🌗
* Start/Stop scan controls
* Animated progress with real-time logs
* Export scan results to a file
* Modular scanner design (easy to extend)

---

## 🧰 Technologies Used

* Python 3.8+
* [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
* `nmap` Python module (requires `nmap` installed)

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/vidaque/sentinel-scan-tool.git
cd sentinel-scan-tool

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 main.py
```

---

## 📂 Project Structure

```
sentinel-scan-tool/
├── main.py
├── requirements.txt
├── README.md
├── scanner/
│   ├── port_scanner.py
│   ├── secret_scanner.py
│   └── file_scanner.py
└── gui/
    └── app.py
```

---

---

## 📁 Exporting Results

Click the `📂 Export Results` button after any scan to save logs to `scan_results.txt`.

---

## ❗ Requirements

Make sure you have:

* Python 3.8+
* `nmap` installed (e.g., `sudo apt install nmap` on Linux)

---

## 🧪 Testing

Test each scan type using real or simulated targets:

* `127.0.0.1` for port scanning
* Path to a code folder for secret scanning
* Directory path for file scanning

---

## ⚠️ Disclaimer

> This tool is for **educational and ethical use only**. The developer is not responsible for misuse.

---

## 👨‍💻 Author

\*\*Aadith k v \*\*
[GitHub](https://github.com/vidaque)

---

## 📜 License

MIT License

---
