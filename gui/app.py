import customtkinter as ctk
from tkinter import messagebox
import threading
import time
from scanner import port_scanner, secret_scanner, file_scanner


class SentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Sentinel Scan Tool")
        self.geometry("1100x700")
        self.resizable(False, False)
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.is_scanning = False
        self.animation_running = False
        self.max_output_lines = 500  # Limit output lines

        self.create_widgets()

    def create_widgets(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=12)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="🛡️ Sentinel", font=("Poppins", 26, "bold"))
        self.logo_label.pack(pady=(25, 20))

        self.scan_type = ctk.StringVar(value="Port Scanner")

        self.port_scan_button = ctk.CTkButton(self.sidebar, text="🌐 Port Scan", command=lambda: self.scan_type.set("Port Scanner"), font=("Segoe UI", 13))
        self.port_scan_button.pack(pady=12, padx=15, fill="x")

        self.secret_scan_button = ctk.CTkButton(self.sidebar, text="🔐 Secret Scan", command=lambda: self.scan_type.set("Secret Scanner"), font=("Segoe UI", 13))
        self.secret_scan_button.pack(pady=12, padx=15, fill="x")

        self.file_scan_button = ctk.CTkButton(self.sidebar, text="📁 File Scan", command=lambda: self.scan_type.set("File Scanner"), font=("Segoe UI", 13))
        self.file_scan_button.pack(pady=12, padx=15, fill="x")

        self.mode_switch = ctk.CTkSwitch(self.sidebar, text="🌃 Toggle Theme", command=self.toggle_mode)
        self.mode_switch.pack(pady=30)

        self.footer = ctk.CTkLabel(self.sidebar, text="© 2025 AK Tools", font=("Segoe UI", 10))
        self.footer.pack(side="bottom", pady=10)

        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.pack(padx=20, pady=20, expand=True, fill="both")

        self.title_label = ctk.CTkLabel(self.main_frame, text="Sentinel Scan Tool", font=("Poppins", 28, "bold"))
        self.title_label.pack(pady=(15, 20))

        self.input_field = ctk.CTkEntry(self.main_frame, placeholder_text="Enter target IP, domain or folder", width=640, font=("Segoe UI", 14))
        self.input_field.pack(pady=12)

        self.button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.button_frame.pack(pady=8)

        self.start_button = ctk.CTkButton(self.button_frame, text="▶ Start Scan", command=self.start_scan, fg_color="#43A047", hover_color="#2E7D32", font=("Segoe UI", 14), corner_radius=10, width=160)
        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = ctk.CTkButton(self.button_frame, text="■ Stop Scan", command=self.stop_scan, fg_color="#E53935", hover_color="#C62828", font=("Segoe UI", 14), corner_radius=10, width=160)
        self.stop_button.grid(row=0, column=1, padx=10)

        self.output_box = ctk.CTkTextbox(self.main_frame, width=800, height=300, font=("Consolas", 12), wrap="word")
        self.output_box.pack(pady=20)

        self.loading_label = ctk.CTkLabel(self.main_frame, text="", font=("Segoe UI", 12, "italic"), text_color="#888888")
        self.loading_label.pack()

        self.progress = ctk.CTkProgressBar(self.main_frame, width=400)
        self.progress.set(0)
        self.progress.pack(pady=(10, 5))

        self.export_button = ctk.CTkButton(self.main_frame, text="📂 Export Results", command=self.export_results, font=("Segoe UI", 13))
        self.export_button.pack(pady=(10, 0))

    def toggle_mode(self):
        new_mode = "Light" if ctk.get_appearance_mode() == "Dark" else "Dark"
        ctk.set_appearance_mode(new_mode)

    def start_scan(self):
        target = self.input_field.get()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target.")
            return

        self.is_scanning = True
        self.output_box.delete("1.0", "end")
        self.append_output("[✓] Scan started...", color="#00FF00")
        self.progress.set(0.05)

        scan_type = self.scan_type.get()

        self.animation_running = True
        threading.Thread(target=self.animate_loading).start()

        thread = threading.Thread(target=self.run_scan, args=(scan_type, target))
        thread.start()

    def stop_scan(self):
        self.is_scanning = False
        self.animation_running = False
        self.loading_label.configure(text="")
        self.progress.set(0)
        self.append_output("[!] Scan stopped by user.", color="#FF4444")

    def animate_loading(self):
        dots = ""
        while self.animation_running:
            dots = "." * ((len(dots) % 3) + 1)
            self.loading_label.configure(text=f"⏳ Scanning{dots}")
            current_val = self.progress.get()
            new_val = min(current_val + 0.01, 0.9)
            self.progress.set(new_val)
            time.sleep(0.4)

    def run_scan(self, scan_type, target):
        try:
            if scan_type == "Port Scanner":
                results = port_scanner.run(target, self.is_scanning_callback)
            elif scan_type == "Secret Scanner":
                results = secret_scanner.run(target, self.is_scanning_callback)
            elif scan_type == "File Scanner":
                results = file_scanner.run(target, self.is_scanning_callback)
            else:
                results = f"[!] Unsupported scan type: {scan_type}"
        except Exception as e:
            results = f"[!] Error occurred: {str(e)}"

        self.animation_running = False
        self.loading_label.configure(text="")
        self.progress.set(1.0)
        for line in results.splitlines():
            self.append_output(line)
        self.append_output("[✓] Scan completed", color="#00FF00")

    def append_output(self, text, color="#CCCCCC"):
        lines = self.output_box.get("1.0", "end-1c").splitlines()
        if len(lines) >= self.max_output_lines:
            self.output_box.delete("1.0", "2.0")  # remove top line
        self.output_box.insert("end", text + "\n")
        self.output_box.tag_add(color, "end-2l", "end-1l")
        self.output_box.tag_config(color, foreground=color)
        self.output_box.see("end")

    def is_scanning_callback(self):
        return self.is_scanning

    def export_results(self):
        with open("scan_results.txt", "w") as f:
            f.write(self.output_box.get("1.0", "end"))
        messagebox.showinfo("Export", "Results exported to scan_results.txt")
