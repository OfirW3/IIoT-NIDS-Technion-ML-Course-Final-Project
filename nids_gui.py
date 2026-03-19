#!/usr/bin/env python3

import tkinter as tk
from tkinter import scrolledtext, font
import subprocess
import threading
import queue
import os

class NIDSCommandCenter:
    def __init__(self, root):
        self.root = root
        self.root.title("NIDS End-to-End Command Center")
        self.root.geometry("1100x750")
        self.root.configure(bg="#1e1e1e")

        self.process = None
        self.log_queue = queue.Queue()

        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#2d2d2d", pady=10)
        header_frame.pack(fill=tk.X)

        title = tk.Label(header_frame, text="Network Intrusion Detection System", 
                         font=("Consolas", 16, "bold"), bg="#2d2d2d", fg="#4CAF50")
        title.pack()

        # Control Panel
        control_frame = tk.Frame(self.root, bg="#1e1e1e", pady=10)
        control_frame.pack(fill=tk.X)

        self.start_btn = tk.Button(control_frame, text="▶ START PIPELINE", bg="#4CAF50", fg="white", 
                                   font=("Consolas", 12, "bold"), command=self.start_pipeline, width=20)
        self.start_btn.pack(side=tk.LEFT, padx=20)

        self.stop_btn = tk.Button(control_frame, text="■ STOP PIPELINE", bg="#f44336", fg="white", 
                                  font=("Consolas", 12, "bold"), command=self.stop_pipeline, width=20, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        self.status_lbl = tk.Label(control_frame, text="Status: OFFLINE", font=("Consolas", 12), bg="#1e1e1e", fg="#9e9e9e")
        self.status_lbl.pack(side=tk.RIGHT, padx=20)

        # Terminal Output Area
        self.console_font = font.Font(family="Consolas", size=10)
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, bg="#000000", fg="#00FF00", 
                                                   font=self.console_font, padx=10, pady=10)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        self.text_area.config(state=tk.DISABLED)

        # Custom Copy-Paste Binding
        self.text_area.bind("<Control-c>", self.copy_to_clipboard)

        # Colors for alerts
        self.text_area.tag_config("alert_header", foreground="#ffffff", background="#ff1744", font=("Consolas", 11, "bold"))
        self.text_area.tag_config("alert", foreground="#ff5252", font=("Consolas", 10, "bold"))
        self.text_area.tag_config("info", foreground="#00b0ff")
        self.text_area.tag_config("sniffer", foreground="#424242") # Dim the tcpdump noise

        self.root.after(100, self.poll_logs)

    def copy_to_clipboard(self, event=None):
        """Safely extracts text without copying junk characters."""
        try:
            selected_text = self.text_area.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
            self.root.update()
        except tk.TclError:
            pass # Nothing was selected
        return "break" # Stops Tkinter from doing its buggy default copy

    def log(self, message):
        self.log_queue.put(message)

    def poll_logs(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.text_area.config(state=tk.NORMAL)
            
            # Styling logic
            if "STATUS: ALERT" in msg or "INFERENCE REPORT" in msg:
                self.text_area.insert(tk.END, msg, "alert_header")
            elif "Flagged as:" in msg and "benign" not in msg:
                self.text_area.insert(tk.END, msg, "alert")
            elif "tcpdump" in msg or "captured" in msg or "received by filter" in msg:
                self.text_area.insert(tk.END, msg, "sniffer") # Hide the sniffer noise a bit
            else:
                self.text_area.insert(tk.END, msg, "info")
                
            self.text_area.see(tk.END)
            self.text_area.config(state=tk.DISABLED)
            
        self.root.after(50, self.poll_logs)

    def read_stdout(self):
        try:
            for line in iter(self.process.stdout.readline, b''):
                self.log(line.decode('utf-8'))
        except Exception as e:
            self.log(f"[GUI ERROR] {e}\n")
        finally:
            self.root.after(0, self.handle_process_exit)

    def start_pipeline(self):
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text="Status: RUNNING", fg="#4CAF50")
        
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)
        
        self.log("[GUI] Initializing End-to-End Pipeline...\n")

        cmd = ["sudo", "nids_env/bin/python", "run_pipeline.py"]
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1" 

        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            threading.Thread(target=self.read_stdout, daemon=True).start()
        except Exception as e:
            self.log(f"\n[GUI FATAL ERROR] {e}\n")
            self.handle_process_exit()

    def stop_pipeline(self):
        if self.process:
            self.log("\n[GUI] Sending graceful interrupt (Ctrl+C) to pipeline via sudo...\n")
            self.stop_btn.config(state=tk.DISABLED)
            self.status_lbl.config(text="Status: SHUTTING DOWN...", fg="#ffd600")
            
            # Use sudo pkill to safely send SIGINT directly to the orchestrator script
            subprocess.run(["sudo", "pkill", "-SIGINT", "-f", "run_pipeline.py"], stderr=subprocess.DEVNULL)

    def handle_process_exit(self):
        self.process = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_lbl.config(text="Status: OFFLINE", fg="#9e9e9e")
        self.log("\n[GUI] Pipeline gracefully terminated.\n")

    def on_closing(self):
        if self.process:
            self.stop_pipeline()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NIDSCommandCenter(root)
    root.mainloop()