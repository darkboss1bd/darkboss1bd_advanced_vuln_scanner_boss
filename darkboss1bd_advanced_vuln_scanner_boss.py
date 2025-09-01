import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from urllib.parse import urljoin, urlparse
import threading
import time
import random

class HackerVulnScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("💀 DARKBOSS1BD HACKER TOOLKIT - VULNSCAN X 💀")
        self.root.geometry("950x750")
        self.root.configure(bg='#000000')
        self.root.resizable(True, True)
        
        # Create the hacker interface
        self.create_hacker_interface()
        
    def create_hacker_interface(self):
        # Matrix-style background effect
        self.matrix_label = tk.Label(
            self.root,
            text="█▓▒░ SYSTEM ACCESS GRANTED ░▒▓█",
            font=('Courier', 10, 'bold'),
            fg='#00ff00',
            bg='#000000'
        )
        self.matrix_label.pack(pady=5)
        
        # Main Title
        title_frame = tk.Frame(self.root, bg='#000000')
        title_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_ascii = """
╔══════════════════════════════════════════════════════════════╗
║                    ██╗   ██╗ █████╗ ██╗     ███████╗         ║
║                    ██║   ██║██╔══██╗██║     ██╔════╝         ║
║                    ██║   ██║███████║██║     ███████╗         ║
║                    ╚██╗ ██╔╝██╔══██║██║     ╚════██║         ║
║                     ╚████╔╝ ██║  ██║███████╗███████║         ║
║                      ╚═══╝  ╚═╝  ╚═╝╚══════╝╚══════╝         ║
║                                                              ║
║              ███████╗ ██████╗██╗   ██╗██████╗                ║
║              ██╔════╝██╔════╝██║   ██║██╔══██╗               ║
║              ███████╗██║     ██║   ██║██████╔╝               ║
║              ╚════██║██║     ██║   ██║██╔══██╗               ║
║              ███████║╚██████╗╚██████╔╝██║  ██║               ║
║              ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝               ║
╚══════════════════════════════════════════════════════════════╝
        """
        
        title_label = tk.Label(
            title_frame,
            text=title_ascii,
            font=('Courier', 8),
            fg='#00ff00',
            bg='#000000',
            justify='left'
        )
        title_label.pack()
        
        # Subtitle
        subtitle_label = tk.Label(
            self.root,
            text=">>> ADVANCED CYBER SECURITY SCANNER <<<",
            font=('Courier', 12, 'bold'),
            fg='#ff0000',
            bg='#000000'
        )
        subtitle_label.pack(pady=5)
        
        # Target Input Section
        target_frame = tk.LabelFrame(
            self.root,
            text="🎯 TARGET SPECIFICATION",
            font=('Courier', 12, 'bold'),
            fg='#00ff00',
            bg='#000000',
            relief='groove',
            bd=2
        )
        target_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # URL Input
        url_frame = tk.Frame(target_frame, bg='#000000')
        url_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            url_frame,
            text="TARGET URL:",
            font=('Courier', 10, 'bold'),
            fg='#00ff00',
            bg='#000000'
        ).pack(anchor='w')
        
        self.url_entry = tk.Entry(
            url_frame,
            font=('Courier', 11),
            bg='#111111',
            fg='#00ff00',
            insertbackground='#00ff00',
            relief='solid',
            bd=1
        )
        self.url_entry.pack(fill=tk.X, pady=5)
        self.url_entry.insert(0, "https://example.com")
        
        # API Key Input
        api_frame = tk.Frame(target_frame, bg='#000000')
        api_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            api_frame,
            text="VIRUS TOTAL API KEY:",
            font=('Courier', 10, 'bold'),
            fg='#00ff00',
            bg='#000000'
        ).pack(anchor='w')
        
        self.api_key_entry = tk.Entry(
            api_frame,
            font=('Courier', 11),
            bg='#111111',
            fg='#00ff00',
            insertbackground='#00ff00',
            relief='solid',
            bd=1,
            show='*'
        )
        self.api_key_entry.pack(fill=tk.X, pady=5)
        
        # Control Buttons
        button_frame = tk.Frame(self.root, bg='#000000')
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.scan_button = tk.Button(
            button_frame,
            text="🔥 INITIATE SCAN 🔥",
            font=('Courier', 12, 'bold'),
            bg='#330000',
            fg='#ff0000',
            activebackground='#660000',
            activeforeground='#ff0000',
            relief='raised',
            bd=3,
            command=self.start_scan,
            cursor='cross'
        )
        self.scan_button.pack(side=tk.LEFT, padx=10)
        
        self.clear_button = tk.Button(
            button_frame,
            text="💣 CLEAR ALL 💣",
            font=('Courier', 12, 'bold'),
            bg='#003300',
            fg='#00ff00',
            activebackground='#006600',
            activeforeground='#00ff00',
            relief='raised',
            bd=3,
            command=self.clear_all,
            cursor='cross'
        )
        self.clear_button.pack(side=tk.LEFT, padx=10)
        
        # Progress and Status
        self.progress = ttk.Progressbar(
            self.root,
            mode='indeterminate',
            length=400
        )
        self.progress.pack(pady=10)
        
        self.status_label = tk.Label(
            self.root,
            text="[SYSTEM] READY FOR PENETRATION TEST",
            font=('Courier', 10),
            fg='#00ff00',
            bg='#000000'
        )
        self.status_label.pack(pady=5)
        
        # Hacker Animation
        self.hacker_display = tk.Label(
            self.root,
            text="",
            font=('Courier', 8),
            fg='#00ff00',
            bg='#000000'
        )
        self.hacker_display.pack(pady=5)
        
        # Results Area
        results_frame = tk.LabelFrame(
            self.root,
            text="📊 SCAN RESULTS",
            font=('Courier', 12, 'bold'),
            fg='#00ff00',
            bg='#000000',
            relief='groove',
            bd=2
        )
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=('Courier', 9),
            bg='#111111',
            fg='#00ff00',
            insertbackground='#00ff00',
            wrap=tk.WORD,
            height=15
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Footer
        footer_label = tk.Label(
            self.root,
            text="💀 HACK THE PLANET 💀",
            font=('Courier', 10, 'bold'),
            fg='#ff0000',
            bg='#000000'
        )
        footer_label.pack(pady=5)
        
    def hacker_animation(self):
        """Display hacker-style animation during scan"""
        animations = [
            "[█▒▒▒▒▒▒▒▒▒] INITIATING SCAN...",
            "[███▒▒▒▒▒▒▒] CONNECTING TO TARGET...",
            "[█████▒▒▒▒▒] ANALYZING SECURITY...",
            "[███████▒▒▒] DETECTING VULNERABILITIES...",
            "[██████████] SCAN COMPLETE!"
        ]
        
        for animation in animations:
            self.root.after(0, lambda a=animation: self.hacker_display.config(text=a))
            time.sleep(0.8)
            
    def real_virus_check(self, url):
        """Check URL using VirusTotal API"""
        api_key = self.api_key_entry.get().strip()
        if not api_key:
            return {"error": "API key required for VirusTotal scan"}
            
        scan_url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': api_key, 'resource': url}
        try:
            response = requests.get(scan_url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {"error": f"API Error: {str(e)}"}
        
    def start_scan(self):
        """Start the scanning process"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("ERROR", "TARGET URL REQUIRED")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Start scanning in background
        self.scan_button.config(state='disabled')
        self.status_label.config(text="[SYSTEM] SCANNING IN PROGRESS...")
        self.progress.start()
        
        scan_thread = threading.Thread(target=self.perform_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def perform_scan(self, url):
        """Perform the actual scanning"""
        try:
            # Show hacker animation
            animation_thread = threading.Thread(target=self.hacker_animation)
            animation_thread.daemon = True
            animation_thread.start()
            
            # Scan for vulnerabilities
            vuln_issues = self.scan_vulnerabilities(url)
            
            # Check with VirusTotal
            vt_result = self.real_virus_check(url)
            
            # Update GUI
            self.root.after(0, self.display_results, vuln_issues, vt_result)
            
        except Exception as e:
            self.root.after(0, self.show_error, str(e))
            
    def scan_vulnerabilities(self, url):
        """Basic vulnerability scanning"""
        try:
            response = requests.get(url, timeout=15)
            headers = response.headers
            body = response.text.lower()
            
            issues = []
            
            # Security checks
            if 'x-powered-by' in headers:
                issues.append(f"[X] TECHNOLOGY DISCLOSURE: {headers['x-powered-by']}")
                
            if 'server' in headers:
                issues.append(f"[X] SERVER INFO EXPOSED: {headers['server']}")
                
            if 'access-control-allow-origin' in headers:
                if headers['access-control-allow-origin'] == '*':
                    issues.append("[X] CORS MISCONFIGURATION DETECTED")
                    
            if any(keyword in body for keyword in ['xss', '<script>', 'alert(']):
                issues.append("[X] POSSIBLE XSS VULNERABILITY")
                
            if 'sql syntax' in body or 'mysql_fetch' in body:
                issues.append("[X] POSSIBLE SQL INJECTION")
                
            return issues
        except Exception as e:
            return [f"[X] SCAN ERROR: {str(e)}"]
            
    def display_results(self, vuln_issues, vt_result):
        """Display scan results"""
        self.progress.stop()
        self.scan_button.config(state='normal')
        self.status_label.config(text="[SYSTEM] SCAN COMPLETED")
        self.hacker_display.config(text="[█] SCANNING COMPLETE")
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        
        # Display header
        self.results_text.insert(tk.END, "="*70 + "\n")
        self.results_text.insert(tk.END, "💀 HACKER SCAN REPORT 💀\n")
        self.results_text.insert(tk.END, "="*70 + "\n\n")
        
        # Vulnerability Results
        self.results_text.insert(tk.END, "🔍 VULNERABILITY ANALYSIS:\n")
        self.results_text.insert(tk.END, "-"*40 + "\n")
        
        if vuln_issues:
            for issue in vuln_issues:
                self.results_text.insert(tk.END, f"{issue}\n")
        else:
            self.results_text.insert(tk.END, "✅ NO VULNERABILITIES DETECTED\n")
            
        self.results_text.insert(tk.END, "\n")
        
        # VirusTotal Results
        self.results_text.insert(tk.END, "🦠 VIRUS TOTAL ANALYSIS:\n")
        self.results_text.insert(tk.END, "-"*40 + "\n")
        
        if 'error' in vt_result:
            self.results_text.insert(tk.END, f"[X] {vt_result['error']}\n")
        elif 'positives' in vt_result:
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            if positives > 0:
                self.results_text.insert(tk.END, f"🔴 TARGET IS MALICIOUS: {positives}/{total} ENGINES DETECTED\n")
                self.results_text.insert(tk.END, f"📊 DETECTION RATIO: {positives}/{total}\n")
            else:
                self.results_text.insert(tk.END, f"✅ TARGET IS CLEAN: 0/{total} ENGINES DETECTED\n")
        else:
            self.results_text.insert(tk.END, "⚠️  NO VIRUS TOTAL DATA AVAILABLE\n")
            
        # Footer
        self.results_text.insert(tk.END, "\n" + "="*70 + "\n")
        self.results_text.insert(tk.END, "💀 SCAN COMPLETE - HACK THE PLANET 💀\n")
        self.results_text.see(tk.END)
        
    def show_error(self, error_msg):
        """Show error message"""
        self.progress.stop()
        self.scan_button.config(state='normal')
        self.status_label.config(text="[SYSTEM] SCAN FAILED")
        messagebox.showerror("SCAN ERROR", f"AN ERROR OCCURRED:\n{error_msg}")
        
    def clear_all(self):
        """Clear all fields"""
        self.url_entry.delete(0, tk.END)
        self.api_key_entry.delete(0, tk.END)
        self.results_text.delete(1.0, tk.END)
        self.status_label.config(text="[SYSTEM] READY FOR PENETRATION TEST")
        self.hacker_display.config(text="")
        self.url_entry.insert(0, "https://example.com")

def main():
    root = tk.Tk()
    app = HackerVulnScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()