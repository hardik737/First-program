import urllib.request
import urllib.parse
import json
import csv
import datetime
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

TIMEOUT = 5

def read_url(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SimpleCloudAuditor"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            code = resp.getcode()
            text = resp.read().decode("utf-8", errors="ignore")
            return code, text
    except Exception:
        return None, None

def classify_url(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    if "s3" in host:
        return "s3"
    elif "blob.core.windows.net" in host:
        return "azure"
    else:
        return "unknown"

def write_test(url):
    try:
        data = b"Test file from SimpleCloudAuditor"
        req = urllib.request.Request(url + "/auditor_test.txt", data=data, method="PUT")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.getcode() in (200, 201)
    except Exception:
        return False

def scan_bucket(url, enable_write=False, confirm_text=""):
    result = {
        "url": url,
        "provider": classify_url(url),
        "public_read": False,
        "listing_enabled": False,
        "write_allowed": False,
        "http_status": None,
        "risk_level": "Unknown"
    }
    status, text = read_url(url)
    result["http_status"] = status
    if status == 200:
        result["public_read"] = True
    if text:
        txt = text.lower()
        if "listbucketresult" in txt or "enumerationresults" in txt or "index of" in txt:
            result["listing_enabled"] = True
            result["public_read"] = True
    if enable_write and confirm_text == "ALLOW-WRITE-TEST":
        if write_test(url):
            result["write_allowed"] = True
    score = 0
    if result["public_read"]:
        score += 2
    if result["listing_enabled"]:
        score += 2
    if result["write_allowed"]:
        score += 5
    if score >= 7:
        result["risk_level"] = "Critical"
    elif score >= 4:
        result["risk_level"] = "High"
    elif score >= 2:
        result["risk_level"] = "Medium"
    else:
        result["risk_level"] = "Low"
    return result

def save_report(results):
    outdir = filedialog.askdirectory(title="Select folder to save reports")
    if not outdir:
        return
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(outdir, f"report_{ts}.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    keys = ["url", "provider", "public_read", "listing_enabled", "write_allowed", "http_status", "risk_level"]
    with open(os.path.join(outdir, f"report_{ts}.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(results)
    messagebox.showinfo("Saved", f"Reports saved in: {outdir}")

class AuditorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Cloud Bucket Auditor")
        self.geometry("950x550")
        self.results = []
        self._build_ui()
    def _build_ui(self):
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Paste URLs (one per line):").pack(anchor="w")
        self.text_urls = tk.Text(frm, height=8)
        self.text_urls.insert("1.0",
            "https://safe-bucket.s3.amazonaws.com      \n"
            "https://public-open.s3.amazonaws.com       \n"
            "https://listing.blob.core.windows.net/container   \n"
            "https://dangerous-public-bucket.s3.amazonaws.com  \n"
        )
        self.text_urls.pack(fill="x", pady=5)
        self.write_var = tk.BooleanVar()
        self.chk_write = ttk.Checkbutton(frm, text="Enable write test (DANGEROUS)", variable=self.write_var)
        self.chk_write.pack(anchor="w")
        ttk.Label(frm, text="Type 'ALLOW-WRITE-TEST' to confirm write test:").pack(anchor="w")
        self.entry_confirm = ttk.Entry(frm)
        self.entry_confirm.pack(fill="x", pady=3)
        btnfrm = ttk.Frame(frm)
        btnfrm.pack(fill="x", pady=5)
        ttk.Button(btnfrm, text="Scan", command=self.on_scan).pack(side="left", padx=4)
        ttk.Button(btnfrm, text="Save Report", command=self.on_save).pack(side="left", padx=4)
        ttk.Button(btnfrm, text="Clear", command=self.on_clear).pack(side="left", padx=4)
        cols = ("url", "provider", "public_read", "listing_enabled", "write_allowed", "http_status", "risk_level")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=15)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=130, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=5)
    def on_scan(self):
        raw = self.text_urls.get("1.0", "end").strip()
        if not raw:
            messagebox.showwarning("No input", "Please enter at least one URL.")
            return
        urls = [line.split("#")[0].strip() for line in raw.splitlines() if line.strip()]
        self.results = []
        self.tree.delete(*self.tree.get_children())
        enable_write = self.write_var.get()
        confirm_text = self.entry_confirm.get().strip()
        for u in urls:
            r = scan_bucket(u, enable_write, confirm_text)
            self.results.append(r)
            self.tree.insert("", "end", values=(
                r["url"], r["provider"], r["public_read"], r["listing_enabled"],
                r["write_allowed"], r["http_status"], r["risk_level"]
            ))
    def on_save(self):
        if not self.results:
            messagebox.showinfo("No data", "Please scan first before saving.")
            return
        save_report(self.results)
    def on_clear(self):
        self.results = []
        self.tree.delete(*self.tree.get_children())

def main():
    app = AuditorGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
