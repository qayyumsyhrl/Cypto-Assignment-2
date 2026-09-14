"""
stego_gui.py — LSB Steganography Studio (GUI version)

A simple point-and-click app for hiding and extracting secret files inside
images, plus a built-in visual analysis tool.

Requires: pillow, numpy, matplotlib  (tkinter ships with Python already)
    pip install pillow numpy matplotlib

Run:
    python stego_gui.py
"""

import os
import io
import struct
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from PIL import Image, ImageTk
import numpy as np
import matplotlib
matplotlib.use("Agg")  # render off-screen, we display via PIL/Tkinter
import matplotlib.pyplot as plt


# =====================================================================
# CORE STEGANOGRAPHY LOGIC (same LSB technique as before)
# =====================================================================
MAGIC = b"STG1"


def _bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    pad = (-len(bits)) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(bits).tobytes()


def hide_data(cover_path, secret_path, output_path):
    img = Image.open(cover_path).convert("RGB")
    arr = np.array(img)

    filename = os.path.basename(secret_path).encode("utf-8")
    with open(secret_path, "rb") as f:
        secret_bytes = f.read()

    payload = MAGIC
    payload += struct.pack(">H", len(filename))
    payload += filename
    payload += struct.pack(">Q", len(secret_bytes))
    payload += secret_bytes

    bits = _bytes_to_bits(payload)
    capacity_bits = arr.size
    if len(bits) > capacity_bits:
        raise ValueError(
            f"Secret file too large for this cover image.\n\n"
            f"Needs: {len(bits)//8:,} bytes\n"
            f"Cover image capacity: {capacity_bits//8:,} bytes\n\n"
            f"Use a larger cover image or a smaller secret file."
        )

    flat = arr.flatten().copy()
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    stego_arr = flat.reshape(arr.shape).astype(np.uint8)
    Image.fromarray(stego_arr, mode="RGB").save(output_path, format="PNG")

    return {
        "payload_bytes": len(payload),
        "capacity_bytes": capacity_bits // 8,
        "percent_used": len(payload) / (capacity_bits // 8) * 100,
    }


def extract_data(stego_path):
    """Returns (filename, file_bytes) recovered from the stego image."""
    img = Image.open(stego_path).convert("RGB")
    arr = np.array(img)
    all_bits = arr.flatten() & 1

    header1 = _bits_to_bytes(all_bits[:48])
    if header1[:4] != MAGIC:
        raise ValueError("No hidden file found in this image (signature mismatch).")

    filename_len = struct.unpack(">H", header1[4:6])[0]
    total_header_bytes = 4 + 2 + filename_len + 8
    header2 = _bits_to_bytes(all_bits[:total_header_bytes * 8])

    filename = header2[6:6 + filename_len].decode("utf-8")
    data_len = struct.unpack(">Q", header2[6 + filename_len:6 + filename_len + 8])[0]

    total_bytes = total_header_bytes + data_len
    payload = _bits_to_bytes(all_bits[:total_bytes * 8])
    data = payload[total_header_bytes:total_header_bytes + data_len]

    return filename, data


def build_analysis_image(cover_path, stego_path):
    """Builds the 6-panel analysis chart and returns it as a PIL Image."""
    cover_img = Image.open(cover_path).convert("RGB")
    stego_img = Image.open(stego_path).convert("RGB")
    cover_arr = np.array(cover_img)
    stego_arr = np.array(stego_img)

    diff = np.abs(cover_arr.astype(int) - stego_arr.astype(int))
    changed_pixels = np.any(diff > 0, axis=-1).sum()
    total_pixels = cover_arr.shape[0] * cover_arr.shape[1]

    cover_size = os.path.getsize(cover_path)
    stego_size = os.path.getsize(stego_path)

    fig, axes = plt.subplots(2, 3, figsize=(13, 8))

    axes[0, 0].imshow(cover_img); axes[0, 0].set_title(f"Cover\n{cover_size:,} bytes"); axes[0, 0].axis("off")
    axes[0, 1].imshow(stego_img); axes[0, 1].set_title(f"Stego\n{stego_size:,} bytes"); axes[0, 1].axis("off")

    diff_vis = np.clip(diff.astype(int) * 60, 0, 255).astype(np.uint8)
    axes[0, 2].imshow(diff_vis)
    axes[0, 2].set_title(f"Diff (amplified 60x)\n{changed_pixels:,}/{total_pixels:,} px changed")
    axes[0, 2].axis("off")

    for i, c in enumerate(["red", "green", "blue"]):
        axes[1, 0].hist(cover_arr[:, :, i].flatten(), bins=256, range=(0, 255), color=c, alpha=0.5, label=c.upper())
    axes[1, 0].set_title("Cover Histogram"); axes[1, 0].legend()

    for i, c in enumerate(["red", "green", "blue"]):
        axes[1, 1].hist(stego_arr[:, :, i].flatten(), bins=256, range=(0, 255), color=c, alpha=0.5, label=c.upper())
    axes[1, 1].set_title("Stego Histogram"); axes[1, 1].legend()

    axes[1, 2].hist(cover_arr.flatten(), bins=256, range=(0, 255), color="black", alpha=0.5, label="Cover")
    axes[1, 2].hist(stego_arr.flatten(), bins=256, range=(0, 255), color="orange", alpha=0.5, label="Stego")
    axes[1, 2].set_title("Overlay"); axes[1, 2].legend()

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110)
    plt.close(fig)
    buf.seek(0)
    return Image.open(buf), changed_pixels, total_pixels, cover_size, stego_size


# =====================================================================
# GUI APP
# =====================================================================
BG = "#1e1f26"
CARD = "#2a2c38"
ACCENT = "#7c5cff"
ACCENT_HOVER = "#9078ff"
TEXT = "#f2f2f7"
SUBTEXT = "#a0a0b0"
GOOD = "#4ade80"
BAD = "#f87171"


class StegoApp:
    def __init__(self, root):
        self.root = root
        root.title("Steganography Tool")
        root.geometry("760x640")
        root.configure(bg=BG)
        root.minsize(700, 600)

        self.cover_path = None
        self.secret_path = None
        self.stego_path = None
        self.analysis_cover_path = None

        self._setup_style()
        self._build_layout()

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=CARD, foreground=TEXT,
                         padding=(20, 10), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", ACCENT)])
        style.configure("TFrame", background=BG)

    def _build_layout(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=24, pady=(20, 10))
        tk.Label(header, text="🔐 Steganography Tool", font=("Segoe UI", 18, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w")

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=24, pady=10)

        hide_tab = tk.Frame(notebook, bg=BG)
        extract_tab = tk.Frame(notebook, bg=BG)
        notebook.add(hide_tab, text="  🔒  Hide  ")
        notebook.add(extract_tab, text="  🔓  Extract & Analyze  ")

        self._build_hide_tab(hide_tab)
        self._build_extract_tab(extract_tab)

    # ---------------- Reusable widgets ----------------
    def _card(self, parent, title):
        card = tk.Frame(parent, bg=CARD, highlightthickness=0)
        card.pack(fill="x", pady=8, padx=2)
        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill="x", padx=16, pady=14)
        tk.Label(inner, text=title, font=("Segoe UI", 11, "bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        return inner

    def _button(self, parent, text, command, primary=False):
        bg = ACCENT if primary else "#3a3c4a"
        btn = tk.Button(parent, text=text, command=command, bg=bg, fg=TEXT,
                         activebackground=ACCENT_HOVER, activeforeground=TEXT,
                         font=("Segoe UI", 10, "bold"), relief="flat",
                         padx=16, pady=8, cursor="hand2", borderwidth=0)
        return btn

    def _thumb(self, parent):
        lbl = tk.Label(parent, bg=CARD, fg=SUBTEXT, text="No image selected",
                        font=("Segoe UI", 8), width=18, height=8, relief="flat")
        return lbl

    def _set_thumb(self, label, path):
        img = Image.open(path).convert("RGB")
        img.thumbnail((150, 150))
        photo = ImageTk.PhotoImage(img)
        label.configure(image=photo, text="", width=150, height=150)
        label.image = photo  # keep reference

    # ---------------- HIDE TAB ----------------
    def _build_hide_tab(self, parent):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x")

        # --- Cover image card ---
        c1 = self._card(row, "1. Cover Image")
        c1.master.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.cover_thumb = self._thumb(c1)
        self.cover_thumb.pack(pady=8)
        self.cover_label = tk.Label(c1, text="No file chosen", bg=CARD, fg=SUBTEXT, font=("Segoe UI", 8))
        self.cover_label.pack(anchor="w")
        self._button(c1, "Choose Cover Image", self.choose_cover).pack(fill="x", pady=(8, 0))

        # --- Secret file card ---
        c2 = self._card(row, "2. Secret File")
        c2.master.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(c2, text="📄", font=("Segoe UI", 40), bg=CARD, fg=SUBTEXT).pack(pady=8)
        self.secret_label = tk.Label(c2, text="No file chosen", bg=CARD, fg=SUBTEXT, font=("Segoe UI", 8), wraplength=200)
        self.secret_label.pack(anchor="w")
        self._button(c2, "Choose Secret File", self.choose_secret).pack(fill="x", pady=(8, 0))
        tk.Label(c2, text="Any file type works: .txt .pdf .doc .png .jpg …",
                 bg=CARD, fg=SUBTEXT, font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 0))

        # --- Action card ---
        c3 = self._card(parent, "3. Create Stego Image")
        self._button(c3, "🔒  Hide Secret & Save Stego Image", self.run_hide, primary=True).pack(fill="x", pady=(8, 0))
        self.hide_status = tk.Label(c3, text="", bg=CARD, fg=SUBTEXT, font=("Segoe UI", 9), justify="left")
        self.hide_status.pack(anchor="w", pady=(10, 0))

    def choose_cover(self):
        path = filedialog.askopenfilename(title="Choose Cover Image",
                                           filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if path:
            self.cover_path = path
            self.cover_label.configure(text=os.path.basename(path))
            self._set_thumb(self.cover_thumb, path)

    def choose_secret(self):
        path = filedialog.askopenfilename(title="Choose Secret File")
        if path:
            self.secret_path = path
            size = os.path.getsize(path)
            self.secret_label.configure(text=f"{os.path.basename(path)}\n({size:,} bytes)")

    def run_hide(self):
        if not self.cover_path or not self.secret_path:
            messagebox.showwarning("Missing files", "Please choose both a cover image and a secret file first.")
            return
        out_path = filedialog.asksaveasfilename(title="Save Stego Image As", defaultextension=".png",
                                                  initialfile="stego.png", filetypes=[("PNG image", "*.png")])
        if not out_path:
            return
        try:
            stats = hide_data(self.cover_path, self.secret_path, out_path)
            self.stego_path = out_path
            self.hide_status.configure(
                fg=GOOD,
                text=(f"✅ Success! Saved to {os.path.basename(out_path)}\n"
                      f"Used {stats['payload_bytes']:,} of {stats['capacity_bytes']:,} available bytes "
                      f"({stats['percent_used']:.3f}%)")
            )
        except Exception as e:
            self.hide_status.configure(fg=BAD, text=f"❌ Error: {e}")

    # ---------------- EXTRACT / ANALYZE TAB ----------------
    def _build_extract_tab(self, parent):
        c1 = self._card(parent, "1. Choose Stego Image")
        self.stego_thumb = self._thumb(c1)
        self.stego_thumb.pack(pady=8)
        self.stego_label = tk.Label(c1, text="No file chosen", bg=CARD, fg=SUBTEXT, font=("Segoe UI", 8))
        self.stego_label.pack(anchor="w")
        self._button(c1, "Choose Stego Image", self.choose_stego).pack(fill="x", pady=(8, 0))

        c2 = self._card(parent, "2. Extract Hidden File")
        self._button(c2, "🔓  Extract & Save Hidden File", self.run_extract, primary=True).pack(fill="x", pady=(8, 0))
        self.extract_status = tk.Label(c2, text="", bg=CARD, fg=SUBTEXT, font=("Segoe UI", 9), justify="left")
        self.extract_status.pack(anchor="w", pady=(10, 0))

        c3 = self._card(parent, "3. Visual & File Size Analysis (optional)")
        tk.Label(c3, text="Pick the original cover image to compare against the stego image above.",
                 bg=CARD, fg=SUBTEXT, font=("Segoe UI", 8), wraplength=600, justify="left").pack(anchor="w")
        row = tk.Frame(c3, bg=CARD)
        row.pack(fill="x", pady=(8, 0))
        self._button(row, "Choose Original Cover Image", self.choose_analysis_cover).pack(side="left")
        self.analysis_cover_label = tk.Label(row, text="No file chosen", bg=CARD, fg=SUBTEXT, font=("Segoe UI", 8))
        self.analysis_cover_label.pack(side="left", padx=10)
        self._button(c3, "📊  Run Analysis", self.run_analysis).pack(fill="x", pady=(10, 0))
        self.analysis_status = tk.Label(c3, text="", bg=CARD, fg=SUBTEXT, font=("Segoe UI", 9), justify="left")
        self.analysis_status.pack(anchor="w", pady=(8, 0))

    def choose_stego(self):
        path = filedialog.askopenfilename(title="Choose Stego Image", filetypes=[("PNG image", "*.png")])
        if path:
            self.stego_path = path
            self.stego_label.configure(text=os.path.basename(path))
            self._set_thumb(self.stego_thumb, path)

    def choose_analysis_cover(self):
        path = filedialog.askopenfilename(title="Choose Original Cover Image",
                                           filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if path:
            self.analysis_cover_path = path
            self.analysis_cover_label.configure(text=os.path.basename(path))

    def run_extract(self):
        if not self.stego_path:
            messagebox.showwarning("Missing file", "Please choose a stego image first.")
            return
        try:
            filename, data = extract_data(self.stego_path)
            out_path = filedialog.asksaveasfilename(title="Save Recovered File As",
                                                      initialfile=filename)
            if not out_path:
                return
            with open(out_path, "wb") as f:
                f.write(data)
            self.extract_status.configure(
                fg=GOOD, text=f"✅ Recovered '{filename}' ({len(data):,} bytes)\nSaved to {out_path}")
        except Exception as e:
            self.extract_status.configure(fg=BAD, text=f"❌ Error: {e}")

    def run_analysis(self):
        if not self.stego_path or not self.analysis_cover_path:
            messagebox.showwarning("Missing files", "Please choose both the stego image and the original cover image.")
            return
        try:
            img, changed, total, cover_size, stego_size = build_analysis_image(
                self.analysis_cover_path, self.stego_path)
            self.analysis_status.configure(
                fg=GOOD,
                text=(f"✅ {changed:,}/{total:,} pixels changed ({changed/total*100:.2f}%) — invisible to the eye\n"
                      f"Cover: {cover_size:,} bytes | Stego: {stego_size:,} bytes")
            )
            self._show_analysis_window(img)
        except Exception as e:
            self.analysis_status.configure(fg=BAD, text=f"❌ Error: {e}")

    def _show_analysis_window(self, pil_img):
        win = tk.Toplevel(self.root)
        win.title("Analysis Report")
        win.configure(bg=BG)
        screen_w = win.winfo_screenwidth()
        max_w = min(1100, screen_w - 100)
        ratio = max_w / pil_img.width
        display_img = pil_img.resize((max_w, int(pil_img.height * ratio)))
        photo = ImageTk.PhotoImage(display_img)
        lbl = tk.Label(win, image=photo, bg=BG)
        lbl.image = photo
        lbl.pack(padx=10, pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()
