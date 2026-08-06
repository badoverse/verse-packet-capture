import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from scapy.all import conf
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff

# --- UI COLOR PALETTE ---
BG = "#1e1f26"
PANEL = "#262832"
ACCENT = "#5b9df9"
TEXT = "#e6e6e6"
SUBTEXT = "#9aa0ab"
ROW_ALT = "#2a2c37"

PROTO_OPTIONS = ["ALL", "TCP", "UDP", "ICMP", "ARP", "OTHER"]


class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Verse Packet Capture")
        self.root.geometry("1150x720")
        self.root.configure(bg=BG)

        self.sniff_thread = None
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue()
        self.packet_count = 0
        self.all_rows = []

        self._build_style()
        self._build_ui()
        self._refresh_interfaces()
        self._poll_queue()

    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabelframe", background=BG, foreground=SUBTEXT, borderwidth=0)
        style.configure("TLabelframe.Label", background=BG, foreground=SUBTEXT, font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background=BG, foreground=SUBTEXT, font=("Segoe UI", 10))

        style.configure("TButton", background=PANEL, foreground=TEXT, borderwidth=0,
                        padding=(14, 8), font=("Segoe UI", 10, "bold"))
        style.map("TButton",
                  background=[("active", ACCENT), ("disabled", PANEL)],
                  foreground=[("disabled", SUBTEXT)])

        style.configure("Accent.TButton", background=ACCENT, foreground="#0d0d0d")
        style.map("Accent.TButton", background=[("active", "#78b0ff"), ("disabled", PANEL)])

        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, borderwidth=0,
                        insertcolor=TEXT, padding=6)
        style.configure("TCombobox", fieldbackground=PANEL, background=PANEL, foreground=TEXT,
                        arrowcolor=TEXT, borderwidth=0, padding=6)

        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        borderwidth=0, rowheight=26, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=BG, foreground=SUBTEXT,
                        font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#0d0d0d")])
        style.map("Treeview.Heading", background=[("active", BG)])

        style.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BG, borderwidth=0, arrowsize=12)

    def _build_ui(self):
        # Top toolbar frame
        top = ttk.Frame(self.root, padding=(16, 14))
        top.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top, text="INTERFACE").grid(row=0, column=0, sticky="w")
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(top, textvariable=self.iface_var, width=28, state="readonly")
        self.iface_combo.grid(row=1, column=0, sticky="w", padx=(0, 20), pady=(2, 0))

        ttk.Label(top, text="BPF FILTER").grid(row=0, column=1, sticky="w")
        self.filter_var = tk.StringVar(value="ip or arp")
        self.filter_var.trace_add("write", self._force_lowercase_filter)
        filter_entry = ttk.Entry(top, textvariable=self.filter_var, width=28)
        filter_entry.grid(row=1, column=1, sticky="w", padx=(0, 20), pady=(2, 0))

        btns = ttk.Frame(top)
        btns.grid(row=1, column=2, sticky="w")
        self.start_btn = ttk.Button(btns, text="▶  Start", style="Accent.TButton", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.stop_btn = ttk.Button(btns, text="■  Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.clear_btn = ttk.Button(btns, text="Clear", command=self.clear_table)
        self.clear_btn.pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="● idle")
        ttk.Label(top, textvariable=self.status_var, foreground=SUBTEXT).grid(
            row=0, column=3, rowspan=2, sticky="e", padx=(20, 0)
        )
        top.columnconfigure(3, weight=1)

        # Search/Filter Bar
        search_bar = ttk.Frame(self.root, padding=(16, 0, 16, 10))
        search_bar.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(search_bar, text="SEARCH").grid(row=0, column=0, sticky="w")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filters())
        search_entry = ttk.Entry(search_bar, textvariable=self.search_var, width=30)
        search_entry.grid(row=1, column=0, sticky="w", padx=(0, 16), pady=(2, 0))

        ttk.Label(search_bar, text="PROTOCOL").grid(row=0, column=1, sticky="w")
        self.proto_filter_var = tk.StringVar(value="ALL")
        proto_combo = ttk.Combobox(search_bar, textvariable=self.proto_filter_var, values=PROTO_OPTIONS,
                                   width=10, state="readonly")
        proto_combo.grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(2, 0))
        proto_combo.bind("<<ComboboxSelected>>", lambda *_: self._apply_filters())

        ttk.Label(search_bar, text="IP").grid(row=0, column=2, sticky="w")
        self.ip_filter_var = tk.StringVar()
        self.ip_filter_var.trace_add("write", lambda *_: self._apply_filters())
        ttk.Entry(search_bar, textvariable=self.ip_filter_var, width=18).grid(
            row=1, column=2, sticky="w", padx=(0, 16), pady=(2, 0))

        ttk.Label(search_bar, text="PORT").grid(row=0, column=3, sticky="w")
        self.port_filter_var = tk.StringVar()
        self.port_filter_var.trace_add("write", lambda *_: self._apply_filters())
        ttk.Entry(search_bar, textvariable=self.port_filter_var, width=10).grid(
            row=1, column=3, sticky="w", padx=(0, 16), pady=(2, 0))

        reset_btn = ttk.Button(search_bar, text="Reset filters", command=self._reset_filters)
        reset_btn.grid(row=1, column=4, sticky="w")

        self.match_count_var = tk.StringVar(value="")
        ttk.Label(search_bar, textvariable=self.match_count_var, foreground=SUBTEXT).grid(
            row=0, column=5, rowspan=2, sticky="e"
        )
        search_bar.columnconfigure(5, weight=1)

        # Packet Table
        table_wrap = ttk.Frame(self.root, padding=(16, 0))
        table_wrap.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        columns = ("no", "time", "proto", "src", "dst", "sport", "dport", "length", "info")
        self.tree = ttk.Treeview(table_wrap, columns=columns, show="headings", height=16)
        headings = {
            "no": ("No.", 50),
            "time": ("Time", 90),
            "proto": ("Protocol", 80),
            "src": ("Source", 160),
            "dst": ("Destination", 160),
            "sport": ("SPort", 60),
            "dport": ("DPort", 60),
            "length": ("Length", 60),
            "info": ("Info", 320),
        }
        for col, (label, width) in headings.items():
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor=tk.W)

        vsb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.tag_configure("odd", background=PANEL)
        self.tree.tag_configure("even", background=ROW_ALT)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Packet Detail View
        detail_frame = ttk.LabelFrame(self.root, text="PACKET DETAIL", padding=10)
        detail_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=False, padx=16, pady=16)
        self.detail_text = tk.Text(detail_frame, height=12, wrap="none", font=("Consolas", 9),
                                   bg=PANEL, fg=TEXT, insertbackground=TEXT, borderwidth=0,
                                   highlightthickness=0)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_vsb = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_vsb.set)
        detail_vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _force_lowercase_filter(self, *_args):
        current = self.filter_var.get()
        lowered = current.lower()
        if current != lowered:
            self.filter_var.set(lowered)

    def _refresh_interfaces(self):
        """Detect active interfaces based on routing table and active IPs."""
        interfaces = []

        # 1. Parse active default gateway interface from routing table
        try:
            route_output = subprocess.check_output(["ip", "route"], text=True)
            for line in route_output.splitlines():
                if line.startswith("default"):
                    match = re.search(r"dev\s+(\S+)", line)
                    if match:
                        default_iface = match.group(1)
                        if default_iface not in interfaces:
                            interfaces.append(default_iface)
                else:
                    match = re.search(r"dev\s+(\S+)", line)
                    if match:
                        iface = match.group(1)
                        if iface not in interfaces and iface != "lo":
                            interfaces.append(iface)
        except Exception:
            pass

        # 2. Add assigned IP interfaces
        try:
            addr_output = subprocess.check_output(["ip", "-o", "addr"], text=True)
            for line in addr_output.splitlines():
                match = re.match(r"\d+:\s+(\S+).*inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    iface = match.group(1)
                    if iface not in interfaces and iface != "lo":
                        interfaces.append(iface)
        except Exception:
            pass

        # 3. Fallback to Scapy internal interface list
        if not interfaces:
            try:
                scapy_iface = conf.iface.name if hasattr(conf.iface, "name") else str(conf.iface)
                if scapy_iface:
                    interfaces.append(scapy_iface)
            except Exception:
                pass

        self.iface_combo["values"] = interfaces
        if interfaces:
            self.iface_combo.current(0)

    def start_capture(self):
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showwarning("No interface", "Please select a network interface.")
            return

        bpf_filter = self.filter_var.get().strip().lower() or None
        self.stop_event.clear()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"● capturing on {iface}")

        self.sniff_thread = threading.Thread(
            target=self._sniff_worker, args=(iface, bpf_filter), daemon=True
        )
        self.sniff_thread.start()

    def stop_capture(self):
        self.stop_event.set()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("● idle")

    def clear_table(self):
        self.tree.delete(*self.tree.get_children())
        self.detail_text.delete("1.0", tk.END)
        self.all_rows.clear()
        self.packet_count = 0
        self._update_match_count(0)

    def _reset_filters(self):
        self.search_var.set("")
        self.ip_filter_var.set("")
        self.port_filter_var.set("")
        self.proto_filter_var.set("ALL")
        self._apply_filters()

    def _sniff_worker(self, iface, bpf_filter):
        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=lambda pkt: self.packet_queue.put(pkt),
                store=False,
                stop_filter=lambda pkt: self.stop_event.is_set(),
            )
        except PermissionError:
            self.packet_queue.put(
                PermissionError("Insufficient raw socket permissions. Run as root/sudo.")
            )
        except Exception as e:
            self.packet_queue.put(e)
        finally:
            self.root.after(0, lambda: self.status_var.set("● idle"))
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))

    def _poll_queue(self):
        try:
            while True:
                item = self.packet_queue.get_nowait()
                if isinstance(item, Exception):
                    messagebox.showerror("Capture Error", str(item))
                    continue
                self._register_packet(item)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _register_packet(self, packet):
        self.packet_count += 1
        ts = time.strftime("%H:%M:%S", time.localtime(getattr(packet, "time", time.time())))
        length = len(packet)

        proto, src, dst, sport, dport, info = "OTHER", "-", "-", "-", "-", ""

        if packet.haslayer(ARP):
            arp = packet[ARP]
            proto = "ARP"
            src, dst = arp.psrc, arp.pdst
            op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
            info = f"{op} {dst} (hwsrc {arp.hwsrc})"

        elif packet.haslayer(IP):
            ip = packet[IP]
            src, dst = ip.src, ip.dst
            info = f"ttl={ip.ttl} id={ip.id}"

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                proto = "TCP"
                sport, dport = tcp.sport, tcp.dport
                info = f"flags={tcp.flags} seq={tcp.seq} ack={tcp.ack} win={tcp.window} ttl={ip.ttl}"

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                proto = "UDP"
                sport, dport = udp.sport, udp.dport
                info = f"len={udp.len} ttl={ip.ttl}"

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                proto = "ICMP"
                info = f"type={icmp.type} code={icmp.code} ttl={ip.ttl}"

            else:
                proto = "OTHER"
                info = f"ip_proto={ip.proto} ttl={ip.ttl}"

        row = {
            "no": self.packet_count, "time": ts, "proto": proto,
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "length": length, "info": info, "packet": packet,
        }
        self.all_rows.append(row)

        if self._row_matches(row):
            self._insert_row(row)
        self._update_match_count()

    def _row_matches(self, row):
        search = self.search_var.get().strip().lower()
        proto = self.proto_filter_var.get()
        ip_val = self.ip_filter_var.get().strip().lower()
        port_val = self.port_filter_var.get().strip()

        if proto != "ALL":
            row_proto = row["proto"].upper()
            if proto == "OTHER":
                if row_proto in ("TCP", "UDP", "ICMP", "ARP"):
                    return False
            elif row_proto != proto:
                return False

        if ip_val and ip_val not in str(row["src"]).lower() and ip_val not in str(row["dst"]).lower():
            return False

        if port_val:
            if port_val != str(row["sport"]) and port_val != str(row["dport"]):
                return False

        if search:
            haystack = " ".join(str(v) for k, v in row.items() if k != "packet").lower()
            if search not in haystack:
                return False

        return True

    def _insert_row(self, row):
        tag = "even" if row["no"] % 2 == 0 else "odd"
        iid = str(row["no"])
        self.tree.insert(
            "", tk.END, iid=iid,
            values=(row["no"], row["time"], row["proto"], row["src"], row["dst"],
                    row["sport"], row["dport"], row["length"], row["info"]),
            tags=(tag,),
        )
        self.tree.see(iid)

    def _apply_filters(self):
        self.tree.delete(*self.tree.get_children())
        for row in self.all_rows:
            if self._row_matches(row):
                self._insert_row(row)
        self._update_match_count()

    def _update_match_count(self, shown=None):
        total = len(self.all_rows)
        shown = len(self.tree.get_children()) if shown is None else shown
        self.match_count_var.set(f"{shown} / {total} packets")

    def _on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        row = next((r for r in self.all_rows if str(r["no"]) == sel[0]), None)
        if row is None:
            return
        self.detail_text.delete("1.0", tk.END)
        try:
            detail = row["packet"].show(dump=True)
        except Exception as e:
            detail = f"(could not render detail: {e})"
        self.detail_text.insert(tk.END, detail)


def main():
    # Automatically request root elevation via sudo if not executed with privileges
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Raw socket capture requires root privileges. Elevating process via sudo...")
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"[-] Failed to elevate permissions: {e}")
            sys.exit(1)

    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()