import argparse
import os
import re
import subprocess
import sys
import threading
import queue
from datetime import datetime
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from scapy.all import conf, get_if_list, wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer


# ============================================================
# SECURITY ANALYSIS
# ============================================================

CREDENTIAL_PATTERNS = [
    re.compile(
        rb"(?:username|user|usr|login|pass|password|pwd|authorization)=",
        re.IGNORECASE,
    ),
    re.compile(
        rb"Basic\s+[A-Za-z0-9+/=]+",
        re.IGNORECASE,
    ),
    re.compile(
        rb"Bearer\s+[A-Za-z0-9\-\._~\+/]+=*",
        re.IGNORECASE,
    ),
]

def analyze_selected_packet(self):
    record = self.get_selected_packet()

    if record is None:
        messagebox.showwarning(
            "No Packet Selected",
            "Select a packet from the table first.",
        )
        return

    packet = record["packet"]

    analysis = run_packet_security_analysis(packet)

    self.details_text.configure(
        state="normal"
    )

    self.details_text.delete(
        "1.0",
        "end",
    )

    self.details_text.insert(
        "1.0",
        f"Packet #{record['no']} Security Analysis\n"
        f"{'=' * 60}\n\n"
        f"{analysis}\n\n"
        f"Protocol: {record['proto']}\n"
        f"Source: {record['src']}\n"
        f"Destination: {record['dst']}\n"
        f"Source Port: {record['sport']}\n"
        f"Destination Port: {record['dport']}\n"
        f"Length: {record['length']}\n"
    )

    self.details_text.configure(
        state="disabled"
    )
    
def run_packet_security_analysis(pkt: Packet) -> str:
    """
    Performs lightweight security analysis on one packet.

    This is intentionally heuristic.
    A finding does not automatically mean the packet is malicious.
    """

    findings: List[str] = []

    # --------------------------------------------------------
    # IP packets
    # --------------------------------------------------------

    if pkt.haslayer(IP):

        # ----------------------------------------------------
        # TCP flag anomalies
        # ----------------------------------------------------

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            flags = int(tcp_layer.flags)

            # NULL scan
            if flags == 0:
                findings.append(
                    "[CRITICAL] TCP NULL Scan Flag Set "
                    "(no TCP flags active)"
                )

            # FIN + PSH + URG
            elif flags == 0x29:
                findings.append(
                    "[HIGH] TCP XMAS Scan Flag Set "
                    "(FIN + PSH + URG)"
                )

        # ----------------------------------------------------
        # Cleartext credential/token inspection
        # ----------------------------------------------------

        if pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)

                for pattern in CREDENTIAL_PATTERNS:
                    if pattern.search(payload):
                        findings.append(
                            "[CRITICAL] Potential cleartext "
                            "credentials or authentication token "
                            "found in payload"
                        )
                        break

            except Exception:
                pass

        # ----------------------------------------------------
        # DNS query inspection
        # ----------------------------------------------------

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                raw_qname = pkt[DNSQR].qname

                if isinstance(raw_qname, bytes):
                    qname = raw_qname.decode(
                        "utf-8",
                        errors="ignore",
                    )
                else:
                    qname = str(raw_qname)

                if len(qname) > 60:
                    findings.append(
                        f"[MEDIUM] Suspiciously long DNS query "
                        f"({len(qname)} characters) - "
                        f"potential DNS tunneling"
                    )

            except Exception:
                pass

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    if not findings:
        return (
            "[INFO] No obvious vulnerabilities or scan "
            "patterns were detected in this packet."
        )

    return "\n".join(findings)


# ============================================================
# MAIN GUI
# ============================================================

class PacketSnifferGUI:

    def __init__(
        self,
        root: tk.Tk,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = "ip or arp",
    ):
        self.root = root

        self.interface = interface
        self.bpf_filter = bpf_filter

        self.sniffer: Optional[AsyncSniffer] = None

        self.is_capturing = False
        self.is_paused = False

        self.packet_counter = 0

        self.stats: Dict[str, int] = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "OTHER": 0,
        }

        self.packet_records: List[Dict[str, Any]] = []

        # Packets are stored separately from table rows.
        # Each record contains its corresponding raw packet.
        self.packet_queue: queue.Queue = queue.Queue()

        self.setup_window()
        self.setup_style()
        self.build_gui()
        self.load_interfaces()

        if self.interface:
            self.interface_var.set(self.interface)

        self.filter_var.set(
            self.bpf_filter or ""
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.on_close,
        )

        self.process_packet_queue()

    # ========================================================
    # WINDOW
    # ========================================================

    def setup_window(self):
        self.root.title(
            "Packet Sniffer & Security Analyzer"
        )

        self.root.geometry(
            "1500x900"
        )

        self.root.minsize(
            1100,
            650,
        )

        self.root.configure(
            bg="#101216"
        )

    # ========================================================
    # STYLE
    # ========================================================

    def setup_style(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background="#17191f",
            foreground="#e5e7eb",
            fieldbackground="#17191f",
            rowheight=27,
            borderwidth=0,
        )

        style.map(
            "Treeview",
            background=[
                ("selected", "#315f9e")
            ],
            foreground=[
                ("selected", "#ffffff")
            ],
        )

        style.configure(
            "Treeview.Heading",
            background="#252832",
            foreground="#ffffff",
            font=(
                "TkDefaultFont",
                10,
                "bold",
            ),
            relief="flat",
        )

        style.configure(
            "TButton",
            padding=(
                10,
                6,
            ),
        )

        style.configure(
            "TCombobox",
            padding=5,
        )

    # ========================================================
    # GUI
    # ========================================================

    def build_gui(self):

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        header = tk.Frame(
            self.root,
            bg="#101216",
        )

        header.pack(
            fill="x",
            padx=20,
            pady=15,
        )

        title = tk.Label(
            header,
            text="PACKET SNIFFER",
            bg="#101216",
            fg="#ffffff",
            font=(
                "TkDefaultFont",
                21,
                "bold",
            ),
        )

        title.pack(
            side="left",
        )

        subtitle = tk.Label(
            header,
            text="Security Analyzer",
            bg="#101216",
            fg="#6b7280",
            font=(
                "TkDefaultFont",
                10,
            ),
        )

        subtitle.pack(
            side="left",
            padx=12,
            pady=(8, 0),
        )

        self.status_label = tk.Label(
            header,
            text="● STOPPED",
            bg="#101216",
            fg="#ef4444",
            font=(
                "TkDefaultFont",
                11,
                "bold",
            ),
        )

        self.status_label.pack(
            side="right",
        )

        # ----------------------------------------------------
        # Controls
        # ----------------------------------------------------

        controls = tk.Frame(
            self.root,
            bg="#181a20",
            highlightbackground="#2b2f3a",
            highlightthickness=1,
        )

        controls.pack(
            fill="x",
            padx=20,
            pady=(0, 10),
        )

        # Interface

        tk.Label(
            controls,
            text="Interface",
            bg="#181a20",
            fg="#9ca3af",
        ).grid(
            row=0,
            column=0,
            padx=(12, 5),
            pady=12,
        )

        self.interface_var = tk.StringVar()

        self.interface_combo = ttk.Combobox(
            controls,
            textvariable=self.interface_var,
            width=18,
            state="readonly",
        )

        self.interface_combo.grid(
            row=0,
            column=1,
            padx=5,
        )

        refresh_button = ttk.Button(
            controls,
            text="↻",
            width=3,
            command=self.load_interfaces,
        )

        refresh_button.grid(
            row=0,
            column=2,
            padx=(0, 15),
        )

        # BPF

        tk.Label(
            controls,
            text="BPF Filter",
            bg="#181a20",
            fg="#9ca3af",
        ).grid(
            row=0,
            column=3,
            padx=5,
        )

        self.filter_var = tk.StringVar()

        self.filter_entry = tk.Entry(
            controls,
            textvariable=self.filter_var,
            bg="#101216",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            width=35,
        )

        self.filter_entry.grid(
            row=0,
            column=4,
            padx=5,
            ipady=6,
        )

        # Start

        self.start_button = ttk.Button(
            controls,
            text="Start Capture",
            command=self.start_capture,
        )

        self.start_button.grid(
            row=0,
            column=5,
            padx=(15, 5),
        )

        # Stop

        self.stop_button = ttk.Button(
            controls,
            text="Stop",
            command=self.stop_capture,
            state="disabled",
        )

        self.stop_button.grid(
            row=0,
            column=6,
            padx=5,
        )

        # Pause

        self.pause_button = ttk.Button(
            controls,
            text="Pause",
            command=self.toggle_pause,
            state="disabled",
        )

        self.pause_button.grid(
            row=0,
            column=7,
            padx=5,
        )

        # Clear

        self.clear_button = ttk.Button(
            controls,
            text="Clear",
            command=self.clear_packets,
        )

        self.clear_button.grid(
            row=0,
            column=8,
            padx=(5, 12),
        )

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        stats_frame = tk.Frame(
            self.root,
            bg="#101216",
        )

        stats_frame.pack(
            fill="x",
            padx=20,
            pady=(0, 10),
        )

        self.stat_labels: Dict[str, tk.Label] = {}

        protocols = [
            "TOTAL",
            "TCP",
            "UDP",
            "ICMP",
            "ARP",
            "OTHER",
        ]

        for protocol in protocols:

            card = tk.Frame(
                stats_frame,
                bg="#181a20",
                highlightbackground="#2b2f3a",
                highlightthickness=1,
            )

            card.pack(
                side="left",
                fill="x",
                expand=True,
                padx=3,
            )

            value = tk.Label(
                card,
                text="0",
                bg="#181a20",
                fg="#ffffff",
                font=(
                    "TkDefaultFont",
                    18,
                    "bold",
                ),
            )

            value.pack(
                pady=(8, 0),
            )

            label = tk.Label(
                card,
                text=protocol,
                bg="#181a20",
                fg="#8b92a1",
            )

            label.pack(
                pady=(0, 8),
            )

            self.stat_labels[protocol] = value

        # ----------------------------------------------------
        # Packet Table
        # ----------------------------------------------------

        table_frame = tk.Frame(
            self.root,
            bg="#101216",
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 10),
        )

        columns = (
            "no",
            "time",
            "protocol",
            "source",
            "destination",
            "sport",
            "dport",
            "length",
            "info",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "no": "No.",
            "time": "Time",
            "protocol": "Protocol",
            "source": "Source",
            "destination": "Destination",
            "sport": "SPort",
            "dport": "DPort",
            "length": "Length",
            "info": "Info",
        }

        widths = {
            "no": 60,
            "time": 80,
            "protocol": 90,
            "source": 170,
            "destination": 170,
            "sport": 70,
            "dport": 70,
            "length": 70,
            "info": 450,
        }

        for column in columns:

            self.tree.heading(
                column,
                text=headings[column],
            )

            self.tree.column(
                column,
                width=widths[column],
                minwidth=50,
                anchor="w",
            )

        # Protocol colors

        self.tree.tag_configure(
            "TCP",
            foreground="#60a5fa",
        )

        self.tree.tag_configure(
            "UDP",
            foreground="#4ade80",
        )

        self.tree.tag_configure(
            "ICMP",
            foreground="#facc15",
        )

        self.tree.tag_configure(
            "ARP",
            foreground="#e879f9",
        )

        self.tree.tag_configure(
            "OTHER",
            foreground="#d1d5db",
        )

        scrollbar_y = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview,
        )

        scrollbar_x = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.tree.xview,
        )

        self.tree.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set,
        )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        scrollbar_y.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        scrollbar_x.grid(
            row=1,
            column=0,
            sticky="ew",
        )

        table_frame.grid_rowconfigure(
            0,
            weight=1,
        )

        table_frame.grid_columnconfigure(
            0,
            weight=1,
        )

        self.tree.bind(
            "<Double-1>",
            self.on_packet_double_click,
        )

        self.tree.bind(
            "<Return>",
            self.on_packet_double_click,
        )

        # ----------------------------------------------------
        # Details
        # ----------------------------------------------------

        details_frame = tk.Frame(
            self.root,
            bg="#181a20",
            highlightbackground="#2b2f3a",
            highlightthickness=1,
        )

        details_frame.pack(
            fill="x",
            padx=20,
            pady=(0, 20),
        )

        tk.Label(
            details_frame,
            text="Packet Details",
            bg="#181a20",
            fg="#ffffff",
            font=(
                "TkDefaultFont",
                10,
                "bold",
            ),
        ).pack(
            anchor="w",
            padx=10,
            pady=(8, 2),
        )

        self.details_text = tk.Text(
            details_frame,
            height=8,
            bg="#101216",
            fg="#d1d5db",
            insertbackground="#ffffff",
            relief="flat",
            wrap="none",
            font=("TkFixedFont", 9),
        )

        self.details_text.pack(
            fill="x",
            padx=10,
            pady=(0, 10),
        )

        self.details_text.configure(
            state="disabled",
        )

    # ========================================================
    # INTERFACES
    # ========================================================

    def load_interfaces(self):

        try:
            interfaces = get_if_list()

            if not interfaces:
                interfaces = [
                    str(conf.iface)
                ]

            self.interface_combo["values"] = interfaces

            current = self.interface_var.get()

            if current in interfaces:
                self.interface_var.set(
                    current
                )

            elif self.interface in interfaces:
                self.interface_var.set(
                    self.interface
                )

            else:
                default_iface = detect_default_interface()

                if default_iface in interfaces:
                    self.interface_var.set(
                        default_iface
                    )

                else:
                    self.interface_var.set(
                        interfaces[0]
                    )

        except Exception as e:

            messagebox.showerror(
                "Interface Error",
                f"Unable to detect interfaces:\n\n{e}",
            )

    # ========================================================
    # START
    # ========================================================

    def start_capture(self):

        if self.is_capturing:
            return

        interface = self.interface_var.get().strip()

        bpf_filter = (
            self.filter_var.get().strip()
        )

        if not interface:
            messagebox.showwarning(
                "No Interface",
                "Select a network interface first.",
            )
            return

        self.interface = interface

        self.bpf_filter = (
            bpf_filter
            if bpf_filter
            else None
        )

        self.is_capturing = True
        self.is_paused = False

        self.start_button.configure(
            state="disabled",
        )

        self.stop_button.configure(
            state="normal",
        )

        self.pause_button.configure(
            state="normal",
            text="Pause",
        )

        self.interface_combo.configure(
            state="disabled",
        )

        self.filter_entry.configure(
            state="disabled",
        )

        self.status_label.configure(
            text="● CAPTURING",
            fg="#22c55e",
        )

        try:

            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
            )

            self.sniffer.start()

        except Exception as e:

            self.is_capturing = False

            self.start_button.configure(
                state="normal",
            )

            self.stop_button.configure(
                state="disabled",
            )

            self.pause_button.configure(
                state="disabled",
            )

            self.interface_combo.configure(
                state="readonly",
            )

            self.filter_entry.configure(
                state="normal",
            )

            messagebox.showerror(
                "Capture Error",
                str(e),
            )

    # ========================================================
    # STOP
    # ========================================================

    def stop_capture(self):

        if not self.is_capturing:
            return

        self.is_capturing = False
        self.is_paused = False

        if self.sniffer:

            try:

                if self.sniffer.running:
                    self.sniffer.stop()

            except Exception:
                pass

        self.sniffer = None

        self.start_button.configure(
            state="normal",
        )

        self.stop_button.configure(
            state="disabled",
        )

        self.pause_button.configure(
            state="disabled",
        )

        self.interface_combo.configure(
            state="readonly",
        )

        self.filter_entry.configure(
            state="normal",
        )

        self.status_label.configure(
            text="● STOPPED",
            fg="#ef4444",
        )

    # ========================================================
    # PAUSE
    # ========================================================

    def toggle_pause(self):

        if not self.is_capturing:
            return

        self.is_paused = not self.is_paused

        if self.is_paused:

            self.pause_button.configure(
                text="Resume",
            )

            self.status_label.configure(
                text="● PAUSED",
                fg="#f59e0b",
            )

        else:

            self.pause_button.configure(
                text="Pause",
            )

            self.status_label.configure(
                text="● CAPTURING",
                fg="#22c55e",
            )

    # ========================================================
    # PACKET CALLBACK
    # ========================================================

    def _handle_packet(
        self,
        packet: Packet,
    ):

        # AsyncSniffer callback runs outside Tk's main thread.
        # Never modify Tk widgets directly here.

        if self.is_paused:
            return

        self.packet_queue.put(
            packet
        )

    # ========================================================
    # PACKET QUEUE
    # ========================================================

    def process_packet_queue(self):

        try:

            while True:

                packet = (
                    self.packet_queue.get_nowait()
                )

                self.process_packet(
                    packet
                )

        except queue.Empty:
            pass

        self.root.after(
            50,
            self.process_packet_queue,
        )

    # ========================================================
    # PACKET PROCESSING
    # ========================================================

    def process_packet(
        self,
        packet: Packet,
    ):

        self.packet_counter += 1

        timestamp = (
            datetime.now().strftime(
                "%H:%M:%S"
            )
        )

        length = len(packet)

        proto = "OTHER"
        src = "-"
        dst = "-"
        sport = "-"
        dport = "-"
        info = ""

        # ----------------------------------------------------
        # ARP
        # ----------------------------------------------------

        if packet.haslayer(ARP):

            arp = packet[ARP]

            proto = "ARP"

            src = str(
                arp.psrc
            )

            dst = str(
                arp.pdst
            )

            operation = (
                "who-has"
                if arp.op == 1
                else "is-at"
                if arp.op == 2
                else str(arp.op)
            )

            info = (
                f"{operation} "
                f"{dst} "
                f"(hwsrc {arp.hwsrc})"
            )

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        elif packet.haslayer(IP):

            ip = packet[IP]

            src = str(
                ip.src
            )

            dst = str(
                ip.dst
            )

            info = (
                f"ttl={ip.ttl} "
                f"id={ip.id}"
            )

            # TCP

            if packet.haslayer(TCP):

                tcp = packet[TCP]

                proto = "TCP"

                sport = str(
                    tcp.sport
                )

                dport = str(
                    tcp.dport
                )

                info = (
                    f"flags={tcp.flags} "
                    f"seq={tcp.seq} "
                    f"ack={tcp.ack} "
                    f"win={tcp.window}"
                )

            # UDP

            elif packet.haslayer(UDP):

                udp = packet[UDP]

                proto = "UDP"

                sport = str(
                    udp.sport
                )

                dport = str(
                    udp.dport
                )

                info = (
                    f"len={udp.len}"
                )

            # ICMP

            elif packet.haslayer(ICMP):

                icmp = packet[ICMP]

                proto = "ICMP"

                info = (
                    f"type={icmp.type} "
                    f"code={icmp.code}"
                )

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        self.stats[proto] = (
            self.stats.get(proto, 0) + 1
        )

        # ----------------------------------------------------
        # Record
        # ----------------------------------------------------

        record = {
            "no": self.packet_counter,
            "time": timestamp,
            "proto": proto,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "length": str(length),
            "info": info,
            "packet": packet,
        }

        self.packet_records.append(
            record
        )

        # ----------------------------------------------------
        # Add row
        # ----------------------------------------------------

        item_id = self.tree.insert(
            "",
            "end",
            values=(
                record["no"],
                record["time"],
                record["proto"],
                record["src"],
                record["dst"],
                record["sport"],
                record["dport"],
                record["length"],
                record["info"],
            ),
            tags=(
                record["proto"],
            ),
        )

        self.tree.see(
            item_id
        )

        self.update_statistics()

        # ----------------------------------------------------
        # Memory limit
        # ----------------------------------------------------

        max_packets = 5000

        if len(self.packet_records) > max_packets:

            self.packet_records.pop(0)

            children = (
                self.tree.get_children()
            )

            if children:
                self.tree.delete(
                    children[0]
                )

    # ========================================================
    # STATISTICS
    # ========================================================

    def update_statistics(self):

        self.stat_labels[
            "TOTAL"
        ].configure(
            text=str(
                self.packet_counter
            )
        )

        for protocol in (
            "TCP",
            "UDP",
            "ICMP",
            "ARP",
            "OTHER",
        ):

            self.stat_labels[
                protocol
            ].configure(
                text=str(
                    self.stats[protocol]
                )
            )

    # ========================================================
    # PACKET SELECTION
    # ========================================================

    def get_selected_packet(
        self,
    ) -> Optional[Dict[str, Any]]:

        selection = (
            self.tree.selection()
        )

        if not selection:
            return None

        item_id = selection[0]

        values = self.tree.item(
            item_id,
            "values",
        )

        if not values:
            return None

        try:
            packet_number = int(
                values[0]
            )
        except (
            ValueError,
            TypeError,
        ):
            return None

        for record in self.packet_records:

            if record["no"] == packet_number:
                return record

        return None

    # ========================================================
    # PACKET INSPECTION
    # ========================================================

    def on_packet_double_click(
        self,
        _event=None,
    ):

        record = (
            self.get_selected_packet()
        )

        if record is None:
            return

        self.show_packet_details(
            record
        )

    def show_packet_details(
        self,
        record: Dict[str, Any],
    ):

        packet = record["packet"]

        analysis = (
            run_packet_security_analysis(
                packet
            )
        )

        # ----------------------------------------------------
        # Detail window
        # ----------------------------------------------------

        window = tk.Toplevel(
            self.root
        )

        window.title(
            f"Packet #{record['no']} Inspection"
        )

        window.geometry(
            "1100x750"
        )

        window.minsize(
            800,
            500
        )

        window.configure(
            bg="#101216"
        )

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        header = tk.Frame(
            window,
            bg="#181a20",
        )

        header.pack(
            fill="x",
            padx=15,
            pady=15,
        )

        tk.Label(
            header,
            text=(
                f"Packet #{record['no']} "
                f"Inspection"
            ),
            bg="#181a20",
            fg="#ffffff",
            font=(
                "TkDefaultFont",
                16,
                "bold",
            ),
        ).pack(
            side="left"
        )

        # ----------------------------------------------------
        # Packet summary
        # ----------------------------------------------------

        summary = tk.Frame(
            window,
            bg="#181a20",
        )

        summary.pack(
            fill="x",
            padx=15,
            pady=(0, 10),
        )

        summary_text = (
            f"Protocol: {record['proto']}    "
            f"Source: {record['src']}    "
            f"Destination: {record['dst']}    "
            f"Length: {record['length']}"
        )

        tk.Label(
            summary,
            text=summary_text,
            bg="#181a20",
            fg="#d1d5db",
            anchor="w",
        ).pack(
            fill="x",
            padx=10,
            pady=10,
        )

        # ----------------------------------------------------
        # Security analysis
        # ----------------------------------------------------

        analysis_frame = tk.Frame(
            window,
            bg="#181a20",
            highlightbackground="#2b2f3a",
            highlightthickness=1,
        )

        analysis_frame.pack(
            fill="x",
            padx=15,
            pady=(0, 10),
        )

        tk.Label(
            analysis_frame,
            text="Security Analysis",
            bg="#181a20",
            fg="#60a5fa",
            font=(
                "TkDefaultFont",
                11,
                "bold",
            ),
        ).pack(
            anchor="w",
            padx=10,
            pady=(8, 4),
        )

        analysis_text = tk.Text(
            analysis_frame,
            height=5,
            bg="#101216",
            fg="#d1d5db",
            relief="flat",
            wrap="word",
        )

        analysis_text.pack(
            fill="x",
            padx=10,
            pady=(0, 10),
        )

        analysis_text.insert(
            "1.0",
            analysis,
        )

        analysis_text.configure(
            state="disabled",
        )

        # ----------------------------------------------------
        # Packet dump
        # ----------------------------------------------------

        dump_frame = tk.Frame(
            window,
            bg="#181a20",
        )

        dump_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(0, 10),
        )

        tk.Label(
            dump_frame,
            text="Layer Structure",
            bg="#181a20",
            fg="#60a5fa",
            font=(
                "TkDefaultFont",
                11,
                "bold",
            ),
        ).pack(
            anchor="w",
            padx=10,
            pady=(8, 4),
        )

        dump_text = tk.Text(
            dump_frame,
            bg="#101216",
            fg="#d1d5db",
            insertbackground="#ffffff",
            relief="flat",
            wrap="none",
            font=("TkFixedFont", 9),
        )

        dump_scroll = ttk.Scrollbar(
            dump_frame,
            orient="vertical",
            command=dump_text.yview,
        )

        dump_text.configure(
            yscrollcommand=dump_scroll.set
        )

        dump_text.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(10, 0),
            pady=(0, 10),
        )

        dump_scroll.pack(
            side="right",
            fill="y",
            padx=(0, 10),
            pady=(0, 10),
        )

        packet_dump = packet.show(
            dump=True
        )

        if packet_dump is None:
            packet_dump = (
                "[No layer breakdown available]"
            )

        dump_text.insert(
            "1.0",
            packet_dump,
        )

        dump_text.configure(
            state="disabled",
        )

        # ----------------------------------------------------
        # Buttons
        # ----------------------------------------------------

        button_frame = tk.Frame(
            window,
            bg="#101216",
        )

        button_frame.pack(
            fill="x",
            padx=15,
            pady=(0, 15),
        )

        def export_packet():

            default_name = (
                f"packet_{record['no']}_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            )

            filename = filedialog.asksaveasfilename(
                parent=window,
                title="Export Packet",
                initialfile=default_name,
                defaultextension=".pcap",
                filetypes=[
                    (
                        "PCAP files",
                        "*.pcap",
                    ),
                    (
                        "All files",
                        "*.*",
                    ),
                ],
            )

            if not filename:
                return

            try:

                wrpcap(
                    filename,
                    [packet],
                )

                messagebox.showinfo(
                    "Export Complete",
                    (
                        f"Packet #{record['no']} "
                        f"exported successfully.\n\n"
                        f"{filename}"
                    ),
                    parent=window,
                )

            except Exception as e:

                messagebox.showerror(
                    "Export Failed",
                    str(e),
                    parent=window,
                )

        ttk.Button(
            button_frame,
            text="Export Single .PCAP",
            command=export_packet,
        ).pack(
            side="left",
            padx=(0, 8),
        )

        ttk.Button(
            button_frame,
            text="Close",
            command=window.destroy,
        ).pack(
            side="right",
        )

    # ========================================================
    # CLEAR
    # ========================================================

    def clear_packets(self):

        if self.is_capturing:

            answer = messagebox.askyesno(
                "Clear Packets",
                (
                    "Packet capture is currently running.\n\n"
                    "Clear the displayed packets anyway?"
                ),
            )

            if not answer:
                return

        self.packet_counter = 0

        self.stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "OTHER": 0,
        }

        self.packet_records.clear()

        while True:

            try:
                self.packet_queue.get_nowait()

            except queue.Empty:
                break

        for item in self.tree.get_children():

            self.tree.delete(
                item
            )

        self.details_text.configure(
            state="normal"
        )

        self.details_text.delete(
            "1.0",
            "end",
        )

        self.details_text.configure(
            state="disabled"
        )

        self.update_statistics()

    # ========================================================
    # CLOSE
    # ========================================================

    def on_close(self):

        if self.sniffer:

            try:

                if self.sniffer.running:
                    self.sniffer.stop()

            except Exception:
                pass

        self.root.destroy()


# ============================================================
# DEFAULT INTERFACE DETECTION
# ============================================================

def detect_default_interface() -> str:

    try:

        route_output = subprocess.check_output(
            [
                "ip",
                "route",
            ],
            text=True,
        )

        for line in route_output.splitlines():

            if line.startswith("default"):

                match = re.search(
                    r"dev\s+(\S+)",
                    line,
                )

                if match:
                    return match.group(1)

    except Exception:
        pass

    try:

        iface = getattr(
            conf,
            "iface",
            "eth0",
        )

        if isinstance(
            iface,
            str,
        ):
            return iface

        name = getattr(
            iface,
            "name",
            None,
        )

        if isinstance(
            name,
            str,
        ):
            return name

        return str(iface)

    except Exception:

        return "eth0"


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Root privilege
    # --------------------------------------------------------

    if (
        hasattr(os, "geteuid")
        and os.geteuid() != 0
    ):

        print(
            "[!] Raw packet capture requires root privileges."
        )

        print(
            "[+] Restarting with sudo..."
        )

        try:

            os.execvp(
                "sudo",
                [
                    "sudo",
                    sys.executable,
                ] + sys.argv,
            )

        except Exception as e:

            print(
                f"[-] Elevation failed: {e}"
            )

            sys.exit(1)

    # --------------------------------------------------------
    # Arguments
    # --------------------------------------------------------

    parser = argparse.ArgumentParser(
        description=(
            "GUI Real-time Packet Sniffer "
            "& Security Analyzer"
        )
    )

    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Network interface",
    )

    parser.add_argument(
        "-f",
        "--filter",
        default="ip or arp",
        help="BPF filter",
    )

    args = parser.parse_args()

    interface = (
        args.interface
        or detect_default_interface()
    )

    # --------------------------------------------------------
    # Start GUI
    # --------------------------------------------------------

    root = tk.Tk()

    PacketSnifferGUI(
        root,
        interface=interface,
        bpf_filter=args.filter,
    )

    root.mainloop()


if __name__ == "__main__":
    main()
