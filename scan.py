import argparse
import os
import queue
import re
import subprocess
import sys
import threading
import time
import warnings

# Suppress Scapy cryptography deprecation warnings cluttering terminal output
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", module="scapy.*")

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box

from scapy.all import conf
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

console = Console()

class PacketSnifferCLI:
    def __init__(self, interface=None, bpf_filter="ip or arp", max_rows=15):
        self.interface = interface or self._detect_default_interface()
        self.bpf_filter = bpf_filter.lower() if bpf_filter else None
        self.max_rows = max_rows
        
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.packet_count = 0
        self.captured_packets = []
        
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}

    def _detect_default_interface(self):
        try:
            route_output = subprocess.check_output(["ip", "route"], text=True)
            for line in route_output.splitlines():
                if line.startswith("default"):
                    match = re.search(r"dev\s+(\S+)", line)
                    if match:
                        return match.group(1)
        except Exception:
            pass

        try:
            return conf.iface.name if hasattr(conf.iface, "name") else str(conf.iface)
        except Exception:
            return "eth0"

    def _sniff_worker(self):
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=lambda pkt: self.packet_queue.put(pkt),
                store=False,
                stop_filter=lambda _: self.stop_event.is_set(),
            )
        except Exception as e:
            self.packet_queue.put(e)

    def _process_packet(self, packet):
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
                info = f"flags={tcp.flags} seq={tcp.seq} ack={tcp.ack} win={tcp.window}"

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                proto = "UDP"
                sport, dport = udp.sport, udp.dport
                info = f"len={udp.len}"

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                proto = "ICMP"
                info = f"type={icmp.type} code={icmp.code}"

            else:
                proto = "OTHER"
                info = f"ip_proto={ip.proto}"

        self.stats[proto] = self.stats.get(proto, 0) + 1

        row = {
            "no": self.packet_count,
            "time": ts,
            "proto": proto,
            "src": src,
            "dst": dst,
            "sport": str(sport),
            "dport": str(dport),
            "length": str(length),
            "info": info,
        }

        self.captured_packets.append(row)
        if len(self.captured_packets) > self.max_rows:
            self.captured_packets.pop(0)

    def generate_table(self) -> Table:
        table = Table(box=box.SIMPLE_HEAD, expand=True)
        table.add_column("No.", style="dim", width=6)
        table.add_column("Time", width=10)
        table.add_column("Protocol", width=10)
        table.add_column("Source", width=18)
        table.add_column("Destination", width=18)
        table.add_column("SPort", width=8)
        table.add_column("DPort", width=8)
        table.add_column("Length", width=8)
        table.add_column("Info")

        proto_colors = {
            "TCP": "bright_blue",
            "UDP": "bright_green",
            "ICMP": "bright_yellow",
            "ARP": "bright_magenta",
            "OTHER": "white",
        }

        for pkt in reversed(self.captured_packets):
            color = proto_colors.get(pkt["proto"], "white")
            table.add_row(
                str(pkt["no"]),
                pkt["time"],
                f"[{color}]{pkt['proto']}[/{color}]",
                pkt["src"],
                pkt["dst"],
                pkt["sport"],
                pkt["dport"],
                pkt["length"],
                pkt["info"],
            )
        return table

    def generate_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        header_text = f"Interface: [bold cyan]{self.interface}[/bold cyan] | BPF Filter: [bold yellow]{self.bpf_filter or 'None'}[/bold yellow] | Status: [bold green]CAPTURING[/bold green]"
        layout["header"].update(Panel(header_text, style="white on black"))

        layout["body"].update(Panel(self.generate_table(), title="Live Traffic", border_style="blue"))

        stats_summary = " | ".join([f"{k}: [bold]{v}[/bold]" for k, v in self.stats.items()])
        footer_text = f"Total Captured: [bold green]{self.packet_count}[/bold green] | {stats_summary} | Press [bold red]Ctrl+C[/bold red] to stop"
        layout["footer"].update(Panel(footer_text, style="white on black"))

        return layout

    def start(self):
        sniff_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        sniff_thread.start()

        try:
            with Live(self.generate_layout(), refresh_per_second=4, screen=True) as live:
                while not self.stop_event.is_set():
                    try:
                        while True:
                            item = self.packet_queue.get_nowait()
                            if isinstance(item, Exception):
                                console.print(f"[bold red]Capture Error:[/bold red] {item}")
                                return
                            self._process_packet(item)
                    except queue.Empty:
                        pass

                    live.update(self.generate_layout())
                    time.sleep(0.1)
        except KeyboardInterrupt:
            self.stop_event.set()
            console.print("\n[bold yellow][!] Stopping packet capture...[/bold yellow]")


def main():
    # Auto-elevation check
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Raw packet capture requires root privileges. Elevating via sudo...")
        try:
            # Re-execute preserving argument vectors without duplicating the binary path
            os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:])
        except Exception as e:
            print(f"[-] Failed to elevate permissions: {e}")
            sys.exit(1)

    parser = argparse.ArgumentParser(description="Terminal-based Real-time Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to capture on (e.g. eth0, wlan0)", default=None)
    parser.add_argument("-f", "--filter", help="BPF filter string (default: 'ip or arp')", default="ip or arp")
    parser.add_argument("-n", "--rows", help="Max visible table rows in live display", type=int, default=15)
    args = parser.parse_args()

    sniffer = PacketSnifferCLI(interface=args.interface, bpf_filter=args.filter, max_rows=args.rows)
    sniffer.start()


if __name__ == "__main__":
    main()