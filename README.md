# Packet Sniffer CLI

A terminal-based, real-time packet sniffer built with [Scapy](https://scapy.net/) and [Rich](https://github.com/Textualize/rich). It captures live network traffic and displays it in a continuously updating table, along with per-protocol statistics.

## Features

- Live-updating terminal UI (via Rich `Live`) showing the most recent packets
- Supports **TCP**, **UDP**, **ICMP**, and **ARP** traffic, with a fallback "OTHER" category
- Per-protocol packet counters in the footer
- Configurable BPF capture filter
- Configurable network interface (auto-detected from the default route if not specified)
- Adjustable number of visible rows in the live table
- Automatically re-executes itself with `sudo` if not run as root (raw sockets require elevated privileges)

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- [Rich](https://github.com/Textualize/rich)
- Linux (interface auto-detection relies on the `ip route` command; capture itself works cross-platform wherever Scapy/libpcap does)
- Root/administrator privileges (needed for raw packet capture)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python sniffer.py [-i INTERFACE] [-f FILTER] [-n ROWS]
```

The script requires root privileges to open raw sockets. If not run as root, it will automatically attempt to relaunch itself via `sudo`.

### Options

| Flag | Long form | Description | Default |
|------|-----------|--------------|---------|
| `-i` | `--interface` | Network interface to capture on (e.g. `eth0`, `wlan0`) | Auto-detected from the system's default route |
| `-f` | `--filter` | [BPF filter](https://biot.com/capstats/bpf.html) string to restrict captured traffic | `ip or arp` |
| `-n` | `--rows` | Maximum number of packet rows shown in the live table | `15` |

### Examples

Capture on the default interface with the default filter:

```bash
sudo python sniffer.py
```

Capture only TCP traffic on a specific interface:

```bash
sudo python sniffer.py -i eth0 -f "tcp"
```

Capture traffic to/from a specific host, showing more rows:

```bash
sudo python sniffer.py -f "host 192.168.1.10" -n 30
```

## Display

The live view is split into three sections:

- **Header** — shows the active interface, BPF filter, and capture status
- **Body** — a scrolling table of the most recent packets (No., Time, Protocol, Source, Destination, Source Port, Destination Port, Length, Info)
- **Footer** — total packet count, a running tally per protocol, and the keybinding to stop capture

Protocols are color-coded in the table:

- TCP — bright blue
- UDP — bright green
- ICMP — bright yellow
- ARP — bright magenta
- Other — white

Press **Ctrl+C** at any time to stop the capture and exit.

## How it works

1. A background thread runs Scapy's `sniff()`, pushing each captured packet onto a thread-safe queue.
2. The main thread drains the queue, parses each packet's protocol/addresses/ports, and appends a summary row to a bounded in-memory list (capped at `--rows` entries).
3. Rich's `Live` display re-renders the header/body/footer panels several times per second from that in-memory state.

## Notes

- Raw packet capture requires elevated privileges on virtually all operating systems; this is why the script attempts a `sudo` re-exec rather than failing outright.
- The BPF filter is applied at the capture level (via libpcap), so it's efficient even on busy interfaces traffic that doesn't match the filter is never handed to Python.
- This tool is intended for legitimate network diagnostics, learning, and troubleshooting on networks you own or have explicit authorization to monitor.
