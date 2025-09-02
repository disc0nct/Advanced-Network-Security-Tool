# Advanced Network Security Tool

> **Warning:** This tool is intended **only** for authorized security testing on networks you own or have explicit permission to test. Unauthorized access, disruption, or interception of networks or devices is illegal and unethical. Read the **Security & Legal** section below before using.

---

## Table of contents

* [Project overview](#project-overview)
* [Features](#features)
* [Prerequisites / Dependencies](#prerequisites--dependencies)
* [Installation](#installation)
* [Usage](#usage)
* [Configuration notes](#configuration-notes)
* [Security & legal / Responsible use](#security--legal--responsible-use)
* [Troubleshooting](#troubleshooting)
* [Contributing](#contributing)
* [License](#license)

---

## Project overview

This repository contains a single-file Bash toolkit that provides a menu-driven interface for common network security testing tasks. It aggregates calls to many well-known open-source network/security tools and wraps them into an interactive CLI menu so authorized testers can run scans, captures, and assessments from one place.

The script is **not** an automated exploit tool — it is a wrapper that helps launch and manage various legitimate security utilities installed on your system.

---

## Features

High-level features implemented by the script:

* Interactive, colorized main menu and sub-menus
* Network sniffing / packet capture options (tcpdump, tshark, Wireshark)
* Port scanning (nmap, masscan) with quick/comprehensive/stealth modes
* Vulnerability assessment helpers (nmap scripts, nikto, OWASP ZAP)
* MITM (man-in-the-middle) helpers (bettercap, ettercap, arpspoof, sslstrip)
* DNS spoofing helpers (dnschef, ettercap DNS plugin)
* Wireless actions (monitor mode helper, deauthentication, handshake capture, WPS testing)
* Password cracking helpers (John the Ripper, Hashcat, crunch)
* Built-in checks to detect if required tools are present and to offer installation
* Graceful start/stop handling for long-running background processes

> Note: The script only *invokes* the listed tools — the actual behavior depends on those external programs.

---

## Prerequisites / Dependencies

This repository does **not** bundle third-party tools. The script expects standard Linux security tools to be available on the host. Common dependencies (one or more of these) include:

* `nmap`
* `masscan`
* `tcpdump`
* `tshark` / `wireshark`
* `aircrack-ng` (includes `airmon-ng`, `airodump-ng`, `aireplay-ng`)
* `mdk4`
* `reaver`
* `bettercap`
* `ettercap`
* `dnschef`
* `sslstrip`
* `nikto`
* `zap-cli` (OWASP ZAP CLI)
* `john` (John the Ripper)
* `hashcat`
* `crunch`
* `iptables` / `sysctl` (system utilities)
* `sudo` (script runs elevated commands)

Install only the packages you need and ensure you understand their usage and local laws before running them.

---

## Installation

1. Place the script file in your project/repo directory (for example `anst.sh`).
2. Make it executable:

```bash
chmod +x anst.sh
```

3. Run it with appropriate privileges (many operations require root):

```bash
sudo ./anst.sh
```

> Running with `sudo` is required for many network interfaces, monitor mode, and packet-capture functionality.

---

## Usage

The script provides an interactive menu. Major menu items are:

1. **Network Sniffing** — packet capture and analysis using tcpdump/tshark/Wireshark.
2. **Port Scanning** — quick/comprehensive/stealth/version scans using nmap; use masscan for very fast scans.
3. **Vulnerability Assessment** — nmap vulnerability scripts, web scans via nikto and OWASP ZAP.
4. **MITM Attacks** — tools for authorized MITM testing (Bettercap, Ettercap, ARP spoofing, SSL stripping).
5. **DNS Spoofing** — DNS redirection helpers (dnschef, Ettercap DNS).
6. **Wireless Attacks** — deauthentication, handshake capture and WPS testing (requires wireless adapter capable of monitor mode).
7. **Password Attacks** — hash cracking helpers (John, Hashcat) and wordlist generation (crunch).

**High-level run flow**

* Launch the script as root (or with `sudo`) from a terminal.
* Pick the desired main menu option, then a sub-option.
* Follow the prompts to provide a target, interface, or filenames as requested by the script.
* The script attempts to detect missing tools and will prompt to install or abort those subroutines.

**Important:** The script intentionally leaves many operational choices to the tester (target IPs, interfaces, channels, etc.). Always confirm authorization and scope before beginning any test.

---

## Configuration notes

* The script may attempt to put wireless interfaces into monitor mode. Ensure you have a compatible adapter and understand the effects (networking may be disrupted).
* Some sub-commands run background processes; the script tracks PIDs in order to terminate them when you choose to stop an action.
* The script uses standard Linux utilities like `sysctl` and `iptables` for certain workflows — modifying these may affect system networking.
* For consistent behavior, test on an isolated lab network or VM before using on production devices.

---

## Security & legal / Responsible use

This repository contains tools and helpers often used in penetration testing. **Before using any of these features you must:**

1. Have explicit, written permission from the network owner for the scope of testing.
2. Understand and comply with local laws and organizational policies.
3. Avoid tests that could cause unintended service interruptions on production networks without prior coordination.
4. Use isolated environments or lab networks for learning/testing whenever possible.

The author and repository maintainers are not responsible for misuse. Use at your own risk.

---

## Troubleshooting

* **Missing tool errors:** Install the required package for the tool indicated by the script (package names vary by distribution).
* **Permission/privilege issues:** Re-run the script with `sudo` if an operation fails due to permissions.
* **Wireless interface not entering monitor mode:** Ensure `aircrack-ng` is installed and no network manager processes are interfering; check that your adapter supports monitor mode.
* **Captures not containing expected traffic:** Verify interface selection, channel, BSSID, and that monitor mode is active.

---

## Contributing

Contributions are welcome for documentation, bug fixes, and safer usability improvements. If you submit changes, please:

* Focus on clarity of prompts and safety checks.
* Add clear README updates for any new feature.
* Avoid adding automated offensive actions; prefer helpers and safe guardrails.

---

## Credits

* This script is a wrapper that invokes many standard open-source security tools. See those individual projects for license and attribution.

---

## License

A permissive license is recommended (e.g., MIT). Example placeholder:

```
MIT License

Copyright (c) <year> <author>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, subject to the following conditions: ...
```

