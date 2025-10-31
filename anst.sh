#!/bin/bash

# Advanced Network Security Testing Suite
# For authorized testing on networks you own or have permission to test
# Version: 2.0

# Enable strict error handling
set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Global variables
SESSION_DIR=""
CURRENT_TARGET=""
CURRENT_INTERFACE=""
MONITOR_INTERFACE=""
ORIGINAL_INTERFACE=""
readonly CONFIG_FILE="$HOME/.network_tester.conf"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Array to track background processes
declare -a BACKGROUND_PIDS=()

# Error handling functions
yell() { echo -e "${RED}$0: $*${NC}" >&2; }
die() { yell "$*"; emergency_stop; exit 111; }
try() { "$@" || die "Cannot $*"; }

# Function to get local network information
get_network_info() {
    local default_interface
    local local_ip
    local public_ip
    local subnet
    local gateway
    local dns_servers
    local hostname
    local mac_address
    
    # Get default interface
    default_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    
    # Get local IP
    if [ -n "$default_interface" ]; then
        local_ip=$(ip addr show "$default_interface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
        subnet=$(ip addr show "$default_interface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        mac_address=$(ip link show "$default_interface" 2>/dev/null | grep "link/ether" | awk '{print $2}')
    else
        local_ip="N/A"
        subnet="N/A"
        mac_address="N/A"
    fi
    
    # Get public IP (with timeout)
    public_ip=$(timeout 3 curl -s ifconfig.me 2>/dev/null || timeout 3 curl -s icanhazip.com 2>/dev/null || echo "N/A")
    
    # Get gateway
    gateway=$(ip route | grep default | awk '{print $3}' | head -1)
    
    # Get DNS servers
    dns_servers=$(grep "nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -3 | tr '\n' ', ' | sed 's/,$//')
    
    # Get hostname
    hostname=$(hostname 2>/dev/null || echo "N/A")
    
    # Display information
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                    ${GREEN}NETWORK INFORMATION${NC}                      ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}Computer Name:${NC}    ${WHITE}$(printf '%-43s' "$hostname")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}Interface:${NC}        ${WHITE}$(printf '%-43s' "${default_interface:-N/A}")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}Local IP:${NC}         ${WHITE}$(printf '%-43s' "${local_ip:-N/A}")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}Public IP:${NC}        ${WHITE}$(printf '%-43s' "${public_ip:-N/A}")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}Subnet:${NC}           ${WHITE}$(printf '%-43s' "${subnet:-N/A}")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}Gateway:${NC}          ${WHITE}$(printf '%-43s' "${gateway:-N/A}")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}MAC Address:${NC}      ${WHITE}$(printf '%-43s' "${mac_address:-N/A}")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}DNS Servers:${NC}      ${WHITE}$(printf '%-43s' "${dns_servers:-N/A}")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to display cool banner
display_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${BLUE}          ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗${NC}"
    echo -e "${BLUE}          ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝${NC}"
    echo -e "${BLUE}          ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ ${NC}"
    echo -e "${BLUE}          ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  ${NC}"
    echo -e "${BLUE}          ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   ${NC}"
    echo -e "${BLUE}          ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ${NC}"
    echo ""
    echo -e "${CYAN}                    ████████╗███████╗███████╗████████╗███████╗██████╗ ${NC}"
    echo -e "${CYAN}                    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗${NC}"
    echo -e "${CYAN}                       ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝${NC}"
    echo -e "${CYAN}                       ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗${NC}"
    echo -e "${CYAN}                       ██║   ███████╗███████║   ██║   ███████╗██║  ██║${NC}"
    echo -e "${CYAN}                       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝${NC}"
    echo ""
    echo -e "${PURPLE}                           Advanced Penetration Testing Suite${NC}"
    echo -e "${YELLOW}                                    Version 2.0${NC}"
    echo ""
    echo -e "${RED}        ⚠️  WARNING: For Authorized Security Testing Only! ⚠️${NC}"
    echo -e "${RED}           Unauthorized access to computer systems is illegal${NC}"
    echo ""
    
    # Display network information
    get_network_info
}

# Function to display header (simplified for menu screens)
header() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}        ${RED}Advanced Network Security Testing Suite${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    if [ -n "${SESSION_DIR:-}" ]; then
        echo -e "${YELLOW}📁 Session: $(basename "$SESSION_DIR")${NC}"
    fi
    if [ -n "${CURRENT_TARGET:-}" ]; then
        echo -e "${YELLOW}🎯 Target: $CURRENT_TARGET${NC}"
    fi
    echo ""
}

# Function to check if tool is installed
check_tool() {
    local tool_cmd="${1:-}"
    local tool_package="${2:-$1}"
    
    if [ -z "$tool_cmd" ]; then
        echo -e "${RED}Error: No tool specified${NC}"
        return 1
    fi
    
    if ! command -v "$tool_cmd" &> /dev/null; then
        echo -e "${RED}$tool_cmd is not installed.${NC}"
        echo "Package name: $tool_package"
        echo "Would you like to install it? (y/n)"
        read -r install_choice
        if [[ $install_choice == "y" || $install_choice == "Y" ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install "$tool_package" -y
            elif command -v yum &> /dev/null; then
                sudo yum install "$tool_package" -y
            elif command -v pacman &> /dev/null; then
                sudo pacman -S "$tool_package"
            else
                echo -e "${RED}Unable to detect package manager. Please install $tool_package manually.${NC}"
                return 1
            fi
        else
            return 1
        fi
    fi
    return 0
}

# Session management
setup_session() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    SESSION_DIR="$SCRIPT_DIR/sessions/session_$timestamp"
    
    mkdir -p "$SESSION_DIR"/{logs,scans,captures,reports,evidence}
    
    echo "Session started: $timestamp" >> "$SESSION_DIR/session.log"
    echo -e "${GREEN}New session created: $SESSION_DIR${NC}"
    
    # Collect initial system state
    collect_evidence
}

# Logging functions
log_command() {
    local command="${1:-}"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    if [ -n "${SESSION_DIR:-}" ]; then
        echo "[$timestamp] $command" >> "$SESSION_DIR/logs/command_history.log"
    fi
}

log_event() {
    local event="${1:-}"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    if [ -n "${SESSION_DIR:-}" ]; then
        echo "[$timestamp] $event" >> "$SESSION_DIR/logs/events.log"
    fi
}

# Evidence collection
collect_evidence() {
    echo -e "${YELLOW}Collecting system evidence...${NC}"
    
    if [ -n "${SESSION_DIR:-}" ]; then
        {
            ifconfig 2>/dev/null || ip addr 2>/dev/null
        } > "$SESSION_DIR/evidence/network_config.txt"
        
        ip addr 2>/dev/null > "$SESSION_DIR/evidence/ip_config.txt" || true
        netstat -tulnp 2>/dev/null > "$SESSION_DIR/evidence/active_connections.txt" || ss -tulnp > "$SESSION_DIR/evidence/active_connections.txt" 2>/dev/null || true
        ps aux > "$SESSION_DIR/evidence/running_processes.txt" 2>/dev/null || true
        
        echo "Evidence collected at: $(date)" >> "$SESSION_DIR/session.log"
    fi
}

# Safety checks
safety_checks() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}⚠️  Not running as root. Some features require root privileges.${NC}"
        echo -e "${YELLOW}Please run with sudo for full functionality.${NC}"
        echo -e "${YELLOW}Press any key to continue or Ctrl+C to exit...${NC}"
        read -n 1 -s
    fi
    
    # Verify ethical use agreement
    echo -e "${RED}═══════════════════════════════════════════════════${NC}"
    echo -e "${RED}           ETHICAL USE AGREEMENT${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}By using this tool, you confirm that:${NC}"
    echo -e "${YELLOW}1. You have explicit written authorization${NC}"
    echo -e "${YELLOW}2. You will only test systems you own or have permission to test${NC}"
    echo -e "${YELLOW}3. You understand that unauthorized access is illegal${NC}"
    echo ""
    echo -e "${GREEN}Do you agree to these terms? (yes/no)${NC}"
    read -r agreement
    
    if [[ ! $agreement =~ ^[Yy][Ee][Ss]$ ]]; then
        echo -e "${RED}Agreement not accepted. Exiting.${NC}"
        exit 1
    fi
    
    # Check if targeting own network
    if [ -n "${CURRENT_TARGET:-}" ]; then
        local target_network
        local my_network
        target_network=$(echo "$CURRENT_TARGET" | cut -d. -f1-3)
        my_network=$(ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d. -f1-3 | head -1)
        
        if [ "$target_network" != "$my_network" ]; then
            echo -e "${RED}⚠️  WARNING: You are targeting a different network!${NC}"
            echo -e "${YELLOW}Target network: $target_network.x${NC}"
            echo -e "${YELLOW}Your network: $my_network.x${NC}"
            echo -e "${YELLOW}Do you have authorization to test this network? (yes/no)${NC}"
            read -r confirm
            if [[ ! $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
                return 1
            fi
        fi
    fi
    
    return 0
}

# Emergency stop function
emergency_stop() {
    echo -e "${RED}🛑 EMERGENCY STOP ACTIVATED${NC}"
    log_event "EMERGENCY STOP ACTIVATED"
    
    # Kill tracked background processes
    for pid in "${BACKGROUND_PIDS[@]:-}"; do
        if ps -p "$pid" > /dev/null 2>&1; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    BACKGROUND_PIDS=()
    
    # Kill all security tools
    pkill -f nmap 2>/dev/null || true
    pkill -f tcpdump 2>/dev/null || true
    pkill -f tshark 2>/dev/null || true
    pkill -f aireplay-ng 2>/dev/null || true
    pkill -f mdk4 2>/dev/null || true
    pkill -f bettercap 2>/dev/null || true
    pkill -f ettercap 2>/dev/null || true
    pkill -f sslstrip 2>/dev/null || true
    pkill -f dnschef 2>/dev/null || true
    pkill -f arpspoof 2>/dev/null || true
    
    # Reset iptables
    if command -v iptables &> /dev/null && [ "$EUID" -eq 0 ]; then
        iptables -F 2>/dev/null || true
        iptables -t nat -F 2>/dev/null || true
    fi
    
    # Disable monitor mode if active
    if [ -n "${MONITOR_INTERFACE:-}" ]; then
        disable_monitor_mode
    fi
    
    echo -e "${GREEN}✓ All processes stopped and network reset${NC}"
    log_event "All processes stopped and network reset"
}

# Disable monitor mode properly
disable_monitor_mode() {
    if [ -n "${ORIGINAL_INTERFACE:-}" ]; then
        echo -e "${YELLOW}Disabling monitor mode on $MONITOR_INTERFACE...${NC}"
        
        if command -v airmon-ng &> /dev/null; then
            sudo airmon-ng stop "$MONITOR_INTERFACE" 2>/dev/null || true
        fi
        
        # Restart network manager
        if command -v systemctl &> /dev/null; then
            sudo systemctl restart NetworkManager 2>/dev/null || true
        else
            sudo service network-manager restart 2>/dev/null || true
        fi
        
        MONITOR_INTERFACE=""
        ORIGINAL_INTERFACE=""
        log_event "Monitor mode disabled"
    fi
}

# AI-like tool recommendation system
recommend_tools() {
    local scenario="${1:-general}"
    
    case $scenario in
        "stealth_scan")
            echo -e "${CYAN}Recommended for stealth scanning:${NC}"
            echo "  • nmap -sS -T2 (Stealth SYN scan, slow timing)"
            echo "  • nmap -f (Fragment packets)"
            echo "  • masscan --rate=100 (Fast scan with rate limiting)"
            echo "  • unicornscan (Advanced asynchronous scanner)"
            ;;
        "comprehensive_scan")
            echo -e "${CYAN}Recommended for comprehensive scanning:${NC}"
            echo "  • nmap -sS -sV -sC -O (Full TCP scan with scripts)"
            echo "  • nmap --script vuln (Vulnerability detection scripts)"
            echo "  • OpenVAS (Open source vulnerability scanner)"
            ;;
        "web_scan")
            echo -e "${CYAN}Recommended for web application scanning:${NC}"
            echo "  • nikto -h <url> (Web server scanner)"
            echo "  • dirb <url> (Web content scanner)"
            echo "  • gobuster dir -u <url> (Directory busting)"
            echo "  • sqlmap -u <url> (SQL injection testing)"
            ;;
        "wireless_attack")
            echo -e "${CYAN}Recommended for wireless security testing:${NC}"
            echo "  • airodump-ng (Monitor and capture packets)"
            echo "  • aireplay-ng (Injection and deauth attacks)"
            echo "  • reaver (WPS PIN recovery)"
            echo "  • aircrack-ng (WEP/WPA cracking)"
            ;;
        "password_attack")
            echo -e "${CYAN}Recommended for password testing:${NC}"
            echo "  • john (Password hash cracking)"
            echo "  • hashcat (GPU-accelerated cracking)"
            echo "  • hydra (Network service brute force)"
            echo "  • medusa (Parallel brute forcing)"
            ;;
        "network_sniffing")
            echo -e "${CYAN}Recommended for network traffic analysis:${NC}"
            echo "  • tcpdump (Command-line packet capture)"
            echo "  • tshark (Terminal Wireshark with filters)"
            echo "  • wireshark (GUI packet analyzer)"
            echo "  • bettercap (Network attack framework)"
            ;;
        "mitm_attack")
            echo -e "${CYAN}Recommended for MITM testing:${NC}"
            echo "  • arpspoof (ARP cache poisoning)"
            echo "  • ettercap (Comprehensive MITM suite)"
            echo "  • bettercap (Modern MITM framework)"
            echo "  • mitmproxy (Interactive HTTPS proxy)"
            ;;
        "dns_spoofing")
            echo -e "${CYAN}Recommended for DNS testing:${NC}"
            echo "  • dnschef (DNS proxy for spoofing)"
            echo "  • ettercap (Includes DNS spoofing)"
            echo "  • bettercap (DNS spoofing module)"
            ;;
        *)
            echo -e "${CYAN}General purpose security tools:${NC}"
            echo "  • nmap (Network discovery and scanning)"
            echo "  • tcpdump (Packet capture and analysis)"
            echo "  • metasploit (Exploitation framework)"
            ;;
    esac
}

# Automated reconnaissance
automated_recon() {
    header
    echo -e "${GREEN}═══ Automated Reconnaissance ═══${NC}"
    
    if [ -z "${CURRENT_TARGET:-}" ]; then
        echo -e "${GREEN}Enter target IP or domain:${NC}"
        read -r CURRENT_TARGET
    fi
    
    if [ -z "$CURRENT_TARGET" ]; then
        echo -e "${RED}No target specified${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Starting comprehensive reconnaissance on $CURRENT_TARGET...${NC}"
    log_event "Starting automated reconnaissance on $CURRENT_TARGET"
    
    # Create directory for recon data
    local recon_dir
    recon_dir="$SESSION_DIR/recon_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$recon_dir"
    
    # WHOIS lookup
    if command -v whois &> /dev/null; then
        echo -e "${CYAN}[1/5] Performing WHOIS lookup...${NC}"
        whois "$CURRENT_TARGET" > "$recon_dir/whois.txt" 2>&1 || echo "WHOIS failed" > "$recon_dir/whois.txt"
        log_command "whois $CURRENT_TARGET"
    fi
    
    # DNS enumeration
    if command -v dig &> /dev/null; then
        echo -e "${CYAN}[2/5] Performing DNS enumeration...${NC}"
        dig "$CURRENT_TARGET" ANY > "$recon_dir/dns_any.txt" 2>&1 || true
        dig "$CURRENT_TARGET" A > "$recon_dir/dns_a.txt" 2>&1 || true
        dig "$CURRENT_TARGET" MX > "$recon_dir/dns_mx.txt" 2>&1 || true
        dig "$CURRENT_TARGET" NS > "$recon_dir/dns_ns.txt" 2>&1 || true
        dig "$CURRENT_TARGET" TXT > "$recon_dir/dns_txt.txt" 2>&1 || true
        log_command "dig $CURRENT_TARGET (multiple queries)"
    fi
    
    # Subdomain discovery
    if [[ $CURRENT_TARGET =~ [a-zA-Z] ]]; then
        echo -e "${CYAN}[3/5] Attempting subdomain discovery...${NC}"
        
        # Try common subdomains
        echo -e "${YELLOW}  Checking common subdomains...${NC}"
        for sub in www ftp mail admin test dev api portal vpn remote; do
            if host "$sub.$CURRENT_TARGET" >> "$recon_dir/subdomains_manual.txt" 2>&1; then
                echo "  ✓ Found: $sub.$CURRENT_TARGET"
            fi
        done
    fi
    
    # Port scan
    if command -v nmap &> /dev/null; then
        echo -e "${CYAN}[4/5] Performing quick port scan...${NC}"
        nmap -F -T4 "$CURRENT_TARGET" > "$recon_dir/port_scan.txt" 2>&1 || true
        log_command "nmap -F -T4 $CURRENT_TARGET"
    fi
    
    # Service detection
    if command -v nmap &> /dev/null; then
        echo -e "${CYAN}[5/5] Performing service detection...${NC}"
        nmap -sV --version-intensity 5 -F "$CURRENT_TARGET" > "$recon_dir/service_detection.txt" 2>&1 || true
        log_command "nmap -sV --version-intensity 5 -F $CURRENT_TARGET"
    fi
    
    # Summary
    echo ""
    echo -e "${GREEN}✓ Reconnaissance complete!${NC}"
    echo -e "${CYAN}Results saved to: $recon_dir${NC}"
    
    # Show quick summary
    if [ -f "$recon_dir/port_scan.txt" ]; then
        echo -e "\n${CYAN}Open ports found:${NC}"
        grep -E "open|filtered" "$recon_dir/port_scan.txt" | head -10 || echo "  None found"
    fi
    
    echo ""
    recommend_tools "comprehensive_scan"
    log_event "Reconnaissance completed on $CURRENT_TARGET"
    
    echo ""
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Function to get target information
get_target() {
    echo -e "${GREEN}Enter target IP, hostname, or network range (CIDR):${NC}"
    read -r CURRENT_TARGET
    
    if [ -z "$CURRENT_TARGET" ]; then
        echo -e "${RED}No target specified${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Enter port(s) or port range (default: common ports):${NC}"
    echo -e "${YELLOW}Examples: 80, 80-443, 21,22,23,80${NC}"
    read -r ports
    
    if [ -z "$ports" ]; then
        ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    fi
}

# Function to get network interface
get_interface() {
    echo -e "${GREEN}Available network interfaces:${NC}"
    ip -brief link show 2>/dev/null || ifconfig -s
    echo ""
    echo -e "${GREEN}Enter network interface (e.g., eth0, wlan0):${NC}"
    read -r CURRENT_INTERFACE
    
    if [ -z "$CURRENT_INTERFACE" ]; then
        echo -e "${RED}No interface specified${NC}"
        return 1
    fi
    
    # Verify interface exists
    if ! ip link show "$CURRENT_INTERFACE" &> /dev/null; then
        echo -e "${RED}Interface $CURRENT_INTERFACE does not exist${NC}"
        return 1
    fi
}

# Function to get wireless interface in monitor mode
get_monitor_interface() {
    echo -e "${GREEN}Available wireless interfaces:${NC}"
    iw dev 2>/dev/null | grep Interface | awk '{print $2}' || iwconfig 2>&1 | grep -v "no wireless" | awk '{print $1}'
    echo ""
    echo -e "${GREEN}Enter wireless interface (e.g., wlan0):${NC}"
    read -r wifi_interface
    
    if [ -z "$wifi_interface" ]; then
        echo -e "${RED}No interface specified${NC}"
        return 1
    fi
    
    ORIGINAL_INTERFACE="$wifi_interface"
    
    echo -e "${YELLOW}Putting interface in monitor mode...${NC}"
    
    # Kill interfering processes
    if command -v airmon-ng &> /dev/null; then
        sudo airmon-ng check kill > /dev/null 2>&1 || true
        
        # Start monitor mode
        local output
        output=$(sudo airmon-ng start "$wifi_interface" 2>&1)
        
        # Try to detect the monitor interface name
        if echo "$output" | grep -q "monitor mode.*enabled"; then
            # Try common patterns
            if ip link show "${wifi_interface}mon" &> /dev/null; then
                MONITOR_INTERFACE="${wifi_interface}mon"
            elif ip link show "mon${wifi_interface}" &> /dev/null; then
                MONITOR_INTERFACE="mon${wifi_interface}"
            else
                # Fallback to the original interface
                MONITOR_INTERFACE="$wifi_interface"
            fi
        else
            echo -e "${RED}Failed to enable monitor mode${NC}"
            return 1
        fi
    else
        echo -e "${RED}airmon-ng not found. Install aircrack-ng suite.${NC}"
        return 1
    fi
    
    CURRENT_INTERFACE="$MONITOR_INTERFACE"
    echo -e "${GREEN}✓ Monitor interface: $MONITOR_INTERFACE${NC}"
    log_event "Set monitor mode: $ORIGINAL_INTERFACE -> $MONITOR_INTERFACE"
}

# Network sniffing function
network_sniff() {
    header
    echo -e "${GREEN}═══ Network Sniffing Options ═══${NC}"
    echo "1. Basic packet capture (tcpdump)"
    echo "2. Advanced packet analysis (tshark)"
    echo "3. GUI packet analysis (Wireshark)"
    echo "4. Analyze captured data"
    echo "5. Return to main menu"
    echo ""
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}Packet capture with tcpdump${NC}"
            check_tool "tcpdump" "tcpdump" || return
            
            get_interface || return
            
            local output_file
            output_file="$SESSION_DIR/captures/capture_$(date +%Y%m%d_%H%M%S).pcap"
            
            echo -e "${GREEN}Enter capture duration in seconds (0 for manual stop):${NC}"
            read -r duration
            
            if [ "$duration" = "0" ] || [ -z "$duration" ]; then
                echo -e "${YELLOW}Starting capture. Press Ctrl+C to stop.${NC}"
                echo -e "${YELLOW}Command: sudo tcpdump -i $CURRENT_INTERFACE -w $output_file${NC}"
                log_command "sudo tcpdump -i $CURRENT_INTERFACE -w $output_file"
                sudo tcpdump -i "$CURRENT_INTERFACE" -w "$output_file"
            else
                echo -e "${YELLOW}Capturing for $duration seconds...${NC}"
                echo -e "${YELLOW}Command: sudo timeout $duration tcpdump -i $CURRENT_INTERFACE -w $output_file${NC}"
                log_command "sudo timeout $duration tcpdump -i $CURRENT_INTERFACE -w $output_file"
                sudo timeout "$duration" tcpdump -i "$CURRENT_INTERFACE" -w "$output_file"
            fi
            
            echo -e "${GREEN}✓ Capture saved to: $output_file${NC}"
            ;;
        2)
            echo -e "${YELLOW}Packet analysis with tshark${NC}"
            check_tool "tshark" "tshark" || return
            
            get_interface || return
            
            echo -e "${GREEN}Enter display filter (e.g., 'tcp.port==80' or leave empty):${NC}"
            read -r filter
            
            local output_file
            output_file="$SESSION_DIR/captures/capture_$(date +%Y%m%d_%H%M%S).pcap"
            
            if [ -z "$filter" ]; then
                echo -e "${YELLOW}Running: sudo tshark -i $CURRENT_INTERFACE -w $output_file${NC}"
                log_command "sudo tshark -i $CURRENT_INTERFACE -w $output_file"
                sudo tshark -i "$CURRENT_INTERFACE" -w "$output_file"
            else
                echo -e "${YELLOW}Running: sudo tshark -i $CURRENT_INTERFACE -f '$filter' -w $output_file${NC}"
                log_command "sudo tshark -i $CURRENT_INTERFACE -f '$filter' -w $output_file"
                sudo tshark -i "$CURRENT_INTERFACE" -f "$filter" -w "$output_file"
            fi
            ;;
        3)
            echo -e "${YELLOW}GUI packet analysis with Wireshark${NC}"
            check_tool "wireshark" "wireshark" || return
            echo -e "${YELLOW}Starting Wireshark GUI...${NC}"
            wireshark &
            ;;
        4)
            echo -e "${YELLOW}Analyze captured data${NC}"
            check_tool "tshark" "tshark" || return
            
            echo -e "${GREEN}Available capture files:${NC}"
            ls -1 "$SESSION_DIR/captures/"*.pcap 2>/dev/null | nl || echo "No captures found"
            echo ""
            echo -e "${GREEN}Enter capture file path:${NC}"
            read -r cap_file
            
            if [ ! -f "$cap_file" ]; then
                echo -e "${RED}File not found: $cap_file${NC}"
                return
            fi
            
            echo -e "${GREEN}Enter display filter (e.g., 'http.request' or leave empty for all):${NC}"
            read -r filter
            
            if [ -z "$filter" ]; then
                echo -e "${YELLOW}Running: tshark -r $cap_file${NC}"
                log_command "tshark -r $cap_file"
                tshark -r "$cap_file" | less
            else
                echo -e "${YELLOW}Running: tshark -r $cap_file -Y '$filter'${NC}"
                log_command "tshark -r $cap_file -Y '$filter'"
                tshark -r "$cap_file" -Y "$filter" | less
            fi
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Port scanning function
port_scan() {
    header
    echo -e "${GREEN}═══ Port Scanning Options ═══${NC}"
    echo "1. Quick scan (Top 100 ports)"
    echo "2. Comprehensive scan (All ports + version detection)"
    echo "3. Stealth scan (SYN scan, slow timing)"
    echo "4. UDP scan"
    echo "5. OS detection"
    echo "6. Fast scan (masscan)"
    echo "7. Return to main menu"
    echo ""
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    if [ -z "${CURRENT_TARGET:-}" ]; then
        get_target || return
    fi
    
    check_tool "nmap" "nmap" || return
    
    local scan_file
    scan_file="$SESSION_DIR/scans/scan_$(date +%Y%m%d_%H%M%S).txt"
    
    case $option in
        1)
            echo -e "${YELLOW}Quick scan (top 100 ports)${NC}"
            echo -e "${YELLOW}Running: nmap -F -T4 $CURRENT_TARGET${NC}"
            log_command "nmap -F -T4 $CURRENT_TARGET"
            nmap -F -T4 "$CURRENT_TARGET" | tee "$scan_file"
            ;;
        2)
            echo -e "${YELLOW}Comprehensive scan${NC}"
            echo -e "${YELLOW}Running: nmap -sS -sV -sC -O -p- -T4 $CURRENT_TARGET${NC}"
            echo -e "${YELLOW}This may take a while...${NC}"
            log_command "nmap -sS -sV -sC -O -p- -T4 $CURRENT_TARGET"
            sudo nmap -sS -sV -sC -O -p- -T4 "$CURRENT_TARGET" | tee "$scan_file"
            ;;
        3)
            echo -e "${YELLOW}Stealth scan${NC}"
            echo -e "${YELLOW}Running: nmap -sS -T2 -f --data-length 24 $CURRENT_TARGET${NC}"
            log_command "nmap -sS -T2 -f --data-length 24 $CURRENT_TARGET"
            sudo nmap -sS -T2 -f --data-length 24 "$CURRENT_TARGET" | tee "$scan_file"
            ;;
        4)
            echo -e "${YELLOW}UDP scan${NC}"
            echo -e "${YELLOW}Running: nmap -sU -F $CURRENT_TARGET${NC}"
            log_command "nmap -sU -F $CURRENT_TARGET"
            sudo nmap -sU -F "$CURRENT_TARGET" | tee "$scan_file"
            ;;
        5)
            echo -e "${YELLOW}OS detection${NC}"
            echo -e "${YELLOW}Running: nmap -O --osscan-guess $CURRENT_TARGET${NC}"
            log_command "nmap -O --osscan-guess $CURRENT_TARGET"
            sudo nmap -O --osscan-guess "$CURRENT_TARGET" | tee "$scan_file"
            ;;
        6)
            echo -e "${YELLOW}Fast scanning with masscan${NC}"
            check_tool "masscan" "masscan" || return
            
            echo -e "${GREEN}Enter rate (packets/second, default: 1000):${NC}"
            read -r rate
            rate=${rate:-1000}
            
            echo -e "${GREEN}Enter ports (default: 1-65535):${NC}"
            read -r ports_range
            ports_range=${ports_range:-1-65535}
            
            echo -e "${YELLOW}Running: sudo masscan -p$ports_range --rate=$rate $CURRENT_TARGET${NC}"
            log_command "sudo masscan -p$ports_range --rate=$rate $CURRENT_TARGET"
            sudo masscan -p"$ports_range" --rate="$rate" "$CURRENT_TARGET" | tee "$scan_file"
            ;;
        7)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            return
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}✓ Scan results saved to: $scan_file${NC}"
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Vulnerability assessment function
vuln_assessment() {
    header
    echo -e "${GREEN}═══ Vulnerability Assessment Options ═══${NC}"
    echo "1. Nmap vulnerability scan"
    echo "2. Web application scan (nikto)"
    echo "3. SSL/TLS scan"
    echo "4. Safe scripts scan"
    echo "5. Return to main menu"
    echo ""
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    if [ -z "${CURRENT_TARGET:-}" ]; then
        get_target || return
    fi
    
    local vuln_file
    vuln_file="$SESSION_DIR/scans/vuln_scan_$(date +%Y%m%d_%H%M%S).txt"
    
    case $option in
        1)
            echo -e "${YELLOW}Vulnerability scan with nmap${NC}"
            check_tool "nmap" "nmap" || return
            echo -e "${YELLOW}Running: nmap --script vuln -sV $CURRENT_TARGET${NC}"
            echo -e "${YELLOW}This may take several minutes...${NC}"
            log_command "nmap --script vuln -sV $CURRENT_TARGET"
            sudo nmap --script vuln -sV "$CURRENT_TARGET" | tee "$vuln_file"
            ;;
        2)
            echo -e "${YELLOW}Web application scan with nikto${NC}"
            check_tool "nikto" "nikto" || return
            echo -e "${GREEN}Enter URL (e.g., http://$CURRENT_TARGET or https://$CURRENT_TARGET):${NC}"
            read -r url
            
            if [ -z "$url" ]; then
                echo -e "${RED}No URL specified${NC}"
                return
            fi
            
            echo -e "${YELLOW}Running: nikto -h $url${NC}"
            log_command "nikto -h $url"
            nikto -h "$url" | tee "$vuln_file"
            ;;
        3)
            echo -e "${YELLOW}SSL/TLS security scan${NC}"
            check_tool "nmap" "nmap" || return
            echo -e "${YELLOW}Running: nmap --script ssl-enum-ciphers -p 443 $CURRENT_TARGET${NC}"
            log_command "nmap --script ssl-enum-ciphers -p 443 $CURRENT_TARGET"
            nmap --script ssl-enum-ciphers -p 443 "$CURRENT_TARGET" | tee "$vuln_file"
            ;;
        4)
            echo -e "${YELLOW}Safe scripts scan with nmap${NC}"
            check_tool "nmap" "nmap" || return
            echo -e "${YELLOW}Running: nmap -sV --script safe $CURRENT_TARGET${NC}"
            log_command "nmap -sV --script safe $CURRENT_TARGET"
            nmap -sV --script safe "$CURRENT_TARGET" | tee "$vuln_file"
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            return
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}✓ Vulnerability scan results saved to: $vuln_file${NC}"
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# MITM Attack function
mitm_attack() {
    header
    echo -e "${GREEN}═══ MITM Attack Options ═══${NC}"
    echo -e "${RED}⚠️  WARNING: MITM attacks can disrupt network services${NC}"
    echo -e "${RED}⚠️  Use only with explicit authorization${NC}"
    echo ""
    echo "1. ARP Spoofing (arpspoof)"
    echo "2. Bettercap (comprehensive MITM)"
    echo "3. Ettercap (GUI and CLI options)"
    echo "4. SSL Stripping (sslstrip)"
    echo "5. Return to main menu"
    echo ""
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}ARP Spoofing with arpspoof${NC}"
            check_tool "arpspoof" "dsniff" || return
            
            get_interface || return
            
            echo -e "${GREEN}Enter target IP:${NC}"
            read -r target_ip
            echo -e "${GREEN}Enter gateway IP:${NC}"
            read -r gateway_ip
            
            if [ -z "$target_ip" ] || [ -z "$gateway_ip" ]; then
                echo -e "${RED}Invalid input${NC}"
                return
            fi
            
            echo -e "${YELLOW}Enabling IP forwarding...${NC}"
            sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
            
            echo -e "${YELLOW}Starting ARP spoofing between $target_ip and $gateway_ip${NC}"
            echo -e "${RED}Press Ctrl+C or any key to stop${NC}"
            
            log_command "sudo arpspoof -i $CURRENT_INTERFACE -t $target_ip $gateway_ip"
            sudo arpspoof -i "$CURRENT_INTERFACE" -t "$target_ip" "$gateway_ip" &
            local arpspoof_pid1=$!
            BACKGROUND_PIDS+=("$arpspoof_pid1")
            
            log_command "sudo arpspoof -i $CURRENT_INTERFACE -t $gateway_ip $target_ip"
            sudo arpspoof -i "$CURRENT_INTERFACE" -t "$gateway_ip" "$target_ip" &
            local arpspoof_pid2=$!
            BACKGROUND_PIDS+=("$arpspoof_pid2")
            
            read -n 1 -s
            
            kill "$arpspoof_pid1" "$arpspoof_pid2" 2>/dev/null || true
            echo -e "${YELLOW}✓ ARP spoofing stopped${NC}"
            log_event "ARP spoofing stopped"
            ;;
        2)
            echo -e "${YELLOW}Comprehensive MITM with Bettercap${NC}"
            check_tool "bettercap" "bettercap" || return
            
            get_interface || return
            
            echo -e "${YELLOW}Starting Bettercap on interface $CURRENT_INTERFACE${NC}"
            echo -e "${CYAN}Tip: Use 'net.probe on' and 'net.recon on' to discover hosts${NC}"
            echo -e "${CYAN}Use 'arp.spoof on' to start ARP spoofing${NC}"
            log_command "sudo bettercap -iface $CURRENT_INTERFACE"
            sudo bettercap -iface "$CURRENT_INTERFACE"
            ;;
        3)
            echo -e "${YELLOW}MITM with Ettercap${NC}"
            check_tool "ettercap" "ettercap-graphical" || return
            
            get_interface || return
            
            echo -e "${GREEN}Choose Ettercap mode:${NC}"
            echo "1. Text mode"
            echo "2. Graphical mode"
            echo "3. Curses mode"
            read -r ettercap_mode
            
            case $ettercap_mode in
                1)
                    log_command "sudo ettercap -T -i $CURRENT_INTERFACE"
                    sudo ettercap -T -i "$CURRENT_INTERFACE"
                    ;;
                2)
                    log_command "sudo ettercap -G -i $CURRENT_INTERFACE"
                    sudo ettercap -G -i "$CURRENT_INTERFACE" &
                    ;;
                3)
                    log_command "sudo ettercap -C -i $CURRENT_INTERFACE"
                    sudo ettercap -C -i "$CURRENT_INTERFACE"
                    ;;
                *)
                    echo -e "${RED}Invalid option${NC}"
                    return
                    ;;
            esac
            ;;
        4)
            echo -e "${YELLOW}SSL Stripping with sslstrip${NC}"
            check_tool "sslstrip" "sslstrip" || return
            
            get_interface || return
            
            echo -e "${GREEN}Enter port to listen on (default: 8080):${NC}"
            read -r sslstrip_port
            sslstrip_port=${sslstrip_port:-8080}
            
            echo -e "${YELLOW}Setting up iptables rules...${NC}"
            sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port "$sslstrip_port"
            sudo iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port "$sslstrip_port"
            
            local logfile
            logfile="$SESSION_DIR/captures/sslstrip_$(date +%Y%m%d_%H%M%S).log"
            
            echo -e "${YELLOW}Starting sslstrip on port $sslstrip_port${NC}"
            echo -e "${RED}Press any key to stop${NC}"
            log_command "sudo sslstrip -l $sslstrip_port -w $logfile"
            sudo sslstrip -l "$sslstrip_port" -w "$logfile" &
            local sslstrip_pid=$!
            BACKGROUND_PIDS+=("$sslstrip_pid")
            
            read -n 1 -s
            
            kill "$sslstrip_pid" 2>/dev/null || true
            sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port "$sslstrip_port" 2>/dev/null || true
            sudo iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port "$sslstrip_port" 2>/dev/null || true
            
            echo -e "${YELLOW}✓ SSL stripping stopped${NC}"
            echo -e "${GREEN}Log saved to: $logfile${NC}"
            log_event "SSL stripping stopped"
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            return
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# DNS Spoofing function
dns_spoof() {
    header
    echo -e "${GREEN}═══ DNS Spoofing Options ═══${NC}"
    echo -e "${RED}⚠️  WARNING: DNS spoofing can redirect legitimate traffic${NC}"
    echo -e "${RED}⚠️  Use only with explicit authorization${NC}"
    echo ""
    echo "1. DNSchef (Python-based)"
    echo "2. Ettercap DNS spoofing"
    echo "3. Return to main menu"
    echo ""
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}DNS Spoofing with DNSchef${NC}"
            
            if ! command -v dnschef &> /dev/null && ! command -v dnschef.py &> /dev/null; then
                echo -e "${RED}DNSchef not found${NC}"
                echo -e "${YELLOW}Install from: https://github.com/iphelix/dnschef${NC}"
                return
            fi
            
            get_interface || return
            
            echo -e "${GREEN}Enter IP address to redirect requests to:${NC}"
            read -r redirect_ip
            
            if [ -z "$redirect_ip" ]; then
                echo -e "${RED}No IP specified${NC}"
                return
            fi
            
            echo -e "${GREEN}Enter domain to spoof (leave empty for all domains):${NC}"
            read -r spoof_domain
            
            local local_ip
            local_ip=$(ip addr show "$CURRENT_INTERFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
            
            if [ -z "$local_ip" ]; then
                echo -e "${RED}Could not determine interface IP${NC}"
                return
            fi
            
            echo -e "${RED}Press Ctrl+C or any key to stop${NC}"
            
            if [ -z "$spoof_domain" ]; then
                echo -e "${YELLOW}Redirecting all domains to $redirect_ip${NC}"
                log_command "dnschef -i $local_ip --fakeip=$redirect_ip"
                sudo dnschef -i "$local_ip" --fakeip="$redirect_ip" &
            else
                echo -e "${YELLOW}Redirecting $spoof_domain to $redirect_ip${NC}"
                log_command "dnschef -i $local_ip --fakedomains=$spoof_domain=$redirect_ip"
                sudo dnschef -i "$local_ip" --fakedomains="$spoof_domain=$redirect_ip" &
            fi
            
            local dnschef_pid=$!
            BACKGROUND_PIDS+=("$dnschef_pid")
            
            read -n 1 -s
            
            kill "$dnschef_pid" 2>/dev/null || true
            echo -e "${YELLOW}✓ DNS spoofing stopped${NC}"
            log_event "DNS spoofing stopped"
            ;;
        2)
            echo -e "${YELLOW}DNS Spoofing with Ettercap${NC}"
            check_tool "ettercap" "ettercap-graphical" || return
            
            echo -e "${GREEN}Enter domain to spoof:${NC}"
            read -r spoof_domain
            echo -e "${GREEN}Enter IP address to redirect to:${NC}"
            read -r redirect_ip
            
            if [ -z "$spoof_domain" ] || [ -z "$redirect_ip" ]; then
                echo -e "${RED}Invalid input${NC}"
                return
            fi
            
            local dns_file
            dns_file="$SESSION_DIR/etter_$(date +%Y%m%d_%H%M%S).dns"
            echo "$spoof_domain A $redirect_ip" > "$dns_file"
            echo -e "${GREEN}✓ Created DNS spoofing configuration${NC}"
            
            get_interface || return
            
            echo -e "${YELLOW}Starting Ettercap for DNS spoofing${NC}"
            log_command "sudo ettercap -T -i $CURRENT_INTERFACE -P dns_spoof -M arp:remote // //"
            sudo ettercap -T -i "$CURRENT_INTERFACE" -P dns_spoof -M arp:remote // //
            ;;
        3)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            return
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Wireless attacks function
wireless_attacks() {
    header
    echo -e "${GREEN}═══ Wireless Attack Options ═══${NC}"
    echo -e "${RED}⚠️  WARNING: Wireless attacks can cause service disruption${NC}"
    echo -e "${RED}⚠️  Use only on networks you own or have authorization to test${NC}"
    echo ""
    echo "1. Scan for networks"
    echo "2. Deauthentication attack (aireplay-ng)"
    echo "3. WPA/WPA2 handshake capture"
    echo "4. WPS attack (reaver)"
    echo "5. Crack captured handshake"
    echo "6. Disable monitor mode"
    echo "7. Return to main menu"
    echo ""
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}Scanning for wireless networks${NC}"
            check_tool "airodump-ng" "aircrack-ng" || return
            
            get_monitor_interface || return
            
            echo -e "${YELLOW}Scanning on interface $MONITOR_INTERFACE${NC}"
            echo -e "${YELLOW}Press Ctrl+C to stop scanning${NC}"
            log_command "sudo airodump-ng $MONITOR_INTERFACE"
            sudo airodump-ng "$MONITOR_INTERFACE"
            ;;
        2)
            echo -e "${YELLOW}Deauthentication attack with aireplay-ng${NC}"
            check_tool "aireplay-ng" "aircrack-ng" || return
            
            if [ -z "${MONITOR_INTERFACE:-}" ]; then
                get_monitor_interface || return
            fi
            
            echo -e "${GREEN}Enter target BSSID (MAC address):${NC}"
            read -r bssid
            
            if [ -z "$bssid" ]; then
                echo -e "${RED}No BSSID specified${NC}"
                return
            fi
            
            echo -e "${GREEN}Enter target client MAC (leave empty for broadcast):${NC}"
            read -r client_mac
            
            echo -e "${GREEN}Enter number of deauth packets (0 for continuous):${
