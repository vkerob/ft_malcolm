#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}====================================================="
echo -e "           FT_MALCOLM - Command Generator           "
echo -e "=====================================================${NC}"
echo ""

# Automatic network configuration
SOURCE_IP="172.31.42.254"    # Gateway IP to spoof (source_ip in ft_malcolm)
TARGET_IP="172.31.42.10"     # Target IP
GATEWAY_IP="172.31.42.254"   # Gateway IP (same as source_ip)

# Function to get MAC addresses
get_mac_addresses() {
    echo -e "${YELLOW}[Info] Retrieving MAC addresses...${NC}"
    
    # Current source container MAC (source_mac in ft_malcolm)
    SOURCE_MAC=$(ip link show eth0 | awk '/ether/ {print $2}')
    
    # Target MAC (ping then retrieve from ARP)
    ping -c 1 $TARGET_IP > /dev/null 2>&1
    TARGET_MAC=$(ip neigh show $TARGET_IP | awk '{print $5}' | head -1)
    
    # Gateway MAC (ping then retrieve from ARP)
    ping -c 1 $GATEWAY_IP > /dev/null 2>&1
    GATEWAY_MAC=$(ip neigh show $GATEWAY_IP | awk '{print $5}' | head -1)
    
    echo -e "  ${WHITE}Source MAC (eth0):${NC} $SOURCE_MAC"
    echo -e "  ${WHITE}Target MAC ($TARGET_IP):${NC} $TARGET_MAC"
    echo -e "  ${WHITE}Gateway MAC ($GATEWAY_IP):${NC} $GATEWAY_MAC"
    echo ""
}

# Retrieve MACs
get_mac_addresses

# Check that all MACs were retrieved
if [ -z "$SOURCE_MAC" ] || [ -z "$TARGET_MAC" ] || [ -z "$GATEWAY_MAC" ]; then
    echo -e "${RED}[Error] Unable to retrieve all necessary MAC addresses.${NC}"
    echo -e "${RED}Make sure target and gateway containers are running.${NC}"
    exit 1
fi

echo -e "${CYAN}====================================================="
echo -e "                  COMMANDS TO COPY                  "
echo -e "=====================================================${NC}"
echo ""

echo -e "${BLUE}🔹 CLASSIC VERSION (passive monitoring):${NC}"
echo -e "   Listen for ARP requests and respond by spoofing the gateway"
echo ""
echo -e "   ${GREEN}./ft_malcolm $SOURCE_IP $SOURCE_MAC $TARGET_IP $TARGET_MAC${NC}"
echo ""

echo -e "${MAGENTA}-----------------------------------------------------${NC}"
echo ""

echo -e "${BLUE}🔸 CLASSIC + VERBOSE (passive monitoring + details):${NC}"
echo -e "   Same as classic version but with detailed information"
echo ""
echo -e "   ${GREEN}./ft_malcolm --verbose $SOURCE_IP $SOURCE_MAC $TARGET_IP $TARGET_MAC${NC}"
echo ""

echo -e "${MAGENTA}-----------------------------------------------------${NC}"
echo ""

echo -e "${BLUE}🔶 ATTACK VERSION (active MITM):${NC}"
echo -e "   Launch complete MITM attack with ARP poisoning"
echo -e "   (Gateway MAC required for bidirectional poisoning)"
echo ""
echo -e "   ${GREEN}./ft_malcolm --attack=$GATEWAY_MAC $SOURCE_IP $SOURCE_MAC $TARGET_IP $TARGET_MAC${NC}"
echo ""

echo -e "${MAGENTA}-----------------------------------------------------${NC}"
echo ""

echo -e "${BLUE}🔺 ATTACK + VERBOSE (active MITM + details):${NC}"
echo -e "   Same as attack version but with detailed information"
echo ""
echo -e "   ${GREEN}./ft_malcolm --verbose --attack=$GATEWAY_MAC $SOURCE_IP $SOURCE_MAC $TARGET_IP $TARGET_MAC${NC}"
echo ""

echo -e "${CYAN}====================================================="
echo -e "                      USAGE                         "
echo -e "=====================================================${NC}"
echo ""
echo -e "${YELLOW}1. Copy the desired command${NC}"
echo -e "${YELLOW}2. Execute it in this container${NC}"
echo -e "${YELLOW}3. To test, from the target container:${NC}"
echo -e "   ${WHITE}docker exec -it target ping 8.8.8.8${NC}"
echo ""
echo -e "${RED}Note: Use Ctrl+C to stop ft_malcolm${NC}"
echo ""

echo -e "${CYAN}====================================================="
echo -e "               DEBUG INFORMATION                     "
echo -e "=====================================================${NC}"
echo ""
echo -e "${WHITE}Current network configuration:${NC}"
echo -e "  ${YELLOW}- Source IP:${NC} $SOURCE_IP"
echo -e "  ${YELLOW}- Target IP:${NC} $TARGET_IP" 
echo -e "  ${YELLOW}- Gateway IP:${NC} $GATEWAY_IP"
echo ""
echo -e "${WHITE}ft_malcolm parameters:${NC}"
echo -e "  ${YELLOW}- source_ip  =${NC} $SOURCE_IP"
echo -e "  ${YELLOW}- source_mac =${NC} $SOURCE_MAC"
echo -e "  ${YELLOW}- target_ip  =${NC} $TARGET_IP"
echo -e "  ${YELLOW}- target_mac =${NC} $TARGET_MAC"
echo ""
echo -e "${WHITE}Current ARP table:${NC}"
ip neigh
echo ""
echo -e "${WHITE}Network interface:${NC}"
ip addr show eth0 | grep -E "(inet |ether )"
echo ""
