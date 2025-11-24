#include "ft_malcolm.h"
#include "packet_utils.h"

void print_sent_arp_reply(char *ifname, char *src_mac, char *spoofed_ip,
						  char *target_mac, char *target_ip)
{
	printf(COLOR_GREEN "====================== ARP Reply Sent "
					   "======================\n" COLOR_RESET);
	printf(COLOR_CYAN "From Interface          : " COLOR_RESET "%s\n", ifname);
	printf(COLOR_CYAN "Ethernet Dest MAC       : " COLOR_RESET COLOR_BLUE
					  "%s\n" COLOR_RESET,
		   target_mac);
	printf(COLOR_CYAN "Ethernet Source MAC     : " COLOR_RESET COLOR_YELLOW
					  "%s\n" COLOR_RESET,
		   src_mac);
	printf(COLOR_CYAN "EtherType               : " COLOR_RESET COLOR_YELLOW
					  "0x0806 (ARP)\n" COLOR_RESET);
	printf(COLOR_CYAN "src MAC              : " COLOR_RESET COLOR_GREEN
					  "%s\n" COLOR_RESET,
		   src_mac);
	printf(COLOR_CYAN "src IP (spoofed)     : " COLOR_RESET COLOR_GREEN
					  "%s\n" COLOR_RESET,
		   spoofed_ip);
	printf(COLOR_CYAN "Target MAC              : " COLOR_RESET COLOR_BLUE
					  "%s\n" COLOR_RESET,
		   target_mac);
	printf(COLOR_CYAN "Target IP               : " COLOR_RESET COLOR_BLUE
					  "%s\n" COLOR_RESET,
		   target_ip);
	printf(COLOR_GREEN "Message: Telling %s that %s is at %s\n" COLOR_RESET,
		   target_ip, spoofed_ip, src_mac);
	printf(COLOR_GREEN
		   "========================================================"
		   "=======\n\n" COLOR_RESET);
}

void print_ip_decimal(const char *label, const char *ip_str)
{
	struct in_addr ip;
	if (inet_pton(AF_INET, ip_str, &ip) != 1)
	{
		fprintf(stderr, COLOR_RED "Failed to convert IP: %s\n" COLOR_RESET,
				ip_str);
		return;
	}
	uint32_t decimal_ip = ntohl(ip.s_addr);
	printf(COLOR_CYAN "%s (decimal) : " COLOR_RESET COLOR_YELLOW
					  "%u\n" COLOR_RESET,
		   label, decimal_ip);
}

void print_arp_packet(const unsigned char *buffer, ssize_t size)
{

	if (size < ARP_PACKET_MIN_LEN) /* ETH_HDR_LEN + ARP_HDR_LEN */
	{
		printf(COLOR_RED "Packet too short to be an ARP frame.\n" COLOR_RESET);
		return;
	}

	const unsigned char *eth_header = buffer;
	uint16_t			 opcode;
	opcode = pkt_get_arp_opcode(buffer);
	const unsigned char *src_mac = pkt_arp_src_mac(buffer);
	const unsigned char *src_ip = pkt_arp_src_ip(buffer);
	const unsigned char *target_mac = pkt_arp_target_mac(buffer);
	const unsigned char *target_ip = pkt_arp_target_ip(buffer);

	char ip_str[INET_ADDRSTRLEN];

	if (opcode == 1)
	{
		printf(COLOR_BLUE "====================== ARP Request Received "
						  "======================\n" COLOR_RESET);
		printf(COLOR_GREEN
			   "Operation               : ARP Request (1)\n" COLOR_RESET);
	}
	else if (opcode == 2)
	{
		printf(COLOR_BLUE "====================== ARP Reply Received "
						  "======================\n" COLOR_RESET);
		printf(COLOR_GREEN
			   "Operation               : ARP Reply (2)\n" COLOR_RESET);
	}
	else
	{
		printf(COLOR_BLUE "====================== ARP Packet Received "
						  "======================\n" COLOR_RESET);
		printf(COLOR_YELLOW
			   "Operation               : Unknown (%d)\n" COLOR_RESET,
			   opcode);
	}

	// Ethernet
	printf(COLOR_CYAN "Ethernet Destination MAC: " COLOR_RESET COLOR_YELLOW
					  "%02x:%02x:%02x:%02x:%02x:%02x\n" COLOR_RESET,
		   eth_header[0], eth_header[1], eth_header[2], eth_header[3],
		   eth_header[4], eth_header[5]);

	printf(COLOR_CYAN "Ethernet Source MAC     : " COLOR_RESET COLOR_YELLOW
					  "%02x:%02x:%02x:%02x:%02x:%02x\n" COLOR_RESET,
		   eth_header[6], eth_header[7], eth_header[8], eth_header[9],
		   eth_header[10], eth_header[11]);

	uint16_t ethertype;
	memcpy(&ethertype, eth_header + ETH_TYPE_OFFSET, sizeof(ethertype));
	ethertype = ntohs(ethertype);
	printf(COLOR_CYAN "EtherType               : " COLOR_RESET COLOR_YELLOW
					  "0x%04x\n" COLOR_RESET,
		   ethertype);

	// ARP information
	printf(COLOR_CYAN "src MAC              : " COLOR_RESET COLOR_GREEN
					  "%02x:%02x:%02x:%02x:%02x:%02x\n" COLOR_RESET,
		   src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4],
		   src_mac[5]);

	if (inet_ntop(AF_INET, src_ip, ip_str, sizeof(ip_str)))
		printf(COLOR_CYAN "src IP               : " COLOR_RESET COLOR_GREEN
						  "%s\n" COLOR_RESET,
			   ip_str);
	else
		printf(COLOR_CYAN "src IP               : " COLOR_RESET COLOR_RED
						  "(invalid)\n" COLOR_RESET);

	printf(COLOR_CYAN "Target MAC              : " COLOR_RESET COLOR_BLUE
					  "%02x:%02x:%02x:%02x:%02x:%02x\n" COLOR_RESET,
		   target_mac[0], target_mac[1], target_mac[2], target_mac[3],
		   target_mac[4], target_mac[5]);

	if (inet_ntop(AF_INET, target_ip, ip_str, sizeof(ip_str)))
		printf(COLOR_CYAN "Target IP               : " COLOR_RESET COLOR_BLUE
						  "%s\n" COLOR_RESET,
			   ip_str);
	else
		printf(COLOR_CYAN "Target IP               : " COLOR_RESET COLOR_RED
						  "(invalid)\n" COLOR_RESET);

	printf(COLOR_BLUE "========================================================"
					  "=======\n\n" COLOR_RESET);
}

void print_config_summary(t_args *args)
{
	printf(COLOR_BLUE "==================== Selected parameters "
					  "====================\n" COLOR_RESET);
	printf(COLOR_CYAN "Interface  : " COLOR_RESET "%s\n", args->ifname);
	printf(COLOR_CYAN "Gateway IP : " COLOR_RESET "%s\n", args->source_ip);
	printf(COLOR_CYAN "Our MAC    : " COLOR_RESET "%s " COLOR_YELLOW
					  "(attacker)\n" COLOR_RESET,
		   args->source_mac);
	printf(COLOR_CYAN "target IP  : " COLOR_RESET "%s\n", args->target_ip);
	printf(COLOR_CYAN "target MAC : " COLOR_RESET "%s\n", args->target_mac);
	printf(COLOR_CYAN "Attack Mode: " COLOR_RESET "%s\n",
		   args->mitm_attack ? COLOR_GREEN "ENABLED" COLOR_RESET
							 : COLOR_RED "DISABLED" COLOR_RESET);
	printf(COLOR_BLUE "========================================================"
					  "\n===\n\n" COLOR_RESET);
	printf(COLOR_YELLOW "[Verbose] IPs in decimal notation:\n" COLOR_RESET);
	print_ip_decimal("Source IP (dec)", args->source_ip);
	print_ip_decimal("Target IP (dec)", args->target_ip);
	printf("\n");
}
