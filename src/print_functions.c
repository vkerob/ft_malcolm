#include "ft_malcolm.h"

void print_sent_arp_reply(t_args *args)
{
	printf(COLOR_GREEN "====================== ARP Reply Sent "
					   "======================\n" COLOR_RESET);
	printf("From Interface          : %s\n", args->ifname);
	printf("Ethernet Dest MAC       : %s\n", args->target_mac);
	printf("Ethernet Source MAC     : %s\n", args->source_mac);
	printf("EtherType               : 0x0806 (ARP)\n");
	printf("Sender MAC (spoofed)    : %s\n", args->source_mac);
	printf("Sender IP (spoofed)     : %s\n", args->source_ip);
	printf("Target MAC              : %s\n", args->target_mac);
	printf("Target IP               : %s\n", args->target_ip);
	printf(COLOR_GREEN "Message: Telling %s that %s is at %s\n" COLOR_RESET,
		   args->target_ip, args->source_ip, args->source_mac);
	printf(COLOR_GREEN
		   "========================================================"
		   "=======\n\n" COLOR_RESET);
}

void print_sent_arp_poison(t_args *args, const char *spoofed_ip,
						   const char *target_ip, const char *target_mac,
						   int packet_num, const char *direction)
{
	printf(COLOR_RED "====================== ARP Poison Sent #%d (%s) "
					 "======================\n" COLOR_RESET,
		   packet_num, direction);
	printf("Operation               : ARP Reply (2) - POISONING\n");
	printf("From Interface          : %s\n", args->ifname);
	printf("Ethernet Dest MAC       : %s\n", target_mac);
	printf("Ethernet Source MAC     : %s\n", args->source_mac);
	printf("EtherType               : 0x0806 (ARP)\n");
	printf("Sender MAC (fake)       : %s\n", args->source_mac);
	printf("Sender IP (spoofed)     : %s\n", spoofed_ip);
	printf("Target MAC              : %s\n", target_mac);
	printf("Target IP               : %s\n", target_ip);
	printf(COLOR_RED
		   "Poison Message: Telling %s that %s is at %s (FAKE!)\n" COLOR_RESET,
		   target_ip, spoofed_ip, args->source_mac);
	printf(COLOR_RED "========================================================"
					 "=======\n\n" COLOR_RESET);
}

void print_attack_summary(int total_packets, int window_packets)
{
	printf(COLOR_BLUE "==================== Attack Summary "
					  "====================\n" COLOR_RESET);
	printf("Total ARP packets sent  : %d\n", total_packets);
	printf("Packets in last 10s     : %d\n", window_packets);
	printf("Packets per cycle       : 2 (Target + Gateway)\n");
	printf("Poisoning interval      : 2 seconds\n");
	printf("Status                  : " COLOR_GREEN "ACTIVE\n" COLOR_RESET);
	printf(COLOR_BLUE "========================================================"
					  "=======\n\n" COLOR_RESET);
}

void print_simple_arp_sent(const char *direction, int packet_num)
{
	printf(COLOR_CYAN "[ARP #%d] Sent to %s\n" COLOR_RESET, packet_num,
		   direction);
}

void print_mitm_header()
{
	printf(COLOR_RED "\n");
	printf(
		"╔══════════════════════════════════════════════════════════════╗\n");
	printf(
		"║                    🚨 MITM ATTACK ACTIVE 🚨                   ║\n");
	printf(
		"║                                                              ║\n");
	printf("║  ft_malcolm is now intercepting and analyzing all traffic   ║\n");
	printf("║  between the target and gateway. All communications are     ║\n");
	printf("║  being monitored for demonstration purposes.                ║\n");
	printf(
		"║                                                              ║\n");
	printf("║  Press Ctrl+C to stop the attack                            ║\n");
	printf(
		"╚══════════════════════════════════════════════════════════════╝\n");
	printf(COLOR_RESET "\n");
}

void print_mitm_success_banner()
{
	printf(COLOR_GREEN "\n");
	printf(
		"╔══════════════════════════════════════════════════════════════╗\n");
	printf(
		"║                   ✅ MITM ATTACK SUCCESSFUL ✅                ║\n");
	printf(
		"║                                                              ║\n");
	printf("║  ARP poisoning active - Traffic interception in progress    ║\n");
	printf("║  All network communications are now being analyzed          ║\n");
	printf(
		"║                                                              ║\n");
	printf(
		"╚══════════════════════════════════════════════════════════════╝\n");
	printf(COLOR_RESET "\n");
}

void print_ip_decimal(const char *label, const char *ip_str)
{
	struct in_addr ip;
	if (inet_pton(AF_INET, ip_str, &ip) != 1)
	{
		fprintf(stderr, "Failed to convert IP: %s\n", ip_str);
		return;
	}
	uint32_t decimal_ip = ntohl(ip.s_addr);
	printf("%s (decimal) : %u\n", label, decimal_ip);
}

void print_arp_packet(const unsigned char *buffer, ssize_t size)
{
	if (size < 42) // 14 (Ethernet) + 28 (ARP)
	{
		printf("Packet too short to be an ARP frame.\n");
		return;
	}

	const unsigned char *eth_header = buffer;
	const unsigned char *arp_header = buffer + 14;

	uint16_t			 opcode = ntohs(*(uint16_t *)(arp_header + 6));
	const unsigned char *sender_mac = arp_header + 8;
	const unsigned char *sender_ip = arp_header + 14;
	const unsigned char *target_mac = arp_header + 18;
	const unsigned char *target_ip = arp_header + 24;

	char ip_str[INET_ADDRSTRLEN];

	// Dynamic title based on packet type
	if (opcode == 1)
		printf(COLOR_BLUE "====================== ARP Request Received "
						  "======================\n" COLOR_RESET);
	else if (opcode == 2)
		printf(COLOR_BLUE "====================== ARP Reply Received "
						  "======================\n" COLOR_RESET);
	else
		printf(COLOR_BLUE "====================== ARP Packet Received "
						  "======================\n" COLOR_RESET);

	// Operation type
	if (opcode == 1)
		printf("Operation               : ARP Request (1)\n");
	else if (opcode == 2)
		printf("Operation               : ARP Reply (2)\n");
	else
		printf("Operation               : Unknown (%d)\n", opcode);

	// Ethernet
	printf("Ethernet Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   eth_header[0], eth_header[1], eth_header[2], eth_header[3],
		   eth_header[4], eth_header[5]);

	printf("Ethernet Source MAC     : %02x:%02x:%02x:%02x:%02x:%02x\n",
		   eth_header[6], eth_header[7], eth_header[8], eth_header[9],
		   eth_header[10], eth_header[11]);

	uint16_t ethertype = (eth_header[12] << 8) | eth_header[13];
	printf("EtherType               : 0x%04x\n", ethertype);

	// ARP information
	printf("Sender MAC              : %02x:%02x:%02x:%02x:%02x:%02x\n",
		   sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3],
		   sender_mac[4], sender_mac[5]);

	if (inet_ntop(AF_INET, sender_ip, ip_str, sizeof(ip_str)))
		printf("Sender IP               : %s\n", ip_str);
	else
		printf("Sender IP               : (invalid)\n");

	printf("Target MAC              : %02x:%02x:%02x:%02x:%02x:%02x\n",
		   target_mac[0], target_mac[1], target_mac[2], target_mac[3],
		   target_mac[4], target_mac[5]);

	if (inet_ntop(AF_INET, target_ip, ip_str, sizeof(ip_str)))
		printf("Target IP               : %s\n", ip_str);
	else
		printf("Target IP               : (invalid)\n");

	printf(COLOR_BLUE "========================================================"
					  "=======\n\n" COLOR_RESET);
}

void print_config_summary(t_args *args)
{
	printf(COLOR_BLUE "==================== Selected parameters "
					  "====================\n" COLOR_RESET);
	printf("Interface  : %s\n", args->ifname);
	printf("Gateway IP : %s\n", args->source_ip);
	printf("Our MAC    : %s (attacker)\n", args->source_mac);
	printf("Victim IP  : %s\n", args->target_ip);
	printf("Victim MAC : %s\n", args->target_mac);
	printf("Attack Mode: %s\n",
		   args->mitm_attack ? COLOR_GREEN "ENABLED" COLOR_RESET : "DISABLED");
	printf(COLOR_BLUE "========================================================"
					  "\n===\n\n" COLOR_RESET);
	printf(COLOR_YELLOW "[Verbose] IPs in decimal notation:\n" COLOR_RESET);
	print_ip_decimal("Source IP (dec)", args->source_ip);
	print_ip_decimal("Target IP (dec)", args->target_ip);
	printf("\n");
}
