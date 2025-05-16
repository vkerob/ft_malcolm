#include "../includes/ft_malcolm.h"

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

	printf(COLOR_BLUE "====================== Requête ARP reçue "
					  "======================\n" COLOR_RESET);

	// Type d'opération
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

	// ARP infos
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

int detect_interface(char *ifname, size_t len)
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		return (1);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;
		if ((ifa->ifa_flags & IFF_LOOPBACK) == 0
			&& ifa->ifa_addr->sa_family == AF_INET)
		{
			ft_strlcpy(ifname, ifa->ifa_name, len);
			freeifaddrs(ifaddr);
			return (0);
		}
	}
	freeifaddrs(ifaddr);
	fprintf(stderr, "No suitable network interface found.\n");
	return (1);
}

void print_config_summary(t_args *args, bool verbose)
{
	printf(COLOR_BLUE "==================== Selected parameters "
					  "====================\n" COLOR_RESET);
	printf("Interface  : %s\n", args->ifname);
	printf("Source IP  : %s\n", args->source_ip);
	printf("Source MAC : %s\n", args->source_mac);
	printf("Target IP  : %s\n", args->target_ip);
	printf("Target MAC : %s\n", args->target_mac);
	printf(COLOR_BLUE "========================================================"
					  "\n===\n\n" COLOR_RESET);
	if (verbose)
	{
		printf(COLOR_YELLOW "[Verbose] IPs in decimal notation:\n" COLOR_RESET);
		print_ip_decimal("Source IP (dec)", args->source_ip);
		print_ip_decimal("Target IP (dec)", args->target_ip);
		printf("\n");
	}
}

void receive_and_print_arp(int sockfd)
{
	unsigned char buffer[2048];
	ssize_t bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);

	if (bytes < 0)
	{
		perror("recvfrom");
		return;
	}

	printf("[Info] Received %zd bytes on the raw socket.\n", bytes);
	print_arp_packet(buffer, bytes);
}
