#include "ft_malcolm.h"
#include "packet_utils.h"
#include <time.h>

int wait_for_arp_request(int sockfd, t_args *args, bool verbose)
{
	unsigned char buffer[PACKET_BUF_SIZE];
	ssize_t		  bytes;

	printf(COLOR_CYAN "[Info] Waiting for ARP request...\n" COLOR_RESET);

	while (!atomic_load(&g_stop))
	{
		// receive packet in big-endian order (network byte order)
		bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
		if (bytes < 0)
		{
			perror("recvfrom");
			return (1);
		}

		/* Need at least Ethernet header to check ethertype */
		if ((size_t)bytes < ETH_HDR_LEN)
			continue;

		uint16_t ethertype;
		ethertype = pkt_get_ethertype(buffer);
		if (ethertype != ETH_P_ARP
			|| (size_t)bytes < ARP_PACKET_MIN_LEN)
			continue;

		uint16_t opcode;
		opcode = pkt_get_arp_opcode(buffer);

		if (opcode == 1) // ARP request
		{
			/* In an incoming ARP request the target hardware address is usually
			 * all zeros because the requester does not know the target MAC.
			 * The request is broadcast to the network, so there is no useful
			 * target MAC to validate here. */
			const unsigned char *src_mac = pkt_arp_src_mac(buffer);
			const unsigned char *src_ip = pkt_arp_src_ip(buffer);
			const unsigned char *target_ip = pkt_arp_target_ip(buffer);

			char target_ip_str[INET_ADDRSTRLEN];
			char src_ip_str[INET_ADDRSTRLEN];
			char src_mac_str[18];

			inet_ntop(AF_INET, target_ip, target_ip_str, sizeof(target_ip_str));
			inet_ntop(AF_INET, src_ip, src_ip_str, sizeof(src_ip_str));
			snprintf(src_mac_str, sizeof(src_mac_str),
					 "%02x:%02x:%02x:%02x:%02x:%02x", src_mac[0], src_mac[1],
					 src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

			if (ft_strcmp(src_ip_str, args->target_ip) == 0)
			{
				printf(COLOR_GREEN
					   "An ARP request has been broadcast.\n" COLOR_RESET);
				printf(COLOR_YELLOW "mac address of request: %s\n" COLOR_RESET,
					   src_mac_str);
				printf(COLOR_YELLOW "IP address of request: %s\n" COLOR_RESET,
					   src_ip_str);

				if (verbose)
					print_arp_packet(buffer, bytes);
				return (0);
			}
		}
	}
	return (1);
}
