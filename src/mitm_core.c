#include "ft_malcolm.h"


static int g_http_packets = 0;
static int g_https_packets = 0;
static int g_total_intercepted = 0;

void increment_traffic_counter(const char *protocol)
{
	if (!protocol)
		return;

	g_total_intercepted++;

	if (ft_strcmp(protocol, "HTTP") == 0)
		g_http_packets++;
	else if (ft_strcmp(protocol, "HTTPS") == 0)
		g_https_packets++;
}

void print_traffic_summary()
{
	if (g_total_intercepted == 0)
	{
		printf(COLOR_YELLOW
			   "[MITM] No web traffic intercepted yet...\n" COLOR_RESET);
		return;
	}

	printf(COLOR_GREEN
		   "[MITM] Intercepted %d web requests (%d HTTP, %d HTTPS)%s\n",
		   g_total_intercepted, g_http_packets, g_https_packets, COLOR_RESET);
}

static bool is_ip_packet(const unsigned char *packet)
{
	return (packet[12] == 0x08 && packet[13] == 0x00);
}

static bool is_web_port(uint16_t port)
{
	return (port == 80 || port == 443 || port == 8080 || port == 8443);
}

static bool is_https_port(uint16_t port)
{
	return (port == 443 || port == 8443);
}

static void extract_domain_from_http(const unsigned char *payload,
									 int payload_len, char *domain)
{
	char *host_start = ft_strnstr((char *)payload, "Host: ", payload_len);
	if (!host_start)
	{
		ft_strlcpy(domain, "unknown", 8);
		return;
	}

	host_start += 6; // Skip "Host: "
	char *host_end = ft_strchr(host_start, '\r');
	if (!host_end)
		host_end = ft_strchr(host_start, '\n');

	if (host_end)
	{
		int domain_len = host_end - host_start;
		if (domain_len < 255)
		{
			ft_strlcpy(domain, host_start, domain_len + 1);
			return;
		}
	}
	ft_strlcpy(domain, "unknown", 8);
}

void analyze_http_traffic(const unsigned char *packet, ssize_t size)
{
	// Basic packet validation
	if (size < 54 || !is_ip_packet(packet))
		return;

	// Parse IP header
	const unsigned char *ip_header = packet + 14;
	uint8_t				 ip_header_len = (ip_header[0] & 0x0F) * 4;
	uint8_t				 ip_protocol = ip_header[9];

	// Only analyze TCP traffic
	if (ip_protocol != 6)
		return;

	// Parse TCP header
	const unsigned char *tcp_header = packet + 14 + ip_header_len;
	uint16_t			 src_port = (tcp_header[0] << 8) | tcp_header[1];
	uint16_t			 dst_port = (tcp_header[2] << 8) | tcp_header[3];

	// Filter web traffic only
	if (!is_web_port(src_port) && !is_web_port(dst_port))
		return;

	// Extract payload
	uint8_t				 tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;
	const unsigned char *payload = tcp_header + tcp_header_len;
	int payload_len = size - 14 - ip_header_len - tcp_header_len;

	if (payload_len <= 10)
		return;

	// Determine protocol and extract domain
	bool is_https = is_https_port(src_port) || is_https_port(dst_port);
	char domain[256] = "unknown";

	if (!is_https)
		extract_domain_from_http(payload, payload_len, domain);

	// Log traffic with minimal output and deduplication
	const char *protocol = is_https ? "HTTPS" : "HTTP";
	increment_traffic_counter(protocol);

	// Simple deduplication: avoid showing same domain repeatedly
	static char	  last_domain[256] = "";
	static time_t last_time = 0;
	time_t		  now = time(NULL);

	if (ft_strcmp(domain, last_domain) != 0 || (now - last_time) > 5)
	{
		printf(COLOR_CYAN "[%s] %s\n" COLOR_RESET, protocol, domain);
		ft_strlcpy(last_domain, domain, sizeof(last_domain));
		last_time = now;
	}
}
