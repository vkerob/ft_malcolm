#include "ft_malcolm.h"
#include "packet_utils.h"



void print_traffic_summary()
{
	if (atomic_load(&g_http_packets) == 0)
	{
		printf(COLOR_YELLOW
			   "[MITM] No web traffic intercepted yet...\n" COLOR_RESET);
		return;
	}

	printf(COLOR_GREEN
		   "[MITM] Intercepted %lu http requests %s\n",
		   atomic_load(&g_http_packets), COLOR_RESET);
}

bool is_ip_packet(const unsigned char *packet)
{
	uint16_t ethertype;
	memcpy(&ethertype, packet + ETH_TYPE_OFFSET, sizeof(ethertype));
	ethertype = ntohs(ethertype);
	return (ethertype == ETH_P_IP);
}

bool is_http_port(uint16_t port)
{
	return (port == 80 || port == 8080);
}

void extract_domain_from_http(const unsigned char *payload,
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