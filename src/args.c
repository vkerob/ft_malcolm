#include "ft_malcolm.h"

static int is_valid_mac(const char *mac)
{
	if (ft_strlen(mac) != 17)
		return (0);
	for (int i = 0; i < 17; i++)
	{
		if ((i % 3 == 2 && mac[i] != ':')
			|| (i % 3 != 2 && !ft_isxdigit(mac[i])))
			return (0);
	}
	return (1);
}

static int resolve_ip(const char *input, char *dst, const char *label)
{
	struct in_addr	tmp_addr;
	struct addrinfo hints, *res;
	int				ret;

	// Try with inet_pton first for IPv4 if the input is a valid IP address
	if (inet_pton(AF_INET, input, &tmp_addr) == 1)
	{
		ft_strlcpy(dst, input, INET_ADDRSTRLEN);
		return (0);
	}

	// else, use getaddrinfo for hostname resolution (bonus)
	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;	  // IPv4 only
	hints.ai_socktype = SOCK_RAW; // useless because we don't create a socket
	ret = getaddrinfo(input, NULL, &hints, &res);
	if (ret != 0)
	{
		fprintf(stderr, "Error resolving %s (%s): %s\n", label, input,
				gai_strerror(ret));
		return (1);
	}

	// Extract the IP address res->ai_addr, is at binary format
	struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
	if (!inet_ntop(AF_INET, &addr->sin_addr, dst, INET_ADDRSTRLEN))
	{
		fprintf(stderr, "inet_ntop failed for %s\n", label);
		freeaddrinfo(res);
		return (1);
	}

	freeaddrinfo(res);
	return (0);
}

int parse_args(int argc, char **argv, t_args *args)
{
	if (argc != 5)
	{
		fprintf(stderr,
				"Usage: ./ft_malcolm [--verbose] [--attack] <src_ip> <src_mac> "
				"<target_ip> <target_mac>\n");
		fprintf(stderr, "Options:\n");
		fprintf(stderr, "  --verbose  Show detailed ARP packet information\n");
		fprintf(stderr, "  --attack   Enable full MITM attack with ARP "
						"flooding and traffic forwarding\n");
		return (1);
	}

	// Source IP resolution
	if (resolve_ip(argv[1], args->source_ip, "source IP/hostname"))
		return (1);

	// Source MAC
	if (!is_valid_mac(argv[2]))
	{
		fprintf(stderr, "Invalid source MAC address: %s\n", argv[2]);
		return (1);
	}
	ft_strlcpy(args->source_mac, argv[2], MAC_ADDR_LEN);

	// Target IP resolution
	if (resolve_ip(argv[3], args->target_ip, "target IP/hostname"))
		return (1);

	// Target MAC
	if (!is_valid_mac(argv[4]))
	{
		fprintf(stderr, "Invalid target MAC address: %s\n", argv[4]);
		return (1);
	}
	ft_strlcpy(args->target_mac, argv[4], MAC_ADDR_LEN);

	return (0);
}
