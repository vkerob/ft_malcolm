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

int parse_flags(int *argc, char ***argv, t_args *args)
{
	int	 i = 1;
	char source_ip_mac[MAC_ADDR_LEN] = { 0 };

	// Initialize flags to default values
	args->verbose = false;
	args->mitm_attack = false;

	while (i < *argc && (*argv)[i][0] == '-')
	{
		if (ft_strcmp((*argv)[i], "--verbose") == 0)
		{
			args->verbose = true;
			i++;
		}
		else if (ft_strncmp((*argv)[i], "--attack", 8) == 0)
		{
			args->mitm_attack = true;
			// Check if --attack=MAC_ADDRESS format
			if ((*argv)[i][8] == '=' && (*argv)[i][9] != '\0')
			{
				// Copy the MAC address after the '='
				ft_strlcpy(source_ip_mac, &(*argv)[i][9], MAC_ADDR_LEN);
				printf(COLOR_CYAN
					   "[Info] Source IP MAC provided: %s\n" COLOR_RESET,
					   source_ip_mac);
			}
			else
			{
				fprintf(stderr,
						"Error: --attack requires a MAC address(gateway): "
						"--attack=MAC_ADDRESS\n");
				fprintf(stderr,
						"Usage: ./ft_malcolm [--verbose] --attack=MAC_ADDRESS "
						"<src_ip> <src_mac> <target_ip> <target_mac>\n");
				return (1);
			}
			i++;
		}
		else
		{
			fprintf(stderr, "Unknown option: %s\n", (*argv)[i]);
			fprintf(stderr,
					"Usage: ./ft_malcolm [--verbose] --attack=MAC_ADDRESS "
					"<src_ip> <src_mac> <target_ip> <target_mac>\n");
			return (1);
		}
	}

	// Copy the provided source IP MAC if available
	if (source_ip_mac[0] != '\0')
	{
		ft_strlcpy(args->source_ip_mac, source_ip_mac, MAC_ADDR_LEN);
	}

	// Adjust argc and argv to skip processed flags
	*argc -= (i - 1);
	*argv += (i - 1);

	return (0);
}

int parse_args(int argc, char **argv, t_args *args)
{
	if (argc != 5)
	{
		fprintf(stderr,
				"Usage: ./ft_malcolm [--verbose] [--attack] <src_ip> <src_mac> "
				"<target_ip> <target_mac>\n");
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
		// Check if the interface is up, not a loopback, and has an IPv4 address
		if ((ifa->ifa_flags & IFF_LOOPBACK) == 0
			&& (ifa->ifa_flags & IFF_UP) != 0
			&& ifa->ifa_addr->sa_family == AF_INET)
		{
			ft_strlcpy(ifname, ifa->ifa_name, len);
			printf(COLOR_GREEN "Found available interface: %s\n" COLOR_RESET,
				   ifname);
			freeifaddrs(ifaddr);
			return (0);
		}
	}
	freeifaddrs(ifaddr);
	fprintf(stderr, "No suitable network interface found.\n");
	return (1);
}
