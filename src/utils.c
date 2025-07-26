#include "ft_malcolm.h"

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
		// Check if the interface is up and not a loopback
		if ((ifa->ifa_flags & IFF_LOOPBACK) == 0
			&& (ifa->ifa_flags & IFF_UP) != 0
			&& ifa->ifa_addr->sa_family == AF_INET)
		{
			ft_strlcpy(ifname, ifa->ifa_name, len);
			freeifaddrs(ifaddr);
			return (0);
		}
	}
	freeifaddrs(ifaddr);
	fprintf(stderr, "No suitable network interface found.\n");
	return (1);
}

int get_interface_mac(const char *ifname, char *mac_str)
{
	int			 sockfd;
	struct ifreq ifr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		perror("socket for MAC retrieval");
		return (1);
	}

	ft_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ioctl SIOCGIFHWADDR");
		close(sockfd);
		return (1);
	}

	close(sockfd);

	// Convert MAC to string format
	unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	snprintf(mac_str, MAC_ADDR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
			 mac[1], mac[2], mac[3], mac[4], mac[5]);

	return (0);
}
