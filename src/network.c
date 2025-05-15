#include "../includes/ft_malcolm.h"

int setup_socket(const char *ifname)
{
	int				   sockfd;
	struct ifreq	   ifr;
	struct sockaddr_ll saddr;

	// Create a raw socket for ARP protocol (Ethernet level)
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sockfd < 0)
	{
		perror("socket");
		return (-1);
	}

	// Get the interface index from its name (e.g., "enp0s3")
	memset(&ifr, 0, sizeof(struct ifreq));
	ft_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("ioctl - SIOCGIFINDEX");
		close(sockfd);
		return (-1);
	}

	// Prepare sockaddr_ll to bind the socket to the interface
	memset(&saddr, 0, sizeof(struct sockaddr_ll));
	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ARP);
	saddr.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
	{
		perror("bind");
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}
