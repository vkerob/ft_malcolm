#include "ft_malcolm.h"

int setup_socket(const char *ifname)
{
	int sockfd;

	// Create a raw socket for ARP protocol (Ethernet level)
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sockfd < 0)
	{
		perror("socket");
		return (-1);
	}

	// Bind the socket to the specified interface using setsockopt
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
				   ft_strlen(ifname))
		< 0)
	{
		perror("setsockopt (SO_BINDTODEVICE)");
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}