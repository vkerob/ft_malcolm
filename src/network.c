#include "ft_malcolm.h"
#include "libft.h"

int setup_socket(const char *ifname)
{
	int sockfd;

	// Create a raw socket for ALL protocols (Ethernet level)
	// ETH_P_ALL allows us to capture both ARP and IP traffic (for bonus)
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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