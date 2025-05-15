#ifndef FT_MALCOLM_H
#define FT_MALCOLM_H

#include "../libft/libft.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h> // getifaddrs / freeifaddrs
#include <net/if.h>
#include <netinet/if_ether.h> // struct ether_header
#include <netinet/in.h>
#include <netpacket/packet.h> // struct sockaddr_ll
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

extern int g_raw_socket;

typedef struct s_args
{
	char source_ip[INET_ADDRSTRLEN];
	char source_mac[18];
	char target_ip[INET_ADDRSTRLEN];
	char target_mac[18];
	char ifname[IFNAMSIZ];
} t_args;

#endif