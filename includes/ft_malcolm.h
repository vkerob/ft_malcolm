#ifndef FT_MALCOLM_H
#define FT_MALCOLM_H

#include "../libft/libft.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h> // getifaddrs / freeifaddrs
#include <net/if.h>	 // for IFNAMSIZ
#include <netdb.h>
#include <netinet/if_ether.h> // struct ether_header
#include <netinet/in.h>
#include <netpacket/packet.h> // struct sockaddr_ll
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAC_ADDR_LEN 18

extern int g_raw_socket;

typedef struct s_args
{
	char source_ip[INET_ADDRSTRLEN];
	char source_mac[MAC_ADDR_LEN];
	char target_ip[INET_ADDRSTRLEN];
	char target_mac[MAC_ADDR_LEN];
	char ifname[IFNAMSIZ];
} t_args;

void setup_signal_handlers();
int	 parse_args(int argc, char **argv, t_args *args);
void print_ip_decimal(const char *label, const char *ip_str);
int	 setup_socket(const char *ifname);
void print_arp_packet(const unsigned char *buffer, ssize_t size);

#endif