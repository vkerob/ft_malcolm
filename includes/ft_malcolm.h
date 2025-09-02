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
#include <pthread.h>
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
#define COLOR_RESET "\033[0m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_RED "\033[1;31m"

extern int		 g_raw_socket;
extern pthread_t g_forward_thread;
extern bool		 g_thread_active;

typedef struct s_args
{
	char source_ip[INET_ADDRSTRLEN];  // IP address of the spoofed victim
	char source_mac[MAC_ADDR_LEN];	  // MAC address of the attacker
	char target_ip[INET_ADDRSTRLEN];  // IP address of the victim who wants to
									  // communicate with the spoofed victim
	char target_mac[MAC_ADDR_LEN];	  // MAC address of the victim who wants to
									  // communicate with the
									  // spoofed ip
	char source_ip_mac[MAC_ADDR_LEN]; // MAC address of the source IP
	char ifname[IFNAMSIZ];
	bool mitm_attack;
	bool verbose;
} t_args;

typedef struct s_forward_args
{
	int		sockfd;
	t_args *args;
} t_forward_args;

// src/signal_handler.c
void setup_signal_handlers();

// src/program_utils.c
int parse_flags(int *argc, char ***argv, t_args *args);
int parse_args(int argc, char **argv, t_args *args);
int detect_interface(char *ifname, size_t len);

// src/display.c
void print_ip_decimal(const char *label, const char *ip_str);
void print_arp_packet(const unsigned char *buffer, ssize_t size);
void print_config_summary(t_args *args);
void print_sent_arp_reply(t_args *args);

// src/network_core.c
int setup_socket(const char *ifname);

// src/arp_protocol.c
int	  wait_for_arp_request(int sockfd, t_args *args, bool verbose);
void  send_arp_reply(int sockfd, t_args *args);
void  perform_mitm_attack(int sockfd, t_args *args);
void *traffic_forwarding_thread(void *arg);
void  create_arp_packet(unsigned char *packet, t_args *args,
						const char *sender_mac, const char *spoofed_ip,
						const char *target_mac, const char *target_ip);
int	  send_arp_packet_raw(int sockfd, t_args *args, const unsigned char *packet,
						  const char *target_mac);
void  send_arp_packet(int sockfd, t_args *args, const char *sender_mac,
					  const char *sender_ip, const char *target_mac,
					  const char *target_ip);

// src/mitm_core.c
void analyze_http_traffic(const unsigned char *packet, ssize_t size);
void increment_traffic_counter(const char *protocol);
void print_traffic_summary();

#endif