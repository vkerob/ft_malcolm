#ifndef FT_MALCOLM_H
#define FT_MALCOLM_H

#include <arpa/inet.h>
#include <ifaddrs.h> // getifaddrs / freeifaddrs
#include <net/if.h>
#include <netdb.h>
#include <netinet/if_ether.h> // struct ether_header
#include <netinet/in.h>
#include <netpacket/packet.h> // struct sockaddr_ll
#include <pthread.h>
#include <stdatomic.h>
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

extern int			g_raw_socket;
extern pthread_t	g_forward_thread;
extern atomic_ulong g_http_packets;
extern atomic_bool	g_stop;

typedef struct s_args
{
	char source_mac[MAC_ADDR_LEN];	 // attacker MAC
	char source_ip[INET_ADDRSTRLEN]; // spoofed IP
	char target_mac[MAC_ADDR_LEN];
	char target_ip[INET_ADDRSTRLEN];
	char spoofed_mac[MAC_ADDR_LEN];
	char ifname[IFNAMSIZ];
	bool mitm_attack;
	bool verbose;
} t_args;

typedef struct s_forward_args
{
	int			 sockfd;
	t_args		*args;
	unsigned int ifindex;
} t_forward_args;

// signal_handler.c
void setup_signal_handlers();

// parsing.c
int parse_flags(int *argc, char ***argv, t_args *args);
int parse_args(int argc, char **argv, t_args *args);
int detect_interface(char *ifname, size_t len);

// display.c
void print_ip_decimal(const char *label, const char *ip_str);
void print_arp_packet(const unsigned char *buffer, ssize_t size);
void print_config_summary(t_args *args);
void print_sent_arp_reply(char *ifname, char *src_mac, char *spoofed_ip,
						  char *target_mac, char *target_ip);

// network_core.c
int setup_socket(const char *ifname);

// program_utils.c
void create_arp_packet(unsigned char *packet, t_args *args, const char *src_mac,
					   const char *spoofed_ip, const char *target_mac,
					   const char *target_ip);
int	 send_arp_packet_raw(int sockfd, t_args *args, const unsigned char *packet,
						 const char *target_mac);
int	 send_arp_reply(int sockfd, t_args *args, char *src_mac, char *spoofed_ip,
					char *target_mac, char *target_ip, bool print_verbose);

// arp_reply.c
int wait_for_arp_request(int sockfd, t_args *args, bool verbose);

// mitm_core.c
void analyze_http_traffic(const unsigned char *packet, ssize_t size);
void perform_mitm_attack(int sockfd, t_args *args);

// mitm_utils.c
void print_traffic_summary();
bool is_ip_packet(const unsigned char *packet);
bool is_http_port(uint16_t port);
void extract_domain_from_http(const unsigned char *payload, int payload_len,
							  char *domain);

#endif