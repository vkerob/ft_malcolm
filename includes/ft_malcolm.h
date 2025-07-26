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

// Address families (ai_family / domain):
//   AF_INET     : IPv4
//   AF_INET6    : IPv6
//   AF_UNIX     : Local sockets (files)
//   AF_PACKET   : Low-level packet access (Linux)
//   AF_NETLINK  : Kernel/user-space communication
//   AF_BLUETOOTH: Bluetooth
//   ...

// Socket types (ai_socktype / type):
//   SOCK_STREAM    : Stream (TCP)
//   SOCK_DGRAM     : Datagram (UDP)
//   SOCK_RAW       : Raw socket (direct packet access)
//   SOCK_SEQPACKET : Sequenced, reliable, two-way connection-based data
//   transmission (rare) SOCK_RDM       : Reliably-delivered messages (rare)
//   ...

/*
 * ============================================================================
 * SYSTEM FUNCTIONS DOCUMENTATION
 * ============================================================================
 * This section documents all system functions used in ft_malcolm (non-libft).
 */

// --- NETWORK FUNCTIONS ---
// socket()         : Create a communication endpoint (socket)
// htons()          : Convert 16-bit host byte order to network byte order
// ntohs()          : Convert 16-bit network byte order to host byte order
// ntohl()          : Convert 32-bit network byte order to host byte order
// setsockopt()     : Set socket options (used for SO_BINDTODEVICE)
// sendto()         : Send data to a specific destination via socket
// recvfrom()       : Receive data from socket with sender information
// close()          : Close a file descriptor (including sockets)

// --- ADDRESS RESOLUTION FUNCTIONS ---
// inet_pton()      : Convert IP address string to binary format
// inet_ntop()      : Convert binary IP address to string format
// getaddrinfo()    : Get address information for hostname resolution
// freeaddrinfo()   : Free memory allocated by getaddrinfo()
// gai_strerror()   : Get error string for getaddrinfo() errors
// if_nametoindex() : Convert interface name to index

// --- INTERFACE ENUMERATION FUNCTIONS ---
// getifaddrs()     : Get list of network interfaces
// freeifaddrs()    : Free memory allocated by getifaddrs()

// --- SIGNAL HANDLING FUNCTIONS ---
// sigaction()      : Set signal action (preferred over signal)
// exit()           : Terminate program with status code

// --- STANDARD I/O FUNCTIONS ---
// printf()         : Print formatted output to stdout
// fprintf()        : Print formatted output to file stream
// perror()         : Print system error message to stderr
// sscanf()         : Read formatted input from string

// --- SYSTEM INFORMATION FUNCTIONS ---
// getuid()         : Get real user ID of calling process

#define MAC_ADDR_LEN 18
#define COLOR_RESET "\033[0m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_RED "\033[1;31m"

extern int g_raw_socket;

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

void  setup_signal_handlers();
int	  parse_args(int argc, char **argv, t_args *args);
void  print_ip_decimal(const char *label, const char *ip_str);
int	  setup_socket(const char *ifname);
void  print_arp_packet(const unsigned char *buffer, ssize_t size);
int	  detect_interface(char *ifname, size_t len);
void  print_config_summary(t_args *args);
void  print_sent_arp_reply(t_args *args);
void  print_sent_arp_poison(t_args *args, const char *spoofed_ip,
							const char *target_ip, const char *target_mac,
							int packet_num, const char *direction);
void  print_attack_summary(int total_packets, int window_packets);
void  print_simple_arp_sent(const char *direction, int packet_num);
int	  wait_for_arp_request(int sockfd, t_args *args, bool verbose);
void  send_arp_reply(int sockfd, t_args *args);
void  perform_mitm_attack(int sockfd, t_args *args);
void  send_arp_poison(int sockfd, t_args *args, const char *target_ip,
					  const char *target_mac, const char *spoofed_ip);
void *traffic_forwarding_thread(void *arg);
void  send_arp_packet(int sockfd, t_args *args, const char *sender_mac,
					  const char *sender_ip, const char *target_mac,
					  const char *target_ip);
void  analyze_http_traffic(const unsigned char *packet, ssize_t size);
void  search_keywords_in_traffic(const unsigned char *packet, ssize_t size);
void  analyze_icmp_traffic(const unsigned char *packet, ssize_t size);
void  print_traffic_statistics();
void  increment_traffic_counter(const char *protocol);
void  reset_traffic_statistics();
void  print_traffic_summary();
int	  get_total_intercepted_packets();
int	  get_sensitive_keywords_count();
void  print_mitm_header();
void  print_mitm_success_banner();

#endif