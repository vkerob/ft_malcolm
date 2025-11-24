#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include "libft.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Common packet constants used across source files */
#define PACKET_BUF_SIZE 2048
#define ETH_HDR_LEN 14
#define ETH_TYPE_OFFSET 12

/* ARP payload/layout */
#define ARP_HDR_LEN 28
#define ARP_PACKET_MIN_LEN (ETH_HDR_LEN + ARP_HDR_LEN)
#define ARP_OPCODE_OFFSET 6
#define ARP_SRC_MAC_OFFSET 8
#define ARP_SRC_IP_OFFSET 14
#define ARP_TARGET_MAC_OFFSET 18
#define ARP_TARGET_IP_OFFSET 24

/* Ethernet field values */
#define ETH_SRC_MAC_OFFSET 6


/* ARP field values */
#define ARP_HTYPE_ETH 1
#define ARP_PTYPE_IPV4 0x0800
#define ARP_HLEN_ETH 6
#define ARP_PLEN_IPV4 4
#define ARP_OPCODE_REPLY 2

/* Minimum header sizes used in packet parsing */
#define IP_HDR_MIN_LEN 20
#define TCP_HDR_MIN_LEN 20
#define IP_SRC_IP_OFFSET 12
#define IP_TARGET_IP_OFFSET 16

/* Inline accessors for packet fields (safe: use ft_memcpy to avoid alignment
 * issues) */
static inline uint16_t pkt_get_ethertype(const unsigned char *buf)
{
	uint16_t v;
	ft_memcpy(&v, buf + ETH_TYPE_OFFSET, sizeof(v));
	return ntohs(v);
}

/* Inline accessors for ARP fields */
static inline uint16_t pkt_get_arp_opcode(const unsigned char *buf)
{
	uint16_t v;
	ft_memcpy(&v, buf + ETH_HDR_LEN + ARP_OPCODE_OFFSET, sizeof(v));
	return ntohs(v);
}

static inline const unsigned char *pkt_eth_src_mac(const unsigned char *buf)
{
    return buf + ETH_SRC_MAC_OFFSET;
}


/* Inline accessors for ARP payload */
static inline const unsigned char *pkt_arp_payload(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN;
}

/* Inline accessors for ARP src MAC */
static inline const unsigned char *pkt_arp_src_mac(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN + ARP_SRC_MAC_OFFSET;
}

/* Inline accessors for ARP src IP */
static inline const unsigned char *pkt_arp_src_ip(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN + ARP_SRC_IP_OFFSET;
}

/* Inline accessors for ARP target MAC */
static inline const unsigned char *pkt_arp_target_mac(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN + ARP_TARGET_MAC_OFFSET;
}

/* Inline accessors for ARP target IP */
static inline const unsigned char *pkt_arp_target_ip(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN + ARP_TARGET_IP_OFFSET;
}

/* Inline mutators for ARP fields */
static inline void pkt_set_arp_opcode(unsigned char *buf, uint16_t opcode)
{
	uint16_t v = htons(opcode);
	ft_memcpy(buf + ETH_HDR_LEN + ARP_OPCODE_OFFSET, &v, sizeof(v));
}

/* Helpers for IP/TCP pointers */
static inline const unsigned char *pkt_ip_header(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN;
}

static inline const unsigned char *pkt_tcp_header(const unsigned char *buf,
												  size_t ip_hdr_len)
{
	return buf + ETH_HDR_LEN + ip_hdr_len;
}

static inline const unsigned char *pkt_ip_src_ip(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN + IP_SRC_IP_OFFSET;
}

static inline const unsigned char *pkt_ip_target_ip(const unsigned char *buf)
{
	return buf + ETH_HDR_LEN + IP_TARGET_IP_OFFSET;
}

#endif