#include "ft_malcolm.h"

void analyze_http_traffic(const unsigned char *packet, ssize_t size)
{
	if (size < 54) // Ethernet(14) + IP(20) + TCP(20) minimum
		return;

	// Vérifier si c'est un paquet IP
	if (packet[12] != 0x08 || packet[13] != 0x00)
		return;

	const unsigned char *ip_header = packet + 14;
	uint8_t				 ip_header_len = (ip_header[0] & 0x0F) * 4;
	uint8_t				 protocol = ip_header[9];

	// Extract IP addresses for all protocols
	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip_header + 12, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ip_header + 16, dst_ip, INET_ADDRSTRLEN);

	// Analyze DNS traffic (UDP port 53)
	if (protocol == 17) // UDP
	{
		const unsigned char *udp_header = packet + 14 + ip_header_len;
		uint16_t			 src_port = (udp_header[0] << 8) | udp_header[1];
		uint16_t			 dst_port = (udp_header[2] << 8) | udp_header[3];

		if (src_port == 53 || dst_port == 53)
		{
			increment_traffic_counter("DNS");
			printf(COLOR_CYAN "🌐 DNS QUERY INTERCEPTED 🌐\n" COLOR_RESET);
			printf("Direction: %s:%d → %s:%d\n", src_ip, src_port, dst_ip,
				   dst_port);
			printf("Packet size: %zd bytes\n", size);
			printf(COLOR_CYAN
				   "=====================================\n" COLOR_RESET);
		}
		return;
	}

	// Analyze TCP traffic (including HTTP/HTTPS)
	if (protocol != 6) // Not TCP
		return;

	const unsigned char *tcp_header = packet + 14 + ip_header_len;
	uint16_t			 src_port = (tcp_header[0] << 8) | tcp_header[1];
	uint16_t			 dst_port = (tcp_header[2] << 8) | tcp_header[3];

	// Check for common web ports
	bool is_web_traffic
		= (src_port == 80 || dst_port == 80 || src_port == 443
		   || dst_port == 443 || src_port == 8080 || dst_port == 8080
		   || src_port == 8443 || dst_port == 8443);

	if (is_web_traffic)
	{
		uint8_t tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;
		const unsigned char *payload = tcp_header + tcp_header_len;
		int payload_len = size - 14 - ip_header_len - tcp_header_len;

		if (payload_len > 10) // Minimum payload pour HTTP
		{
			// Increment counter based on protocol
			if (src_port == 443 || dst_port == 443)
				increment_traffic_counter("HTTPS");
			else
				increment_traffic_counter("HTTP");

			printf(COLOR_RED
				   "🚨 HTTP/HTTPS TRAFFIC INTERCEPTED 🚨\n" COLOR_RESET);
			printf("Direction: %s:%d → %s:%d\n", src_ip, src_port, dst_ip,
				   dst_port);
			printf("Protocol: %s\n",
				   (src_port == 443 || dst_port == 443) ? "HTTPS" : "HTTP");
			printf("Payload size: %d bytes\n", payload_len);

			// Afficher les premiers caractères du payload si c'est du HTTP
			if (src_port == 80 || dst_port == 80 || src_port == 8080
				|| dst_port == 8080)
			{
				printf("Content preview:\n");
				int display_len = (payload_len > 200) ? 200 : payload_len;
				for (int i = 0; i < display_len; i++)
				{
					if (payload[i] >= 32 && payload[i] <= 126)
						printf("%c", payload[i]);
					else if (payload[i] == '\r')
						printf("\\r");
					else if (payload[i] == '\n')
						printf("\\n\n");
					else
						printf(".");
				}
				printf("\n");
			}
			else
			{
				printf("HTTPS content (encrypted)\n");
			}
			printf(COLOR_RED
				   "=====================================\n" COLOR_RESET);
		}
	}
	// Analyze other interesting TCP ports
	else if (src_port == 22 || dst_port == 22) // SSH
	{
		increment_traffic_counter("SSH");
		printf(COLOR_YELLOW "🔒 SSH CONNECTION INTERCEPTED 🔒\n" COLOR_RESET);
		printf("Direction: %s:%d → %s:%d\n", src_ip, src_port, dst_ip,
			   dst_port);
		printf("Protocol: SSH (encrypted)\n");
		printf(COLOR_YELLOW
			   "=====================================\n" COLOR_RESET);
	}
	else if (src_port == 21 || dst_port == 21) // FTP
	{
		increment_traffic_counter("FTP");
		printf(COLOR_YELLOW "📁 FTP CONNECTION INTERCEPTED 📁\n" COLOR_RESET);
		printf("Direction: %s:%d → %s:%d\n", src_ip, src_port, dst_ip,
			   dst_port);
		printf("Protocol: FTP (plaintext)\n");
		printf(COLOR_YELLOW
			   "=====================================\n" COLOR_RESET);
	}
	else if (src_port == 25 || dst_port == 25) // SMTP
	{
		increment_traffic_counter("OTHER");
		printf(COLOR_YELLOW "📧 SMTP CONNECTION INTERCEPTED 📧\n" COLOR_RESET);
		printf("Direction: %s:%d → %s:%d\n", src_ip, src_port, dst_ip,
			   dst_port);
		printf("Protocol: SMTP (email)\n");
		printf(COLOR_YELLOW
			   "=====================================\n" COLOR_RESET);
	}
	else if (src_port == 110 || dst_port == 110) // POP3
	{
		increment_traffic_counter("OTHER");
		printf(COLOR_YELLOW "📬 POP3 CONNECTION INTERCEPTED 📬\n" COLOR_RESET);
		printf("Direction: %s:%d → %s:%d\n", src_ip, src_port, dst_ip,
			   dst_port);
		printf("Protocol: POP3 (email)\n");
		printf(COLOR_YELLOW
			   "=====================================\n" COLOR_RESET);
	}
	else if (src_port == 143 || dst_port == 143) // IMAP
	{
		increment_traffic_counter("OTHER");
		printf(COLOR_YELLOW "📭 IMAP CONNECTION INTERCEPTED 📭\n" COLOR_RESET);
		printf("Direction: %s:%d → %s:%d\n", src_ip, src_port, dst_ip,
			   dst_port);
		printf("Protocol: IMAP (email)\n");
		printf(COLOR_YELLOW
			   "=====================================\n" COLOR_RESET);
	}
}

void search_keywords_in_traffic(const unsigned char *packet, ssize_t size)
{
	const char *keywords[]
		= { "password",		"passwd", "login",		   "user",		 "username",
			"admin",		"secret", "token",		   "auth",		 "key",
			"session",		"cookie", "authorization", "credential", "api_key",
			"access_token", "bearer", "basic",		   NULL };
	char text_buffer[4096];
	int	 text_len = 0;

	// Skip if packet is too small
	if (size < 50)
		return;

	// Convertir le paquet en texte lisible (seulement les caractères ASCII)
	for (ssize_t i = 0; i < size && text_len < 4095; i++)
	{
		if (packet[i] >= 32 && packet[i] <= 126)
		{
			text_buffer[text_len++] = ft_tolower(packet[i]);
		}
		else if (packet[i] == 0 || packet[i] == '\n' || packet[i] == '\r'
				 || packet[i] == '\t')
		{
			text_buffer[text_len++] = ' ';
		}
	}
	text_buffer[text_len] = '\0';

	// Chercher les mots-clés sensibles
	for (int i = 0; keywords[i] != NULL; i++)
	{
		char *keyword_pos = ft_strnstr(text_buffer, keywords[i], text_len);
		if (keyword_pos != NULL)
		{
			increment_traffic_counter("KEYWORD");
			printf(COLOR_YELLOW
				   "🔍 SENSITIVE KEYWORD DETECTED: '%s' 🔍\n" COLOR_RESET,
				   keywords[i]);
			printf("Packet size: %zd bytes\n", size);

			// Trouver le contexte autour du mot-clé (plus large)
			int keyword_offset = keyword_pos - text_buffer;
			int start = keyword_offset - 80;
			if (start < 0)
				start = 0;
			int end = keyword_offset + ft_strlen(keywords[i]) + 80;
			if (end > text_len)
				end = text_len;

			printf("Context: \"");
			for (int j = start; j < end; j++)
			{
				if (text_buffer[j] >= 32 && text_buffer[j] <= 126)
					printf("%c", text_buffer[j]);
				else
					printf(" ");
			}
			printf("\"\n");
			printf(COLOR_YELLOW
				   "=====================================\n" COLOR_RESET);

			// Show only the first keyword found to avoid spam
			break;
		}
	}
}

void analyze_icmp_traffic(const unsigned char *packet, ssize_t size)
{
	if (size < 34) // Ethernet(14) + IP(20) minimum
		return;

	// Vérifier si c'est un paquet IP
	if (packet[12] != 0x08 || packet[13] != 0x00)
		return;

	const unsigned char *ip_header = packet + 14;
	uint8_t				 protocol = ip_header[9];

	// Vérifier si c'est ICMP
	if (protocol != 1)
		return;

	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, ip_header + 12, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ip_header + 16, dst_ip, INET_ADDRSTRLEN);

	const unsigned char *icmp_header
		= packet + 14 + ((ip_header[0] & 0x0F) * 4);
	uint8_t icmp_type = icmp_header[0];
	uint8_t icmp_code = icmp_header[1];

	printf(COLOR_CYAN "🏓 ICMP PACKET INTERCEPTED 🏓\n" COLOR_RESET);
	printf("Direction: %s → %s\n", src_ip, dst_ip);
	printf("ICMP Type: %d, Code: %d\n", icmp_type, icmp_code);

	// Identifier le type ICMP
	if (icmp_type == 8)
		printf("Type: Echo Request (Ping)\n");
	else if (icmp_type == 0)
		printf("Type: Echo Reply (Ping Response)\n");
	else if (icmp_type == 3)
		printf("Type: Destination Unreachable\n");
	else if (icmp_type == 11)
		printf("Type: Time Exceeded\n");
	else
		printf("Type: Other ICMP\n");

	printf(COLOR_CYAN "=====================================\n" COLOR_RESET);
}
