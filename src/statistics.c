#include "ft_malcolm.h"

// Global traffic counters for MITM statistics
static int g_http_packets = 0;
static int g_https_packets = 0;
static int g_dns_packets = 0;
static int g_ssh_packets = 0;
static int g_ftp_packets = 0;
static int g_other_packets = 0;
static int g_sensitive_keywords = 0;
static int g_total_intercepted = 0;

void increment_traffic_counter(const char *protocol)
{
	if (!protocol)
		return;

	g_total_intercepted++;

	if (ft_strcmp(protocol, "HTTP") == 0)
		g_http_packets++;
	else if (ft_strcmp(protocol, "HTTPS") == 0)
		g_https_packets++;
	else if (ft_strcmp(protocol, "DNS") == 0)
		g_dns_packets++;
	else if (ft_strcmp(protocol, "SSH") == 0)
		g_ssh_packets++;
	else if (ft_strcmp(protocol, "FTP") == 0)
		g_ftp_packets++;
	else if (ft_strcmp(protocol, "KEYWORD") == 0)
		g_sensitive_keywords++;
	else
		g_other_packets++;
}

void print_traffic_statistics()
{
	printf(COLOR_BLUE "==================== MITM Traffic Statistics "
					  "====================\n" COLOR_RESET);
	printf("🚨 Total packets intercepted: %s%d%s\n", COLOR_RED,
		   g_total_intercepted, COLOR_RESET);
	printf("🌐 HTTP packets:              %s%d%s\n", COLOR_GREEN,
		   g_http_packets, COLOR_RESET);
	printf("🔒 HTTPS packets:             %s%d%s\n", COLOR_GREEN,
		   g_https_packets, COLOR_RESET);
	printf("🌍 DNS queries:               %s%d%s\n", COLOR_CYAN, g_dns_packets,
		   COLOR_RESET);
	printf("🔐 SSH connections:           %s%d%s\n", COLOR_YELLOW,
		   g_ssh_packets, COLOR_RESET);
	printf("📁 FTP connections:           %s%d%s\n", COLOR_YELLOW,
		   g_ftp_packets, COLOR_RESET);
	printf("📊 Other protocols:           %s%d%s\n", COLOR_CYAN,
		   g_other_packets, COLOR_RESET);
	printf("🔍 Sensitive keywords found:  %s%d%s\n", COLOR_RED,
		   g_sensitive_keywords, COLOR_RESET);
	printf(COLOR_BLUE "========================================================"
					  "========\n" COLOR_RESET);
}

void reset_traffic_statistics()
{
	g_http_packets = 0;
	g_https_packets = 0;
	g_dns_packets = 0;
	g_ssh_packets = 0;
	g_ftp_packets = 0;
	g_other_packets = 0;
	g_sensitive_keywords = 0;
	g_total_intercepted = 0;
}

void print_traffic_summary()
{
	if (g_total_intercepted == 0)
	{
		printf(COLOR_YELLOW
			   "[MITM] No traffic intercepted yet...\n" COLOR_RESET);
		return;
	}

	printf(COLOR_GREEN "[MITM] Intercepted %d packets", g_total_intercepted);

	if (g_sensitive_keywords > 0)
		printf(" (%s%d sensitive keywords detected!%s)", COLOR_RED,
			   g_sensitive_keywords, COLOR_GREEN);

	printf("%s\n", COLOR_RESET);
}

int get_total_intercepted_packets()
{
	return g_total_intercepted;
}

int get_sensitive_keywords_count()
{
	return g_sensitive_keywords;
}
