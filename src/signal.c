#include "ft_malcolm.h"

void sigint_handler(int signum)
{
	(void)signum;
	if (g_raw_socket >= 0)
		close(g_raw_socket);
	printf("\nReceived SIGINT (Ctrl+C), exiting cleanly...\n");
	exit(0);
}

void sigterm_handler(int signum)
{
	(void)signum;
	if (g_raw_socket >= 0)
		close(g_raw_socket);
	printf("\nReceived SIGTERM, exiting cleanly...\n");
	exit(0);
}

void setup_signal_handlers()
{
	struct sigaction sa;

	// Initialize the structure to zero
	ft_memset(&sa, 0, sizeof(sa));

	// SIGINT (Ctrl+C)
	sa.sa_handler = sigint_handler;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);

	// SIGTERM (kill command) (bonus)
	sa.sa_handler = sigterm_handler;
	sa.sa_flags = 0;
	sigaction(SIGTERM, &sa, NULL);
}