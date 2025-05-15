#include "../includes/ft_malcolm.h"

void sigint_handler(int signum)
{
	(void)signum;
	if (g_raw_socket >= 0)
		close(g_raw_socket);
	printf("\nExiting cleanly...\n");
	exit(0);
}

void setup_signal_handlers()
{
	struct sigaction sa;
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
}