#include "ft_malcolm.h"
#include "libft.h"
#include <signal.h>

void sig_handler(int signum)
{
	(void)signum;
	atomic_store(&g_stop, true);
}

void setup_signal_handlers()
{
	struct sigaction sa;

	// Initialize the structure to zero
	ft_memset(&sa, 0, sizeof(sa));

	// SIGINT (Ctrl+C) SIGTERM (kill command) (bonus)
	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}