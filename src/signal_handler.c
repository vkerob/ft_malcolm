#include "ft_malcolm.h"

void sigint_handler(int signum)
{
	(void)signum;
	printf("\nReceived SIGINT (Ctrl+C), exiting cleanly...\n");

	// Clean up thread if active
	if (g_thread_active)
	{
		pthread_cancel(g_forward_thread);
		pthread_join(g_forward_thread, NULL);
		g_thread_active = false;
	}

	// Close socket
	if (g_raw_socket >= 0)
		close(g_raw_socket);

	exit(0);
}

void sigterm_handler(int signum)
{
	(void)signum;
	printf("\nReceived SIGTERM, exiting cleanly...\n");

	// Clean up thread if active
	if (g_thread_active)
	{
		pthread_cancel(g_forward_thread);
		pthread_join(g_forward_thread, NULL);
		g_thread_active = false;
	}

	// Close socket
	if (g_raw_socket >= 0)
		close(g_raw_socket);

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