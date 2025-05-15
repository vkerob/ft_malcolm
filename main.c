#include "ft_malcolm.h"

int g_raw_socket = -1;

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	if (getuid() != 0)
	{
		ft_fprintf(2, "You must be root to run this program.\n");
		return (1);
	}

	// setup_signal_handler();

	// t_args args;
}