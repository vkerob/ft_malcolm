#include "ft_malcolm.h"

int g_raw_socket = -1;

int main(int argc, char **argv)
{
	bool verbose = false;
	(void)argc;
	(void)argv;
	if (getuid() != 0)
	{
		fprintf(stderr, "You must be root to run this program.\n");
		return (1);
	}

	if (argc > 1 && ft_strcmp(argv[1], "--verbose") == 0)
	{
		verbose = true;
		argc--;
		argv++;
	}

	// Set up signal handler to close the socket on exit
	setup_signal_handlers();

	// verify arguments and parse them
	t_args args;
	if (parse_args(argc, argv, &args) != 0)
	{
		fprintf(stderr, "Error parsing arguments.\n");
		return (1);
	}

	// find the interface
	if (detect_interface(args.ifname, IFNAMSIZ))
		return (1);

	print_config_summary(&args, verbose);

	// Set up the raw socket
	g_raw_socket = setup_socket(args.ifname);
	if (g_raw_socket < 0)
	{
		fprintf(stderr, "Error setting up socket.\n");
		return (1);
	}
	// listen for ARP requests
	if (wait_for_arp_request(g_raw_socket, &args) == 0)
	{
		// create and send falsified ARP reply
		send_arp_reply(g_raw_socket, &args);
	}

	close(g_raw_socket);
	return (0);
}