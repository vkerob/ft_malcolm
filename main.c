#include "ft_malcolm.h"

int g_raw_socket = -1;

int main(int argc, char **argv)
{
	bool verbose = false;
	(void)argc;
	(void)argv;
	if (getuid() != 0)
	{
		ft_fprintf(STDERR_FILENO, "You must be root to run this program.\n");
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
		ft_fprintf(STDERR_FILENO, "Error parsing arguments.\n");
		return (1);
	}
	ft_strlcpy(args.ifname, "enp0s3", IFNAMSIZ);

	if (verbose)
	{
		print_ip_decimal("Source IP", args.source_ip);
		print_ip_decimal("Target IP", args.target_ip);
	}
	printf("Source IP   : %s\n", args.source_ip);
	printf("Source MAC  : %s\n", args.source_mac);
	printf("Target IP   : %s\n", args.target_ip);
	printf("Target MAC  : %s\n", args.target_mac);

	// Set up the raw socket
	g_raw_socket = setup_socket(args.ifname);
	if (g_raw_socket < 0)
	{
		ft_fprintf(2, "Error setting up socket.\n");
		return (1);
	}
	unsigned char buffer[2048];
	ssize_t		  bytes
		= recvfrom(g_raw_socket, buffer, sizeof(buffer), 0, NULL, NULL);
	if (bytes < 0)
	{
		perror("recvfrom");
	}
	else
	{
		printf("Received %zd bytes on raw socket.\n", bytes);
	}
	print_arp_packet(buffer, bytes);

	// // listen for ARP requests
	// if (wait_for_arp_request(g_raw_socket, &args) == 0)
	// {
	// 	// create and send falsified ARP reply
	// 	send_arp_reply(g_raw_socket, &args);
	// }

	// close(g_raw_socket);
	// return (0);
}