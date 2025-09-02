#include "ft_malcolm.h"

int		  g_raw_socket = -1;
pthread_t g_forward_thread;
bool	  g_thread_active = false;

int main(int argc, char **argv)
{
	if (getuid() != 0)
	{
		fprintf(stderr, "You must be root to run this program.\n");
		return (1);
	}

	// Set up signal handler to close the socket on exit
	setup_signal_handlers();

	// Parse flags and initialize arguments structure
	t_args args;
	if (parse_flags(&argc, &argv, &args) != 0)
	{
		fprintf(stderr, "Error parsing flags.\n");
		return (1);
	}

	// Parse remaining arguments
	if (parse_args(argc, argv, &args) != 0)
	{
		fprintf(stderr, "Error parsing arguments.\n");
		return (1);
	}

	// find the interface
	if (detect_interface(args.ifname, IFNAMSIZ))
		return (1);

	if (args.verbose)
		print_config_summary(&args);

	// Set up the raw socket
	g_raw_socket = setup_socket(args.ifname);
	if (g_raw_socket < 0)
	{
		fprintf(stderr, "Error setting up socket.\n");
		return (1);
	}

	if (args.mitm_attack)
	{
		printf(COLOR_GREEN
			   "[Info] Launching full MITM attack mode...\n" COLOR_RESET);
		perform_mitm_attack(g_raw_socket, &args);
	}
	else
	{
		// listen for ARP requests
		if (wait_for_arp_request(g_raw_socket, &args, args.verbose) == 0)
		{
			printf(COLOR_BLUE
				   "Now sending an ARP reply to the target address with "
				   "spoofed source, please wait...\n" COLOR_RESET);
			sleep(3);

			// create and send falsified ARP reply
			send_arp_reply(g_raw_socket, &args);

			printf(COLOR_GREEN
				   "Sent an ARP reply packet, you may now check the arp table "
				   "on the target.\n" COLOR_RESET);
		}
	}

	printf(COLOR_CYAN "Exiting program..\n" COLOR_RESET);
	close(g_raw_socket);
	return (0);
}