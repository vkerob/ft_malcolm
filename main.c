#include "ft_malcolm.h"

int g_raw_socket = -1;

int main(int argc, char **argv)
{
	bool verbose = false;
	bool attack_mode = false;
	char source_ip_mac[MAC_ADDR_LEN] = { 0 };

	if (getuid() != 0)
	{
		fprintf(stderr, "You must be root to run this program.\n");
		return (1);
	}

	// Parse flags
	int i = 1;
	while (i < argc && argv[i][0] == '-')
	{
		if (ft_strcmp(argv[i], "--verbose") == 0)
		{
			verbose = true;
			i++;
		}
		else if (ft_strncmp(argv[i], "--attack", 8) == 0)
		{
			attack_mode = true;
			// Check if --attack=MAC_ADDRESS format
			if (argv[i][8] == '=' && argv[i][9] != '\0')
			{
				// Copy the MAC address after the '='
				ft_strlcpy(source_ip_mac, &argv[i][9], MAC_ADDR_LEN);
				printf("[Info] Source IP MAC provided: %s\n", source_ip_mac);
			}
			else
			{
				fprintf(stderr, "Error: --attack requires a MAC address: "
								"--attack=MAC_ADDRESS\n");
				fprintf(stderr,
						"Usage: ./ft_malcolm [--verbose] --attack=MAC_ADDRESS "
						"<src_ip> <src_mac> <target_ip> <target_mac>\n");
				return (1);
			}
			i++;
		}
		else
		{
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			fprintf(stderr,
					"Usage: ./ft_malcolm [--verbose] --attack=MAC_ADDRESS "
					"<src_ip> <src_mac> <target_ip> <target_mac>\n");
			return (1);
		}
	}

	argc -= (i - 1);
	argv += (i - 1);

	// Set up signal handler to close the socket on exit
	setup_signal_handlers();

	// verify arguments and parse them
	t_args args;
	args.mitm_attack = attack_mode;
	args.verbose = verbose;

	// Copy the provided source IP MAC if available
	if (source_ip_mac[0] != '\0')
	{
		ft_strlcpy(args.source_ip_mac, source_ip_mac, MAC_ADDR_LEN);
	}

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

	if (attack_mode)
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
			// create and send falsified ARP reply
			send_arp_reply(g_raw_socket, &args);
		}
	}

	close(g_raw_socket);
	return (0);
}