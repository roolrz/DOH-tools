#include "debug.h"
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include "dns.h"

static int print_help(void) {
	printf("DNS over HTTPS query tool\n");
	printf("Help:\n");
	printf("\t--help\t\t-h\tPrint this help\n");
	printf("\t--port\t\t-p\tSpecify the port\n");
	printf("\t--verbose\t-v\tVerbose mode\n");
	return 0;
}

int main(int argc, char ** argv) {
	int opt;
	int port = -1;
	int verbose = 0;
	char * server = NULL;
	const char * short_opt = "p:s:hv";
	struct option long_opt[] =
	{
		{"help",		no_argument,		NULL,		'h'},
		{"port",		required_argument,	NULL,		'p'},
		{"verbose",		no_argument,		NULL,		'v'},
		{"server",		no_argument,		NULL,		's'},
		{NULL,			0,					NULL,		0  }
	};

	while((opt = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1)
	{  
		switch(opt)  
		{  
			case -1:		/* no more arguments */
			case 0:			/* long options toggles */
				break;
			case 'p':		/* port specification */
				port = atoi(optarg);
				if (port == 0) {
					fprintf(stderr, "Please enter an valid port number\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 's':
				server = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'h':		/* help */
				print_help(); 
				exit(EXIT_SUCCESS);
			default:
				break;
		}  
	}
	  
	/* IP address specification */
	if (argv[optind] == NULL) {
		fprintf(stderr, "Use %s [options] [Domain Name]\n", argv[0]);
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	else {
		do_dns_query(server, port, argv[optind], verbose);
	}

	return 0;
}