// main.c - Entry point for DNS sniffer application
//
// This file contains the main function, argument parsing, and program setup for the DNS sniffer.
// It initializes the packet capture process, handles user input, and manages program lifecycle.
//
// Functions:
//   - main: Program entry point, parses arguments and starts capture
//   - print_usage: Prints usage information for the program
//
// This file uses packet_capture.c to perform network packet capture and DNS analysis.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <getopt.h>
#include "packet_capture.h"
#include "dns_parser.h"

// Prints usage information for the DNS sniffer program
static void print_usage(const char *prog_name) {
    fprintf(stderr,
        "Usage: %s [-i interface] [-v level] [-h]\n"
        "Options:\n"
        "  -i <interface>  Network interface to capture on (required)\n"
        "  -v <level>     Verbosity level (0-3, default: 0)\n"
        "                 0: errors only\n"
        "                 1: + warnings\n"
        "                 2: + info\n"
        "                 3: + debug\n"
        "  -h             Show this help message\n",
        prog_name);
}

// Checks if the program is running with root privileges
static int check_privileges(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges to capture packets.\n"
                "Please run with sudo or as root.\n");
        return -1;
    }
    return 0;
}

// Main entry point for the DNS sniffer application
int main(int argc, char *argv[])
{
    const char *interface = NULL; // Network interface to capture on
    int verbosity = LOG_ERROR;   // Default verbosity level
    int opt;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "hi:v:")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'v':
            verbosity = atoi(optarg);
            if (verbosity < LOG_ERROR || verbosity > LOG_DEBUG) {
                fprintf(stderr, "Invalid verbosity level. Using default (0).\n");
                verbosity = LOG_ERROR;
            }
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    // Ensure the interface is specified
    if (!interface) {
        fprintf(stderr, "Error: Interface must be specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Check for root privileges
    if (check_privileges() != 0) {
        return 1;
    }

    // Set logging level for DNS parser
    dns_set_log_level(verbosity);

    // Start DNS packet capture on the specified interface
    return start_capture(interface);
}