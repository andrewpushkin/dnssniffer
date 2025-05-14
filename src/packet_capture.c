// packet_capture.c - Handles packet capture and DNS packet processing using libpcap
//
// This file contains functions for capturing network packets on a specified interface,
// filtering for DNS traffic, parsing IPv4/IPv6 UDP packets, and extracting DNS queries.
// It uses libpcap for packet capture and filtering, and relies on dns_parser for DNS parsing.

#define _GNU_SOURCE
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "packet_capture.h"
#include "dns_parser.h"

/* Network constants */
#define DNS_PORT             53               // Standard DNS port
#define SNAP_LEN           1518               // Maximum bytes to capture per packet
#define PCAP_TIMEOUT_MS    1000               // Timeout for packet capture in milliseconds
#define PROMISC_MODE         1                // Enable promiscuous mode
#define NO_PROMISC_MODE      0                // Disable promiscuous mode

/* Filter expression constants */
#define FILTER_BUFF_SIZE    64                // Buffer size for filter expression
#define FILTER_OPT_NONE      0                // No filter options

/* Globals for cleanup */
static pcap_t *global_handle = NULL;          // Global pcap handle for cleanup
static struct bpf_program *global_fp = NULL;  // Global filter program pointer for cleanup

/**
 * Returns the filter expression string for capturing DNS UDP traffic
 * @return Pointer to static filter expression string
 */
const char *get_filter_expression()
{
    static char filter_exp[64] = {0};         // Static buffer for filter expression
    if (filter_exp[0] == '\0')
        snprintf(filter_exp, sizeof(filter_exp), "udp port %d", DNS_PORT); // Set filter if not already set
    return filter_exp;
}

/**
 * Cleans up pcap resources (filter and handle)
 * Frees compiled filter and closes pcap handle if allocated
 */
static void cleanup_capture(void) {
    if (global_fp) {
        pcap_freecode(global_fp);             // Free compiled filter
        global_fp = NULL;
    }
    if (global_handle) {
        pcap_close(global_handle);            // Close pcap handle
        global_handle = NULL;
    }
}

/**
 * Checks if the captured packet is at least the minimum required size
 * @param header Pointer to pcap packet header
 * @param min_size Minimum required size
 * @return 1 if valid, 0 otherwise
 */
static int is_valid_packet_size(const struct pcap_pkthdr *header,
                             size_t min_size)
{
    if (!header)
        return NO_PROMISC_MODE;               // Invalid header
    return header->caplen >= min_size;        // Check if packet is large enough
}

/**
 * Parses an IPv4 UDP packet and returns a pointer to the UDP header
 * Also sets ip_header_len to the length of the IP header
 * @param packet Raw packet data
 * @param header Pointer to pcap packet header
 * @param ip_header_len Output: length of IP header
 * @return Pointer to UDP header, or NULL on error
 */
static const struct udphdr *parse_ipv4_packet(const unsigned char *packet,
                                            const struct pcap_pkthdr *header,
                                            size_t *ip_header_len)
{
    if (!packet || !header || !ip_header_len)
        return NULL;                          // Invalid arguments

    if (!is_valid_packet_size(header,
                             sizeof(struct ether_header) + sizeof(struct ip)))
        return NULL;                          // Packet too small for Ethernet + IP

    const struct ip *ip_header = (struct ip *)(packet +
                                             sizeof(struct ether_header)); // Get IP header
    *ip_header_len = ip_header->ip_hl * sizeof(uint32_t); // Calculate IP header length

    if (ip_header->ip_p != IPPROTO_UDP)
        return NULL;                          // Not a UDP packet

    return (struct udphdr *)((uint8_t *)ip_header + *ip_header_len); // Return UDP header pointer
}

/**
 * Parses an IPv6 UDP packet and returns a pointer to the UDP header
 * Also sets ip_header_len to the length of the IPv6 header
 * @param packet Raw packet data
 * @param header Pointer to pcap packet header
 * @param ip_header_len Output: length of IPv6 header
 * @return Pointer to UDP header, or NULL on error
 */
static const struct udphdr *parse_ipv6_packet(const unsigned char *packet,
                                            const struct pcap_pkthdr *header,
                                            size_t *ip_header_len)
{
    if (!packet || !header || !ip_header_len)
        return NULL;                          // Invalid arguments

    if (!is_valid_packet_size(header,
                             sizeof(struct ether_header) + sizeof(struct ip6_hdr)))
        return NULL;                          // Packet too small for Ethernet + IPv6

    const struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet +
                                                         sizeof(struct ether_header)); // Get IPv6 header
    *ip_header_len = sizeof(struct ip6_hdr);  // IPv6 header length is fixed

    if (ip6_header->ip6_nxt != IPPROTO_UDP)
        return NULL;                          // Not a UDP packet

    return (struct udphdr *)((uint8_t *)ip6_header + *ip_header_len); // Return UDP header pointer
}

/**
 * Checks if the source port matches the DNS port
 * @param src_port Source port in host byte order
 * @return 1 if DNS port, 0 otherwise
 */
static int is_dns_port(uint16_t src_port)
{
    return src_port == DNS_PORT;              // Compare with standard DNS port
}

/**
 * Extracts DNS data from the UDP payload
 * @param udp_header Pointer to UDP header
 * @param dns_len Output: length of DNS data
 * @return Pointer to DNS data, or NULL on error
 */
static const uint8_t *get_dns_data(const struct udphdr *udp_header,
                                  size_t *dns_len)
{
    if (!udp_header || !dns_len)
        return NULL;                          // Invalid arguments

    uint16_t udp_len = ntohs(udp_header->len); // Get UDP length
    if (udp_len <= sizeof(struct udphdr))
        return NULL;                          // UDP payload too small

    *dns_len = udp_len - sizeof(struct udphdr); // Calculate DNS data length
    return (uint8_t *)udp_header + sizeof(struct udphdr); // Return pointer to DNS data
}

/**
 * Handles DNS packet processing
 * Extracts the DNS name and parses the DNS packet
 * @param dns_data Pointer to DNS payload
 * @param dns_len Length of DNS payload
 */
static void handle_dns_packet(const uint8_t *dns_data, size_t dns_len)
{
    if (!dns_data)
        return;                               // Invalid DNS data

    if (dns_len <= sizeof(struct dns_header))
        return;                               // DNS data too small

    char domain[MAX_DNS_NAME_LENGTH];         // Buffer for DNS domain name
    dns_result_t result;                      // Structure for parsed DNS result

    extract_dns_name(dns_data, dns_len,
                    sizeof(struct dns_header), domain, sizeof(domain)); // Extract DNS name

    if (parse_dns_packet(dns_data, dns_len, &result) == 0) // Parse DNS packet
        print_dns_result(&result, domain);    // Print parsed DNS result
}

/**
 * Processes a captured packet
 * Filters for DNS traffic and handles DNS packet processing
 * @param args Unused
 * @param header Pointer to pcap packet header
 * @param packet Raw packet data
 */
static void process_packet(unsigned char *args __attribute__((unused)),
                         const struct pcap_pkthdr *header,
                         const unsigned char *packet)
{
    if (!is_valid_packet_size(header, sizeof(struct ether_header)))
        return;                               // Packet too small for Ethernet header

    const struct ether_header *eth_header = (struct ether_header *)packet; // Get Ethernet header
    uint16_t eth_type = ntohs(eth_header->ether_type); // Get Ethernet type
    size_t ip_header_len;
    const struct udphdr *udp_header = NULL;

    if (eth_type == ETHERTYPE_IP)
        udp_header = parse_ipv4_packet(packet, header, &ip_header_len); // Parse IPv4 packet
    else if (eth_type == ETHERTYPE_IPV6)
        udp_header = parse_ipv6_packet(packet, header, &ip_header_len); // Parse IPv6 packet

    if (!udp_header)
        return;                               // Not a valid UDP packet

    uint16_t src_port = ntohs(udp_header->source); // Get source port

    if (!is_dns_port(src_port))
        return;                               // Not DNS traffic

    size_t dns_len;
    const uint8_t *dns_data = get_dns_data(udp_header, &dns_len); // Get DNS data
    
    if (dns_data)
        handle_dns_packet(dns_data, dns_len); // Handle DNS packet
}

/**
 * Starts packet capture on the specified interface
 * Sets up libpcap, applies the DNS filter, and begins capturing packets
 * @param interface Name of the network interface
 * @return PCAP_SUCCESS on success, error code otherwise
 */
int start_capture(const char *interface)
{
    if (!interface) {
        dns_log(LOG_ERROR, "No interface specified"); // Log error if no interface specified
        return PCAP_ERROR_GENERAL;
    }

    char errbuf[PCAP_ERRBUF_SIZE];            // Buffer for error messages
    struct bpf_program fp;                    // Filter program
    bpf_u_int32 net;                          // Network number
    bpf_u_int32 mask;                         // Network mask

    // Get network number and mask associated with capture device
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == PCAP_ERROR_GENERAL) {
        dns_log(LOG_WARN, "Couldn't get netmask for device %s: %s", 
                interface, errbuf);          // Log warning if unable to get netmask
        net = 0;
        mask = 0;
    }

    // Open capture device
    global_handle = pcap_open_live(interface, SNAP_LEN, PROMISC_MODE,
                                 PCAP_TIMEOUT_MS, errbuf);
    if (global_handle == NULL) {
        dns_log(LOG_ERROR, "Couldn't open device %s: %s", interface, errbuf); // Log error if unable to open device
        return PCAP_ERROR_GENERAL;
    }

    // Check if we have permission to capture
    if (pcap_fileno(global_handle) == -1) {
        dns_log(LOG_ERROR, "No permission to capture on interface %s", interface); // Log error if no permission
        cleanup_capture();
        return PCAP_ERROR_PERM;
    }

    // Compile and apply the filter
    if (pcap_compile(global_handle, &fp, get_filter_expression(),
                    FILTER_OPT_NONE, net) == PCAP_ERROR_GENERAL) {
        dns_log(LOG_ERROR, "Couldn't parse filter %s: %s",
                get_filter_expression(), pcap_geterr(global_handle)); // Log error if unable to parse filter
        cleanup_capture();
        return PCAP_ERROR_GENERAL;
    }

    global_fp = &fp;

    if (pcap_setfilter(global_handle, global_fp) == PCAP_ERROR_GENERAL) {
        dns_log(LOG_ERROR, "Couldn't install filter %s: %s",
                get_filter_expression(), pcap_geterr(global_handle)); // Log error if unable to install filter
        cleanup_capture();
        return PCAP_ERROR_GENERAL;
    }

    dns_log(LOG_INFO, "Capturing DNS traffic on interface %s...", interface); // Log info about capture start

    // Start capturing packets
    int res = pcap_loop(global_handle, -1, process_packet, NULL);

    cleanup_capture();
    return (res == PCAP_ERROR) ? PCAP_ERROR_GENERAL : PCAP_SUCCESS; // Return success or error code
}

/**
 * Stops packet capture
 * Breaks the pcap loop and cleans up resources
 */
void stop_capture(void) {
    if (global_handle) {
        pcap_breakloop(global_handle);        // Break pcap loop
    }
}