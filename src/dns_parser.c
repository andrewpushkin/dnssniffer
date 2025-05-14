// dns_parser.c - DNS packet parsing implementation
//
// This file provides functions to parse DNS packets, extract DNS names, and print DNS query results.
// It defines the DNS header structure, result structure, and implements parsing logic for DNS queries.
//
// Functions:
//   - parse_dns_packet: Parses a DNS packet and fills a dns_result_t structure.
//   - extract_dns_name: Extracts a domain name from a DNS packet.
//   - print_dns_result: Prints the parsed DNS result.
//
// This file is used by packet_capture.c to process DNS packets captured from the network.

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include "dns_parser.h"


/* DNS compression constants */
#define DNS_COMPRESSION_MASK    0xC0
#define DNS_COMPRESSION_FLAG    0xC0
#define DNS_POINTER_MASK       0x3F
#define DNS_LABEL_LENGTH_MASK  0x3F
#define DNS_COMPRESSION_SIZE   2
#define DNS_MAX_JUMPS         20

/* DNS record types */
#define DNS_TYPE_A         1
#define DNS_TYPE_AAAA      28
#define DNS_TYPE_PTR       12
#define DNS_CLASS_IN       1

/* DNS record field offsets and sizes */
#define DNS_RR_TYPE_OFFSET      0
#define DNS_RR_CLASS_OFFSET     2
#define DNS_RR_RDLENGTH_OFFSET  8
#define DNS_RR_RDATA_OFFSET     10
#define DNS_RR_FIXED_FIELDS_LEN 10
#define DNS_IPV4_ADDR_LEN       4
#define DNS_IPV6_ADDR_LEN       16

/* Global logging level */
static log_level_t current_log_level = LOG_ERROR;

/* Convert network byte order to host byte order for 16-bit values */
static inline uint16_t bytes_to_uint16(const uint8_t *data)
{
    return (data[0] << 8) | data[1];
}

/**
 * Sets the logging level for DNS operations
 * @param level Logging level to set
 */
void dns_set_log_level(log_level_t level) {
    current_log_level = level;
}

/**
 * Logs a message with the specified logging level
 * @param level Logging level of the message
 * @param fmt Format string for the message
 * @param ... Additional arguments for the format string
 */
void dns_log(log_level_t level, const char *fmt, ...) {
    if (level > current_log_level) {
        return;
    }

    const char *level_str[] = {
        "ERROR",
        "WARN",
        "INFO",
        "DEBUG"
    };

    va_list args;
    fprintf(stderr, "[%s] ", level_str[level]);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

/**
 * Validates the structure and content of a DNS packet
 * @param packet Pointer to the DNS packet data
 * @param packet_len Length of the DNS packet
 * @return DNS_SUCCESS if valid, DNS_ERROR_VALIDATION otherwise
 */
int validate_dns_packet(const uint8_t *packet, size_t packet_len) {
    if (!packet || packet_len < sizeof(struct dns_header)) {
        dns_log(LOG_ERROR, "Invalid packet size or NULL pointer");
        return DNS_ERROR_VALIDATION;
    }

    const struct dns_header *header = (const struct dns_header *)packet;
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    
    /* Basic sanity checks */
    if (qdcount > MAX_DNS_RECORDS || ancount > MAX_DNS_RECORDS) {
        dns_log(LOG_ERROR, "Suspiciously large number of DNS records: %u questions, %u answers", 
                qdcount, ancount);
        return DNS_ERROR_VALIDATION;
    }

    size_t offset = sizeof(struct dns_header);
    char name[MAX_DNS_NAME_LENGTH];

    /* Validate question section */
    for (uint16_t i = 0; i < qdcount; i++) {
        int res = extract_dns_name(packet, packet_len, offset, name, sizeof(name));
        if (res < 0) {
            dns_log(LOG_ERROR, "Failed to parse question name at offset %zu", offset);
            return DNS_ERROR_VALIDATION;
        }
        offset = res + sizeof(uint16_t) * 2; /* Skip QTYPE and QCLASS */
        
        if (offset > packet_len) {
            dns_log(LOG_ERROR, "Question section extends beyond packet boundary");
            return DNS_ERROR_VALIDATION;
        }
    }

    /* Validate answer section */
    for (uint16_t i = 0; i < ancount; i++) {
        if (offset + DNS_RR_FIXED_FIELDS_LEN > packet_len) {
            dns_log(LOG_ERROR, "Answer record header extends beyond packet boundary");
            return DNS_ERROR_VALIDATION;
        }

        int res = extract_dns_name(packet, packet_len, offset, name, sizeof(name));
        if (res < 0) {
            dns_log(LOG_ERROR, "Failed to parse answer name at offset %zu", offset);
            return DNS_ERROR_VALIDATION;
        }
        offset = res;

        uint16_t rdlength = bytes_to_uint16(&packet[offset + DNS_RR_RDLENGTH_OFFSET]);
        offset += DNS_RR_FIXED_FIELDS_LEN;

        if (offset + rdlength > packet_len) {
            dns_log(LOG_ERROR, "Answer record data extends beyond packet boundary");
            return DNS_ERROR_VALIDATION;
        }
        
        offset += rdlength;
    }

    return DNS_SUCCESS;
}

/**
 * Appends a DNS label to the destination buffer with proper dot separation
 * @param dest Destination buffer to append to
 * @param src Source buffer containing the label
 * @param label_len Length of the label to copy
 * @param dest_offset Current position in destination buffer
 * @param max_len Maximum length of destination buffer
 * @return New offset in destination buffer, or DNS_ERROR_GENERAL on error
 */
int append_dns_label(char *dest, const uint8_t *src, uint8_t label_len, 
                          size_t dest_offset, size_t max_len)
{
    if (dest_offset + label_len + 1 >= max_len) {
        return DNS_ERROR_GENERAL;
    }

    if (dest_offset > 0) {
        dest[dest_offset++] = '.';
    }

    memcpy(dest + dest_offset, src, label_len);
    return dest_offset + label_len;
}

/**
 * Handles DNS name compression by following compression pointers
 * @param packet Full DNS packet data
 * @param packet_len Length of the packet
 * @param current_offset Current position in packet (will be updated on compression)
 * @param base_offset Original position to return to after compression
 * @param is_compressed Flag indicating if compression was encountered
 * @param jump_count Counter to prevent infinite loops
 * @return DNS_SUCCESS if compression handled, DNS_ERROR_GENERAL on error
 */
int handle_dns_compression(const uint8_t *packet, size_t packet_len,
                                size_t *current_offset, size_t *base_offset,
                                int *is_compressed, size_t *jump_count)
{
    if (*current_offset >= packet_len) {
        dns_log(LOG_ERROR, "Compression pointer offset exceeds packet length");
        return DNS_ERROR_COMPRESSION;
    }

    uint8_t length_byte = packet[*current_offset];
    
    if ((length_byte & DNS_COMPRESSION_MASK) != DNS_COMPRESSION_FLAG) {
        return DNS_SUCCESS;
    }

    if (*current_offset + DNS_COMPRESSION_SIZE > packet_len) {
        dns_log(LOG_ERROR, "Incomplete compression pointer");
        return DNS_ERROR_COMPRESSION;
    }

    /* Calculate compression pointer target */
    size_t target_offset = ((length_byte & DNS_POINTER_MASK) << 8) | 
                          packet[*current_offset + 1];
                          
    if (target_offset >= packet_len) {
        dns_log(LOG_ERROR, "Compression pointer target beyond packet boundary");
        return DNS_ERROR_COMPRESSION;
    }

    /* Detect compression loops */
    if (*jump_count > 0) {
        for (size_t i = 0; i < *jump_count; i++) {
            if (target_offset == *current_offset) {
                dns_log(LOG_ERROR, "Detected compression pointer loop");
                return DNS_ERROR_COMPRESSION;
            }
        }
    }

    if (!*is_compressed) {
        *base_offset = *current_offset + DNS_COMPRESSION_SIZE;
        *is_compressed = 1;
    }

    *current_offset = target_offset;
    (*jump_count)++;

    return (*jump_count < DNS_MAX_JUMPS) ? 1 : DNS_ERROR_COMPRESSION;
}

/**
 * Extracts a DNS name from a packet, handling compression
 * @param packet Full DNS packet data
 * @param packet_len Length of the packet
 * @param offset Starting offset in the packet
 * @param name Buffer to store the extracted name
 * @param name_len Size of the name buffer
 * @return New offset after the name, or DNS_ERROR_GENERAL on error
 */
int extract_dns_name(const uint8_t *packet, size_t packet_len, size_t offset,
                    char *name, size_t name_len)
{
    if (!packet || !name || packet_len == 0 || name_len == 0) {
        dns_log(LOG_ERROR, "Invalid parameters for extracting DNS name");
        return DNS_ERROR_GENERAL;
    }

    size_t name_offset = 0;
    size_t current_offset = offset;
    int is_compressed = 0;
    size_t jump_count = 0;

    name[0] = '\0';

    while (current_offset < packet_len) {
        uint8_t label_len = packet[current_offset];

        /* Handle DNS name compression if present */
        int compression_result = handle_dns_compression(packet, packet_len,
                                                      &current_offset, &offset,
                                                      &is_compressed, &jump_count);
        if (compression_result < 0) {
            dns_log(LOG_ERROR, "Error handling DNS compression at offset %zu", current_offset);
            return DNS_ERROR_GENERAL;
        }
        if (compression_result > 0) {
            continue;
        }

        /* Move past length byte */
        current_offset++;

        /* End of name reached */
        if (label_len == 0) {
            break;
        }

        /* Validate remaining packet length */
        if (current_offset + label_len > packet_len) {
            dns_log(LOG_ERROR, "Label length exceeds packet boundary at offset %zu", current_offset);
            return DNS_ERROR_GENERAL;
        }

        /* Append the label to our result */
        int new_offset = append_dns_label(name, &packet[current_offset], 
                                        label_len, name_offset, name_len);
        if (new_offset < 0) {
            dns_log(LOG_ERROR, "Failed to append DNS label");
            return DNS_ERROR_GENERAL;
        }
        name_offset = new_offset;
        current_offset += label_len;
    }

    name[name_offset] = '\0';
    return is_compressed ? offset : current_offset;
}

/**
 * Processes the question section of a DNS packet
 * @param packet Full DNS packet data
 * @param packet_len Length of the packet
 * @param offset Current offset in the packet
 * @param qdcount Number of questions in the packet
 * @return DNS_SUCCESS if successful, DNS_ERROR_MALFORMED otherwise
 */
int process_question_section(const uint8_t *packet, size_t packet_len,
                                 size_t *offset, uint16_t qdcount)
{
    char name[MAX_DNS_NAME_LENGTH];
    
    for (uint16_t i = 0; i < qdcount; i++) {
        int res = extract_dns_name(packet, packet_len, *offset, name, sizeof(name));
        if (res < 0) {
            dns_log(LOG_ERROR, "Failed to extract question name at offset %zu", *offset);
            return DNS_ERROR_MALFORMED;
        }
        *offset = res + sizeof(uint16_t) * 2; /* Skip QTYPE and QCLASS */
        
        if (*offset > packet_len) {
            dns_log(LOG_ERROR, "Question section extends beyond packet boundary");
            return DNS_ERROR_MALFORMED;
        }
    }
    return DNS_SUCCESS;
}

/**
 * Processes a single resource record in the answer section
 * @param packet Full DNS packet data
 * @param packet_len Length of the packet
 * @param offset Current offset in the packet
 * @param result Pointer to the dns_result_t structure to store results
 * @return DNS_SUCCESS if successful, DNS_ERROR_MALFORMED otherwise
 */
int process_resource_record(const uint8_t *packet, size_t packet_len,
                                size_t *offset, dns_result_t *result)
{
    char name[MAX_DNS_NAME_LENGTH];
    int res = extract_dns_name(packet, packet_len, *offset, name, sizeof(name));
    if (res < 0) {
        dns_log(LOG_ERROR, "Failed to extract record name at offset %zu", *offset);
        return DNS_ERROR_MALFORMED;
    }
    *offset = res;

    if (*offset + DNS_RR_FIXED_FIELDS_LEN > packet_len) {
        dns_log(LOG_ERROR, "Record header extends beyond packet boundary");
        return DNS_ERROR_MALFORMED;
    }

    uint16_t type = bytes_to_uint16(&packet[*offset + DNS_RR_TYPE_OFFSET]);
    uint16_t class = bytes_to_uint16(&packet[*offset + DNS_RR_CLASS_OFFSET]);
    uint16_t rdlength = bytes_to_uint16(&packet[*offset + DNS_RR_RDLENGTH_OFFSET]);
    *offset += DNS_RR_FIXED_FIELDS_LEN;

    if (*offset + rdlength > packet_len) {
        dns_log(LOG_ERROR, "Record data extends beyond packet boundary");
        return DNS_ERROR_MALFORMED;
    }

    if (class == DNS_CLASS_IN) {
        switch (type) {
        case DNS_TYPE_A:
            if (rdlength == DNS_IPV4_ADDR_LEN && result->ipv4_count < MAX_IP_ADDRESSES) {
                struct in_addr addr;
                memcpy(&addr, &packet[*offset], DNS_IPV4_ADDR_LEN);
                inet_ntop(AF_INET, &addr,
                         result->ipv4[result->ipv4_count++],
                         INET_ADDRSTRLEN);
                dns_log(LOG_DEBUG, "Processed A record for %s", name);
            }
            break;

        case DNS_TYPE_AAAA:
            if (rdlength == DNS_IPV6_ADDR_LEN && result->ipv6_count < MAX_IP_ADDRESSES) {
                struct in6_addr addr;
                memcpy(&addr, &packet[*offset], DNS_IPV6_ADDR_LEN);
                inet_ntop(AF_INET6, &addr,
                         result->ipv6[result->ipv6_count++],
                         INET6_ADDRSTRLEN);
                dns_log(LOG_DEBUG, "Processed AAAA record for %s", name);
            }
            break;
        }
    }

    *offset += rdlength;
    return DNS_SUCCESS;
}

/**
 * Processes the answer section of a DNS packet
 * @param packet Full DNS packet data
 * @param packet_len Length of the packet
 * @param offset Current offset in the packet
 * @param ancount Number of answers in the packet
 * @param result Pointer to the dns_result_t structure to store results
 * @return DNS_SUCCESS if successful, DNS_ERROR_MALFORMED otherwise
 */
int process_answer_section(const uint8_t *packet, size_t packet_len,
                               size_t *offset, uint16_t ancount,
                               dns_result_t *result)
{
    for (uint16_t i = 0; i < ancount; i++) {
        int res = process_resource_record(packet, packet_len, offset, result);
        if (res != DNS_SUCCESS) {
            return res;
        }
    }
    return DNS_SUCCESS;
}

/**
 * Parses a DNS packet and fills the dns_result_t structure with query info
 * @param packet Pointer to the DNS packet data
 * @param packet_len Length of the DNS packet
 * @param result Pointer to the dns_result_t structure to store results
 * @return DNS_SUCCESS if successful, DNS_ERROR_GENERAL otherwise
 */
int parse_dns_packet(const uint8_t *packet, size_t packet_len, dns_result_t *result)
{
    if (!packet || !result || packet_len == 0) {
        dns_log(LOG_ERROR, "Invalid parameters for parsing DNS packet");
        return DNS_ERROR_GENERAL;
    }

    if (validate_dns_packet(packet, packet_len) != DNS_SUCCESS) {
        dns_log(LOG_ERROR, "DNS packet validation failed");
        return DNS_ERROR_MALFORMED;
    }

    const struct dns_header *header = (const struct dns_header *)packet;
    size_t offset = sizeof(struct dns_header);

    memset(result, 0, sizeof(dns_result_t));

    /* Process question section */
    uint16_t qdcount = ntohs(header->qdcount);
    int res = process_question_section(packet, packet_len, &offset, qdcount);
    if (res != DNS_SUCCESS) {
        return res;
    }

    /* Process answer section */
    uint16_t ancount = ntohs(header->ancount);
    res = process_answer_section(packet, packet_len, &offset, ancount, result);
    if (res != DNS_SUCCESS) {
        return res;
    }

    dns_log(LOG_DEBUG, "Successfully parsed DNS packet with %u answers", ancount);
    return DNS_SUCCESS;
}

/**
 * Prints the parsed DNS result
 * @param result Pointer to the dns_result_t structure containing results
 * @param domain Domain name associated with the DNS query
 */
void print_dns_result(const dns_result_t *result, const char *domain)
{
    if (!result || !domain) {
        return;
    }

    /* Only print if we have actual content to show */
    if (result->ipv4_count == 0 && result->ipv6_count == 0) {
        return;
    }

    printf("\nDomain: %s,\n", domain);

    if (result->ipv4_count > 0) {
        printf("IPv4 addresses:\n");
        for (int i = 0; i < result->ipv4_count; i++) {
            printf("  %s\n", result->ipv4[i]);
        }
    }

    if (result->ipv6_count > 0) {
        printf("IPv6 addresses:\n");
        for (int i = 0; i < result->ipv6_count; i++) {
            printf("  %s\n", result->ipv6[i]);
        }
    }
    printf("\n");
}