#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

/* DNS name and result limits */
#define MAX_DNS_NAME_LENGTH 256
#define MAX_IP_ADDRESSES     10
#define MAX_DNS_RECORDS     100  /* Maximum number of records in a single packet */

/* Error codes */
#define DNS_SUCCESS              0
#define DNS_ERROR_GENERAL       -1
#define DNS_ERROR_COMPRESSION   -2
#define DNS_ERROR_MALFORMED     -3
#define DNS_ERROR_BUFFER        -4
#define DNS_ERROR_VALIDATION    -5

/* Logging levels */
typedef enum {
    LOG_ERROR = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} log_level_t;

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

typedef struct {
    char ipv4[MAX_IP_ADDRESSES][INET_ADDRSTRLEN];
    char ipv6[MAX_IP_ADDRESSES][INET6_ADDRSTRLEN];
    int ipv4_count;
    int ipv6_count;
} dns_result_t;

/* Function prototypes */
void dns_set_log_level(log_level_t level);
void dns_log(log_level_t level, const char *fmt, ...);
int extract_dns_name(const uint8_t *packet, size_t packet_len,
                    size_t offset, char *name, size_t name_len);
int parse_dns_packet(const uint8_t *packet, size_t packet_len,
                    dns_result_t *result);
void print_dns_result(const dns_result_t *result, const char *domain);
int validate_dns_packet(const uint8_t *packet, size_t packet_len);
int append_dns_label(char *dest, const uint8_t *src, uint8_t label_len, size_t dest_offset, size_t max_len);
int handle_dns_compression(const uint8_t *packet, size_t packet_len, size_t *current_offset, size_t *base_offset, int *is_compressed, size_t *jump_count);
int process_question_section(const uint8_t *packet, size_t packet_len, size_t *offset, uint16_t qdcount);
int process_resource_record(const uint8_t *packet, size_t packet_len, size_t *offset, dns_result_t *result);
int process_answer_section(const uint8_t *packet, size_t packet_len, size_t *offset, uint16_t ancount, dns_result_t *result);

#endif /* DNS_PARSER_H */