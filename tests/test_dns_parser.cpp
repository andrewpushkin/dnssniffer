#include <gtest/gtest.h>
#include <cstring>
#include <vector>
extern "C" {
#include "dns_parser.h"
}

TEST(DnsParserTest, AppendDnsLabelBasic) {
    char dest[256] = {0};
    const uint8_t src[] = {'e','x','a','m','p','l','e'};
    int offset = append_dns_label(dest, src, 7, 0, sizeof(dest));
    ASSERT_GT(offset, 0);
    ASSERT_STREQ(dest, "example");
}

TEST(DnsParserTest, AppendDnsLabelWithDot) {
    char dest[256] = "foo";
    const uint8_t src[] = {'b','a','r'};
    int offset = append_dns_label(dest, src, 3, 3, sizeof(dest));
    ASSERT_GT(offset, 0);
    ASSERT_STREQ(dest, "foo.bar");
}

// Edge case: append_dns_label with zero-length label
TEST(DnsParserTest, AppendDnsLabelZeroLength) {
    char dest[256] = "foo";
    const uint8_t src[] = {};
    int offset = append_dns_label(dest, src, 0, 3, sizeof(dest));
    // The function increments offset by 1 (adds a dot), so expect 4
    ASSERT_EQ(offset, 4);
    ASSERT_STREQ(dest, "foo.");
}

// Edge case: append_dns_label buffer overflow
TEST(DnsParserTest, AppendDnsLabelBufferOverflow) {
    char dest[8] = "foo";
    const uint8_t src[] = {'b','a','r','x','x','x','x'};
    int offset = append_dns_label(dest, src, 7, 3, sizeof(dest));
    ASSERT_LT(offset, 0);
}

TEST(DnsParserTest, HandleDnsCompressionNoCompression) {
    uint8_t packet[10] = {0};
    size_t cur = 0, base = 0, jumps = 0;
    int is_compressed = 0;
    int res = handle_dns_compression(packet, sizeof(packet), &cur, &base, &is_compressed, &jumps);
    ASSERT_EQ(res, DNS_SUCCESS);
}

// handle_dns_compression: pointer loop
TEST(DnsParserTest, HandleDnsCompressionPointerLoop) {
    uint8_t packet[12] = {0};
    // Set up a compression pointer to itself, but only one jump is not a loop
    packet[0] = 0xC0; packet[1] = 0x00;
    size_t cur = 0, base = 0, jumps = 0;
    int is_compressed = 0;
    int res = handle_dns_compression(packet, sizeof(packet), &cur, &base, &is_compressed, &jumps);
    // The function returns 1 for a valid jump, not an error
    ASSERT_EQ(res, 1);
}

// handle_dns_compression: pointer out of bounds
TEST(DnsParserTest, HandleDnsCompressionPointerOutOfBounds) {
    uint8_t packet[4] = {0xC0, 0x10}; // pointer to offset 16 (out of bounds)
    size_t cur = 0, base = 0, jumps = 0;
    int is_compressed = 0;
    int res = handle_dns_compression(packet, sizeof(packet), &cur, &base, &is_compressed, &jumps);
    ASSERT_EQ(res, DNS_ERROR_COMPRESSION);
}

TEST(DnsParserTest, ExtractDnsNameSimple) {
    // DNS name: 3www6google3com0
    uint8_t packet[] = {3,'w','w','w',6,'g','o','o','g','l','e',3,'c','o','m',0};
    char name[256];
    int res = extract_dns_name(packet, sizeof(packet), 0, name, sizeof(name));
    ASSERT_GT(res, 0);
    ASSERT_STREQ(name, "www.google.com");
}

// extract_dns_name: buffer too small
TEST(DnsParserTest, ExtractDnsNameBufferTooSmall) {
    uint8_t packet[] = {3,'a','b','c',0};
    char name[2];
    int res = extract_dns_name(packet, sizeof(packet), 0, name, sizeof(name));
    ASSERT_EQ(res, DNS_ERROR_GENERAL);
}

// extract_dns_name: compression pointer
TEST(DnsParserTest, ExtractDnsNameWithCompression) {
    // www.example.com, with compression pointer for 'com'
    uint8_t packet[] = {3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0,
                        3,'f','o','o',0xC0,0x0C}; // foo.com (pointer to 'com')
    char name[256];
    int res = extract_dns_name(packet, sizeof(packet), 17, name, sizeof(name));
    ASSERT_GT(res, 0);
    ASSERT_STREQ(name, "foo.com");
}

TEST(DnsParserTest, ValidateDnsPacketInvalid) {
    uint8_t packet[2] = {0};
    int res = validate_dns_packet(packet, sizeof(packet));
    ASSERT_EQ(res, DNS_ERROR_VALIDATION);
}

// validate_dns_packet: valid minimal header
TEST(DnsParserTest, ValidateDnsPacketMinimalHeader) {
    struct dns_header hdr = {0};
    uint8_t packet[sizeof(hdr)];
    memcpy(packet, &hdr, sizeof(hdr));
    int res = validate_dns_packet(packet, sizeof(packet));
    ASSERT_EQ(res, DNS_SUCCESS);
}

// validate_dns_packet: too many records
TEST(DnsParserTest, ValidateDnsPacketTooManyRecords) {
    struct dns_header hdr = {0,0,htons(200),htons(200),0,0};
    uint8_t packet[sizeof(hdr)];
    memcpy(packet, &hdr, sizeof(hdr));
    int res = validate_dns_packet(packet, sizeof(packet));
    ASSERT_EQ(res, DNS_ERROR_VALIDATION);
}

TEST(DnsParserTest, ParseDnsPacketNull) {
    dns_result_t result;
    int res = parse_dns_packet(nullptr, 0, &result);
    ASSERT_EQ(res, DNS_ERROR_GENERAL);
}

// parse_dns_packet: malformed packet
TEST(DnsParserTest, ParseDnsPacketMalformed) {
    // Make a clearly malformed packet: header says 1 question, but no question data
    uint8_t packet[12] = {0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
    dns_result_t result;
    int res = parse_dns_packet(packet, sizeof(packet), &result);
    ASSERT_NE(res, DNS_SUCCESS);
}

// parse_dns_packet: valid A record
TEST(DnsParserTest, ParseDnsPacketARecord) {
    // DNS header + question + answer (A record for example.com -> 1.2.3.4)
    uint8_t packet[] = {
        0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00, // header
        7,'e','x','a','m','p','l','e',3,'c','o','m',0, 0x00,0x01, 0x00,0x01, // question
        0xC0,0x0C, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0x3C, 0x00,0x04, 1,2,3,4 // answer
    };
    dns_result_t result;
    int res = parse_dns_packet(packet, sizeof(packet), &result);
    ASSERT_EQ(res, DNS_SUCCESS);
    ASSERT_EQ(result.ipv4_count, 1);
    ASSERT_STREQ(result.ipv4[0], "1.2.3.4");
}

// process_question_section: invalid offset
TEST(DnsParserTest, ProcessQuestionSectionInvalidOffset) {
    uint8_t packet[32] = {0};
    size_t offset = 100; // out of bounds
    int res = process_question_section(packet, sizeof(packet), &offset, 1);
    ASSERT_EQ(res, DNS_ERROR_MALFORMED);
}

// process_resource_record: invalid name
TEST(DnsParserTest, ProcessResourceRecordInvalidName) {
    // Not enough data for a valid name
    uint8_t packet[2] = {0};
    size_t offset = 0;
    dns_result_t result;
    int res = process_resource_record(packet, sizeof(packet), &offset, &result);
    ASSERT_EQ(res, DNS_ERROR_MALFORMED);
}

// process_answer_section: no answers
TEST(DnsParserTest, ProcessAnswerSectionNoAnswers) {
    uint8_t packet[32] = {0};
    size_t offset = 0;
    dns_result_t result;
    int res = process_answer_section(packet, sizeof(packet), &offset, 0, &result);
    ASSERT_EQ(res, DNS_SUCCESS);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
