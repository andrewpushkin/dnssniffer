#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

/* Error codes */
#define PCAP_SUCCESS        0
#define PCAP_ERROR_GENERAL -1
#define PCAP_ERROR_INIT    -2
#define PCAP_ERROR_PERM    -3

/* Function prototypes */
int start_capture(const char *interface);
void stop_capture(void);

#endif /* PACKET_CAPTURE_H */