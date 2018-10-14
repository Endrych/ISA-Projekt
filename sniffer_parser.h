#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>

#define UDP_HEADER_LEN 8

struct ethheader {
    unsigned char dsta[6];
    unsigned char srca[6];
    unsigned char type[2];
};

struct ipv4header{
    uint8_t version_header_length;
    uint8_t dsf;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags;
    uint8_t time_to_live;
    uint8_t procotocol;
    uint16_t header_check_sum;
    uint8_t source[4];
    uint8_t destination[4];
};

struct ipv6header{
    unsigned char version_trafic_flow[4];
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source[16];
    uint8_t destination[16];
};

struct udpheader{
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct ripheader{
    uint8_t command;
    uint8_t version;
    uint16_t zeroes;
};

void parse_rip(const u_char *packet, int rip_legth);
void print_udp_header(struct udpheader *udp);
void print_mac(char *label, unsigned char* address);
void print_ethernet_header(struct ethheader *eth);
void print_ipv4_address(char *label, uint8_t *address);
void print_ipv4_header(struct ipv4header* ipv4);
void parse_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet);
const u_char* print_ethernet_type(const u_char *packet);