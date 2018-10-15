#ifndef SNIFFER_PARSER_H
#define SNIFFER_PARSER_H

#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "structures.h"


void parse_rip(const u_char *packet, int rip_legth);
void print_udp_header(struct udpheader *udp);
void print_mac(char *label, unsigned char* address);
void print_ethernet_header(struct ethheader *eth);
void print_ipv4_address(char *label, uint8_t *address);
void print_ipv4_header(struct ipv4header* ipv4);
void parse_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet);
const u_char* print_ethernet_type(const u_char *packet);

#endif