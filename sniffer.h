#ifndef SNIFFER_PARSER_H
#define SNIFFER_PARSER_H

#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "structures.h"

/**
 * @brief Funkce vytiskne MAC adresu
 * 
 * @param label Popis vystupu (Na vystupu bude retezec {label: adresa}  )
 * @param address mac adresa
 */
void print_mac(char *label, unsigned char* address);

/**
 * @brief Funkce vytiskne ethernetovou hlavicku
 * 
 * @param eth Struktura reprezentujici ethernetovou hlavicku
 */
void print_ethernet_header(struct ethheader *eth);

/**
 * @brief Funkce vytiskne IPv4 adresu
 * 
 * @param label Popis vystupu (Na vystupu bude retezec {label: adresa}  )
 * @param address IPv4 adresa
 */
void print_ipv4_address(char *label, uint8_t *address);

/**
 * @brief Funkce vytiskne IPv6 adresu
 * 
 * @param label Popis vystupu (Na vystupu bude retezec {label: adresa}  )
 * @param address IPv6 adresa
 */
void print_ipv6_address(char *label, uint8_t *address);

/**
 * @brief Funkce vytiskne hlavicku IPv6 protokolu
 * 
 * @param ipv6 Struktura reprezentujici IPv6 hlavicku
 */
void print_ipv6_header(struct ipv6header *ipv6);

/**
 * @brief Funkce vytiskne hlavicku IPv4 protokolu
 * 
 * @param ipv4 Struktura reprezentujici IPv4 hlavicku
 */
void print_ipv4_header(struct ipv4header* ipv4);

/**
 * @brief Funkce vytiskne hlavicku UDP protokolu
 * 
 * @param udp Struktura reprezentujici UDP hlavicku
 */
void print_udp_header(struct udpheader *udp);

/**
 * @brief Funkce vytiskne telo RIPv1 protokolu
 * 
 * @param body Struktura reprezentujici telo protokolu
 */
void print_ripv1_body(struct ripv1body *body);

/**
 * @brief Funkce vytiskne telo RIPv2 protokolu
 * 
 * @param body Struktura reprezentujici telo protokolu
 */
void print_ripv2_entry(struct entry *entry);

/**
 * @brief 
 * 
 * @param packet 
 * @param rip_legth
 */
void parse_rip(const u_char *packet, int rip_legth);

/**
 * @brief 
 * 
 * @param entry 
 */
void print_ripng_entry(struct entryng *entry);

/**
 * @brief 
 * 
 * @param packet
 * @param rip_length
 */
void parse_ripng(const u_char *packet, int rip_length)

/**
 * @brief 
 * 
 * @param args 
 * @param header 
 * @param packet 
 */
void parse_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet);

#endif