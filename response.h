#ifndef RESPONSE_H
#define RESPONSE_H

#include "structures.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

/**
 * @brief Konverze adresy z in6addr do pole uint8_t
 * 
 * @param address Zdoj
 * @param new_addr Cil
 */
void ipv6_to_uint8_t(struct in6_addr address, uint8_t *new_addr);

/**
 * @brief Funkce odesle RIPng response
 * 
 * @param interface Udává rozhraní, ze kterého má být útočný paket odeslán;
 * @param address IP adresa podvrhávané sítě
 * @param adress_prefix Prefix IPv6 adresy
 * @param next_hop_address Adresa next-hopu pro podvrhávanou routu
 * @param hop_count RIP Metriku (pocet hopu)
 * @param router_tag 
 */
void send_ripng_response(char *interface, struct in6_addr address, unsigned int adress_prefix, struct in6_addr next_hop_address, unsigned int hop_count, unsigned int router_tag);

#endif