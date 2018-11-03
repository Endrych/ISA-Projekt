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


void send_ripng_response(char * interface, struct in6_addr address, unsigned int adress_prefix, struct in6_addr next_hop_address, unsigned int hop_count, unsigned int router_tag);


#endif