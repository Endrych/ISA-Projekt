#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "response.h"


int main(int argc, char *argv[])
{
    int c;
    char *interface = NULL;
    struct in6_addr address;
    struct in6_addr next_hop_address;
    int hop_count = 1;
    int router_tag = 0;
    int state = inet_pton(AF_INET6, "::",&next_hop_address);

    while ((c = getopt(argc, argv, "hi:r:m:n:t:")) != -1)
    {
        switch (c)
        {
            case 'h':
                printf("Help\n");
                return 0;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'r':
                state = inet_pton(AF_INET6, optarg,&address);
                printf("State %d\n",state);
                break;
            case 'm':
                hop_count = atoi(optarg);
                break;
            case 'n':
                state = inet_pton(AF_INET6, optarg,&next_hop_address);
                printf("State %d\n",state);
                break;
            case 't':
                router_tag = atoi(optarg);
                break;
        }
    }

    send_ripng_response();

    return  0;
}