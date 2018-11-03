#include <getopt.h>
#include <string.h>
#include "response.h"

void ipv6_to_str_unexpanded(const struct in6_addr *addr)
{
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           (int)addr->s6_addr[0], (int)addr->s6_addr[1],
           (int)addr->s6_addr[2], (int)addr->s6_addr[3],
           (int)addr->s6_addr[4], (int)addr->s6_addr[5],
           (int)addr->s6_addr[6], (int)addr->s6_addr[7],
           (int)addr->s6_addr[8], (int)addr->s6_addr[9],
           (int)addr->s6_addr[10], (int)addr->s6_addr[11],
           (int)addr->s6_addr[12], (int)addr->s6_addr[13],
           (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

int main(int argc, char *argv[])
{
    int c;
    char *interface = NULL;
    struct in6_addr address;
    unsigned int adress_prefix = -1;
    struct in6_addr next_hop_address;
    unsigned int hop_count = 1;
    unsigned int router_tag = 0;
    unsigned int set_addr = 0;
    if (!inet_pton(AF_INET6, "::", &next_hop_address))
    {
        fprintf(stderr, "Cant convert nexthop adress.\n");
        exit(EXIT_FAILURE);
    }
    char *addr;

    while ((c = getopt(argc, argv, "hi:r:m:n:t:")) != -1)
    {
        switch (c)
        {
        case 'h':
            printf("Help\n");
            return EXIT_SUCCESS;
            break;
        case 'i':
            interface = optarg;
            break;
        case 'r':
            addr = strtok(optarg, "/");
            if (!inet_pton(AF_INET6, addr, &address))
            {
                fprintf(stderr, "Invalid format of IPv6 address.\n");
                exit(EXIT_FAILURE);
            }
            set_addr = 1;

            char *prefix = strtok(NULL, "/");
            if (prefix == NULL)
            {
                fprintf(stderr, "Missing prefix length.\n");
                exit(EXIT_FAILURE);
            }

            adress_prefix = strtoul(prefix, NULL, 0);
            break;
        case 'm':
            hop_count = atoi(optarg);
            break;
        case 'n':
            if (!inet_pton(AF_INET6, optarg, &next_hop_address))
            {
                fprintf(stderr, "Invalid format of IPv6 address.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 't':
            router_tag = atoi(optarg);
            break;
        }
    }

    if (set_addr != 1 || adress_prefix == -1 || interface == NULL)
    {
        fprintf(stderr, "Required arguments not set.\n./myripresponse -h for help.\n");
        exit(EXIT_FAILURE);
    }

    // printf("Interface: %s\n", interface);
    // printf("IPv6 Address:");
    // ipv6_to_str_unexpanded(&address);
    // printf("Prefix: %d\n", adress_prefix);
    // printf("IPv6 Next hop address:");
    // ipv6_to_str_unexpanded(&next_hop_address);
    // printf("Hop count: %d\n", hop_count);
    // printf("Router tag: %d\n", router_tag);

    send_ripng_response(interface, address, adress_prefix, next_hop_address, hop_count, router_tag);

    return 0;
}