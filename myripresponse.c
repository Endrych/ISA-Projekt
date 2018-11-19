#include <getopt.h>
#include <string.h>
#include "response.h"

void print_help()
{
    printf("Usage ./myripsniffer [-h] [-i INTERFACE]\n\t-h\tshow this help message and exit\n\t-i\tInterface\n");
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
    char *addr;

    // Nastaveni defaultni next hop adresy na ::
    if (!inet_pton(AF_INET6, "::", &next_hop_address))
    {
        fprintf(stderr, "Cant convert nexthop adress.\n");
        exit(EXIT_FAILURE);
    }

    // Parsovani argumentu
    while ((c = getopt(argc, argv, "hi:r:m:n:t:")) != -1)
    {
        switch (c)
        {
        case 'h':
            print_help();
            return EXIT_SUCCESS;
            break;
        case 'i':
            interface = optarg;
            break;
        case 'r':
            /**
             * Zpracovani adresy podvrhavane site
             */
            addr = strtok(optarg, "/");
            if (!inet_pton(AF_INET6, addr, &address))
            {
                fprintf(stderr, "Invalid format of IPv6 address.\n");
                exit(EXIT_FAILURE);
            }
            set_addr = 1;

            /**
             * Zpracovani prefixu adresy site
             */
            char *prefix = strtok(NULL, "/");
            if (prefix == NULL)
            {
                fprintf(stderr, "Missing prefix length.\n");
                exit(EXIT_FAILURE);
            }

            adress_prefix = strtoul(prefix, NULL, 0);

            /**
             * Kontrola hodnoty prefixu
             */
            if (adress_prefix < 16 || adress_prefix > 128)
            {
                fprintf(stderr, "Wrong value of address prefix.\n./myripresponse -h for help.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'm':
            hop_count = atoi(optarg);
            if (hop_count < 0 || hop_count > 16)
            {
                fprintf(stderr, "Wrong value of hop count.\n./myripresponse -h for help.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'n':
            /*
             *  Zpracovani adresy next hopu
             */
            if (!inet_pton(AF_INET6, optarg, &next_hop_address))
            {
                fprintf(stderr, "Invalid format of IPv6 address.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 't':
            router_tag = atoi(optarg);
            if (router_tag < 0 || router_tag > 65535)
            {
                fprintf(stderr, "Wrong value of router tag.\n./myripresponse -h for help.\n");
                exit(EXIT_FAILURE);
            }
            break;
        }
    }

    /**
     * Kontrola jestli jsou znamy vsechny dulezite informace
     */
    if (set_addr != 1 || adress_prefix == -1 || interface == NULL)
    {
        fprintf(stderr, "Required arguments not set.\n./myripresponse -h for help.\n");
        exit(EXIT_FAILURE);
    }

    send_ripng_response(interface, address, adress_prefix, next_hop_address, hop_count, router_tag);

    return 0;
}