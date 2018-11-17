#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include "sniffer.h"

void print_help()
{
    printf("Usage ./myripsniffer [-h] [-i INTERFACE]\n\t-h\tshow this help message and exit\n\t-i\tInterface\n");
}

int main(int argc, char *argv[])
{
    int c;
    char *interface = NULL;
    pcap_t *handler = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Parsovani argumentu
    while ((c = getopt(argc, argv, "hi:")) != -1)
    {

        switch (c)
        {
        case 'h':
            print_help();
            return EXIT_SUCCESS;
        case 'i':
            interface = optarg;
            break;
        }
    }

    // Kontrola jestli byl zadan interface
    if (interface == NULL)
    {
        fprintf(stderr, "ERROR: Missing interface argument\n");
        print_help();
        exit(EXIT_FAILURE);
    }

    // Pro testovani pomoci pcap souboru
    if (strstr(interface, ".pcap") != NULL)
    {
        handler = pcap_open_offline(interface, errbuf);
        if (handler == NULL)
        {
            fprintf(stderr, "Cannot open file\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        char filter_exp[] = // Filtr
            "portrange 520-521 and udp";

        struct bpf_program filter;

        bpf_u_int32 mask;
        bpf_u_int32 net;

        // Ziskani ip a site
        if (pcap_lookupnet(interface, &net, &mask, errbuf) < 0)
        {
            fprintf(stderr, "Can't get network number for interface %s\n", interface);
            exit(EXIT_FAILURE);
        }

        // Otevreni interfacu pro sniffing
        handler = pcap_open_live(interface, 500, 1,
                                 500, errbuf);
        if (handler == NULL)
        {
            fprintf(stderr, "Could'nt open interface %s: %s\n", interface, errbuf);
            exit(EXIT_FAILURE);
        }

        // Kompilace a nastaveni filtru
        if (pcap_compile(handler, &filter, filter_exp, 0, net) < 0)
        {
            fprintf(stderr, "Couldn't parse this filter %s: %s\n",
                    filter_exp, pcap_geterr(handler));
            exit(EXIT_FAILURE);
        }

        if (pcap_setfilter(handler, &filter) < 0)
        {
            fprintf(stderr, "Couldn't install this filter %s: %s\n",
                    filter_exp, pcap_geterr(handler));
            exit(EXIT_FAILURE);
        }
    }

    /**
     * Monitoring a posilani packetu do funkce parse packet
     */
    pcap_loop(handler, 0, parse_packet, NULL);
    pcap_close(handler);

    return 0;
}