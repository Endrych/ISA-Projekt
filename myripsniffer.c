#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include "sniffer.h"
#include <pcap.h>


#define PCAP_SNAPLEN 500
#define PROMISC_MOD 1
#define PCAP_TIMEOUT 500

int main(int argc, char *argv[])
{
    int c;
    ;
    ;
    char *interface = NULL;
    pcap_t *handler = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    while ((c = getopt(argc, argv, "hi:")) != -1)
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
        }
    }

    if (interface == NULL)
    {
        printf("Help\n");
        exit(EXIT_FAILURE);
    }

    if (strstr(interface, ".pcap") != NULL)
    {
        handler = pcap_open_offline(interface, errbuf);
        if (handler == NULL)
        {
            fprintf(stderr, "Could't open %s file\n", interface);
            exit(EXIT_FAILURE);
        }
        else
        {
            printf("Open to %s was successfully!\n", interface);
        }
    }
    else
    {
        char filter_exp[] =             // The filter expression
                "portrange 520-521 and udp";
        //          "portrange 520 and udp";
        struct bpf_program filter;      // The compiled expression

        bpf_u_int32 mask;               // The netmask of sniffing device
        bpf_u_int32 net;                // The IP of sniffing device

        // Get the IP and netmask of device
        if (pcap_lookupnet(interface, &net, &mask, errbuf) < 0)
        {
            fprintf(stderr, "Can't get network number for interface %s\n", interface);
            exit(EXIT_FAILURE);
        }

        // Open interface for sniffing
        handler = pcap_open_live(interface, PCAP_SNAPLEN, PROMISC_MOD,
                                 PCAP_TIMEOUT, errbuf);
        if (handler == NULL)
        {
            fprintf(stderr, "Could'nt open interface %s: %s\n", interface, errbuf);
            exit(EXIT_FAILURE);
        }

        // Compile and set the filter
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

    // cnt = 0 => Infinity loop
    pcap_loop(handler, 0, parse_packet, NULL);
    pcap_close(handler);

    return 0;
}