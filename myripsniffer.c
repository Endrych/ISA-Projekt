#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include "sniffer_parser.h"
#include <pcap.h>

int main(int argc, char *argv[])
{
    int c;;;
    char *interface = NULL;
    pcap_t *handler = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];


    while((c = getopt(argc, argv, "hi:")) != -1){
        switch(c){
            case 'h':
                printf("Help\n");
                return 0;
                break;
            case 'i':
                interface = optarg;
                break;
        }
    }

    if (interface == NULL){
        printf("Help\n");
        exit(EXIT_FAILURE);
    }

    if(strstr(interface,".pcap") != NULL){
        handler = pcap_open_offline(interface, errbuf);
        if(handler == NULL){
            fprintf(stderr,"Could't open %s file\n",interface);
            exit(EXIT_FAILURE);
        }else{
            printf("Open to %s was successfully!\n", interface);
        }
    }else{
        printf("Some interface\n");
    }

    // cnt = 0 => Infinity loop
    pcap_loop(handler, 0, parse_packet, NULL);
    pcap_close(handler);


    return 0;
}