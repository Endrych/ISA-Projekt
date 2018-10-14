#include "sniffer_parser.h"


void print_mac(char *label, unsigned char* address)
{
    printf("%s: ", label);
    for(int i=0;i<5;i++){
        printf("%.2x:",address[i]);
    }
    printf("%.2x\n",address[5]);
}

void print_ethernet_header(struct ethheader *eth)
{
    printf("Ethernet protocol\n--------------------\n");
    print_mac("Destination",eth->dsta);
    print_mac("Source",eth->srca);
    printf("\n");
}

void print_ipv4_address(char *label, uint8_t *address)
{   
    printf("%s: ", label);
    for(int i=0;i<3;i++){
        printf("%d.",address[i]);
    }
    printf("%d\n",address[3]);
}

void print_ipv4_header(struct ipv4header* ipv4)
{
    printf("Internet protocol(IPv4)\n--------------------\n");
    print_ipv4_address("Destination",ipv4->destination);
    print_ipv4_address("Source",ipv4->source);
    printf("\n");
}

void print_udp_header(struct udpheader *udp)
{
    printf("User Datagram Protocol\n--------------------\n");
    printf("Destination Port: %d\n",ntohs(udp->dest_port));
    printf("Source Port: %d\n",ntohs(udp->source_port));
    printf("Length: %d", ntohs(udp->length));
    printf("\n");
}

void parse_rip(const u_char *packet, int rip_legth)
{
    struct ripheader *riph = (struct ripheader*) packet;
    printf("Routing Information Procotol\n--------------------\n");
    printf("Command: %s", (riph->command == 2)? "Response":"Request");

}

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader*) packet;
    print_ethernet_header(eth);
    packet += sizeof(struct ethheader);
    if(eth->type[0] == 8 && eth->type[1] == 0)
    {
        //IPv4
        struct ipv4header *ipv4 = (struct ipv4header*) packet;
        print_ipv4_header(ipv4);
        packet += sizeof(struct ipv4header);
        struct udpheader *udp = (struct udpheader*) packet;
        print_udp_header(udp);
        packet += sizeof(struct udpheader);
        int rip_legth = ntohs(udp->length) - UDP_HEADER_LEN;
        parse_rip(packet, rip_legth);

    }
    else
    {
        // IPv6
    }

    printf("\n\n\n");
}