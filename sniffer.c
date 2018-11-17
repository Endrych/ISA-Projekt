#include "sniffer.h"

void print_mac(char *label, unsigned char *address)
{
    printf("%s: ", label);
    for (int i = 0; i < 5; i++)
    {
        printf("%.2x:", address[i]);
    }
    printf("%.2x\n", address[5]);
}

void print_ethernet_header(struct ethheader *eth)
{
    printf("------Ethernet protocol------\n");
    print_mac("Destination", eth->dsta);
    print_mac("Source", eth->srca);
    printf("\n");
}

void print_ipv4_address(char *label, uint8_t *address)
{
    printf("%s: ", label);
    for (int i = 0; i < 3; i++)
    {
        printf("%d.", address[i]);
    }
    printf("%d\n", address[3]);
}

void print_ipv6_address(char *label, uint8_t *address)
{
    char str[INET6_ADDRSTRLEN];

    // Prevod ipv6 adresy do peknejsiho formatu
    inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
    printf("%s: %s\n", label, str);
}

void print_ipv6_header(struct ipv6header *ipv6)
{
    printf("------Internet protocol(IPv6)------\n");
    print_ipv6_address("Destination", ipv6->destination);
    print_ipv6_address("Source", ipv6->source);
    printf("\n");
}

void print_ipv4_header(struct ipv4header *ipv4)
{
    printf("------Internet protocol(IPv4)------\n");
    print_ipv4_address("Destination", ipv4->destination);
    print_ipv4_address("Source", ipv4->source);
    printf("\n");
}

void print_udp_header(struct udpheader *udp)
{
    printf("------User Datagram Protocol------\n");
    printf("Destination Port: %d\n", ntohs(udp->dest_port));
    printf("Source Port: %d\n", ntohs(udp->source_port));
    printf("Length: %d\n", ntohs(udp->length));
    printf("\n");
}

void print_ripv1_body(struct ripv1body *body)
{
    printf("--------------\n");
    print_ipv4_address("IP address", body->ip_address);
    printf("Metric: %lu\n", (unsigned long)ntohl(body->metric));
    printf("--------------\n");
}

void print_ripv2_entry(struct entry *entry)
{
    /**
     * Kontrola jestli se nejedna o autentizaci
     */
    if (ntohs(entry->afi) == 0xFFFF)
    {
        int auth_type = ntohs(entry->route_tag);

        /**
         * Rozliseni vypisu podle typu autentizace
         */
        if (auth_type == 3)
        {
            /**
             * MD5 Prvni cast
             */
            printf("--------Keyed Message Digest-----------\n");
            printf("Digest Offset: %d\n", htons(entry->diggest_offset));
            printf("Key ID: %d\n", entry->key_id);
            printf("Auth Data Len: %d\n", entry->auth_data_len);
            printf("Sequence Number: %d\n", htonl(entry->seq_number));
            printf("\n");
        }
        else if (auth_type == 1)
        {
            /**
             * MD5 Druha cast
             */
            printf("------Authentication Data Trailer------\n");
            printf("Authentication Data: ");
            for (int i = 0; i < 16; i++)
            {
                int c = entry->auth[i];
                printf("%.2x", c);
            }
            printf("\n\n");
        }
        else
        {
            /**
             *  Autentizace pomoci obycejneho hesla 
             */
            printf("------Authentication------\n");
            printf("Authentication type: %d\n", auth_type);

            printf("Password: ");

            for (int i = 0; i < 16; i++)
            {
                int c = entry->auth[i];
                if (c != '\0')
                {
                    putchar(c);
                }
                else
                {
                    break;
                }
            }
            printf("\n\n");
        }
    }
    else
    {
        printf("------Entry------\n");
        printf("Route tag: %d\n", ntohs(entry->route_tag));
        print_ipv4_address("IP address", entry->address);
        print_ipv4_address("Subnet mask", entry->subnet_mask);
        print_ipv4_address("Next hop", entry->next_hop);
        printf("Metric: %lu\n", (unsigned long)ntohl(entry->metric));
        printf("\n");
    }
}

void parse_rip(const u_char *packet, int rip_length)
{
    /**
     * Zpracovani hlavicky protokolu
     */
    struct ripheader *riph = (struct ripheader *)packet;
    packet += sizeof(struct ripheader);
    rip_length -= sizeof(struct ripheader);

    printf("------Routing Information Procotol------\n");
    printf("Command: %s\n", (riph->command == 2) ? "Response" : "Request");
    printf("Version: %d\n", riph->version);

    /**
     * Zjistovani verze protokolu
     */
    if (riph->version == 1)
    {
        int body_size = sizeof(struct ripv1body);
        /**
         * Zpracovani tela protokolu
         */
        while (rip_length >= body_size)
        {
            struct ripv1body *ripbody = (struct ripv1body *)packet;
            print_ripv1_body(ripbody);
            packet += body_size;
            rip_length -= body_size;
        }
    }
    else
    {
        int entry_size = sizeof(struct entry);
        /**
         * Zpracovani tela protokolu
         */
        while (rip_length >= entry_size)
        {
            struct entry *entry = (struct entry *)packet;
            print_ripv2_entry(entry);
            packet += entry_size;
            rip_length -= entry_size;
        }
    }
}

void print_ripng_entry(struct entryng *entry)
{
    if (ntohs(entry->metric) == 0xFF)
    {
        printf("------Next hop------\n");
        print_ipv6_address("IPv6 address", entry->address);
        printf("\n");
    }
    else
    {
        printf("------Entry------\n");
        print_ipv6_address("IPv6 prefix", entry->address);
        printf("Route tag: %x\n", entry->route_tag);
        printf("Prefix len: %d\n", entry->prefix_len);
        printf("Metric: %d\n", entry->metric);
        printf("\n");
    }
}

void parse_ripng(const u_char *packet, int rip_length)
{
    /**
     * Zpracovani hlavicky protokolu
     */
    struct ripheader *riph = (struct ripheader *)packet;
    packet += sizeof(struct ripheader);
    rip_length -= sizeof(struct ripheader);

    printf("------RIPng------\n");
    printf("Command: %s\n", (riph->command == 2) ? "Response" : "Request");
    printf("Version: %d\n", riph->version);

    int entry_size = sizeof(struct entryng);
    /**
     * Zpracovani tela protokolu
     */
    while (rip_length >= entry_size)
    {
        struct entryng *entry = (struct entryng *)packet;
        print_ripng_entry(entry);
        packet += entry_size;
        rip_length -= entry_size;
    }
}

void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("-------------------------------\n"
           "------- Packet start ----------\n"
           "-------------------------------\n\n\n");
    /**
     * Zpracovani ethernetoveho protokolu
     */
    struct ethheader *eth = (struct ethheader *)packet;
    print_ethernet_header(eth);
    packet += sizeof(struct ethheader);

    /**
     * Rozliseni IPv4, IPv6
     */
    if (ntohs(eth->type) == 0x0800)
    {
        /**
         * Zpracovani IPv4 protokolu
         */
        struct ipv4header *ipv4 = (struct ipv4header *)packet;
        print_ipv4_header(ipv4);
        packet += sizeof(struct ipv4header);
    }
    else
    {
        /**
         * Zpracovani IPv6 protokolu
         */
        struct ipv6header *ipv6 = (struct ipv6header *)packet;
        print_ipv6_header(ipv6);
        packet += sizeof(struct ipv6header);
    }

    /**
     * Zpracovani UDP protokolu
     */
    struct udpheader *udp = (struct udpheader *)packet;
    print_udp_header(udp);
    packet += sizeof(struct udpheader);
    int rip_length = ntohs(udp->length) - sizeof(struct udpheader);

    /**
     * Rozliseni RIPv1,v2 / RIPng
     */
    if (ntohs(eth->type) == 0x0800)
    {
        parse_rip(packet, rip_length);
    }
    else
    {
        parse_ripng(packet, rip_length);
    }

    printf("\n\n\n");
}