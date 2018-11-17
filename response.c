#include "response.h"

void ipv6_to_uint8_t(struct in6_addr address, uint8_t *new_addr)
{
    for (int i = 0; i < 16; i++)
    {
        new_addr[i] = address.s6_addr[i];
    }
}

void send_ripng_response(char *interface, struct in6_addr address, unsigned int address_prefix, struct in6_addr next_hop_address, unsigned int hop_count, unsigned int router_tag)
{
    /**
     * Nastaveni hlavicky RIPng protokolu
     */
    struct ripheader header;
    header.command = 2;
    header.version = 1;

    /**
     * Nastaveni entry s nexthop adresou
     */
    struct entryng nexthop_entry;
    nexthop_entry.metric = 0xFF;
    nexthop_entry.prefix_len = 0;
    nexthop_entry.route_tag = 0;
    ipv6_to_uint8_t(next_hop_address, &nexthop_entry.address[0]);

    /**
     * Nastaveni entry s adresou podvravane site
     */
    struct entryng address_entry;
    address_entry.metric = hop_count;
    address_entry.route_tag = router_tag;
    address_entry.prefix_len = address_prefix;
    ipv6_to_uint8_t(address, &address_entry.address[0]);

    /**
     * Velikosti struktur
     */
    size_t header_size = sizeof(struct ripheader);
    size_t entry_size = sizeof(struct entryng);
    unsigned int packet_size = header_size + 2 * entry_size;

    /**
     * Alokace pameti pro packet
     */
    uint8_t *packet = NULL;
    packet = (uint8_t *)malloc(packet_size);

    /**
     *  Naplneni packetu daty
     */
    memcpy(packet, &header, header_size);
    memcpy(packet + header_size, &nexthop_entry, entry_size);
    memcpy(packet + header_size + entry_size, &address_entry, entry_size);

    /**
     * Vytvoreni socketu
     */
    int sockfd;
    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    /**
     * Nastaveni socketu
     */
    setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
               interface, strlen(interface));

    unsigned int index = if_nametoindex(interface);
    unsigned int hops = 255;
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index));

    /**
     * Bind adresy
     */
    struct sockaddr_in6 bind_address, dest_addr;
    bzero(&bind_address, sizeof(bind_address));
    bind_address.sin6_family = AF_INET6;
    bind_address.sin6_addr = in6addr_any;
    bind_address.sin6_port = htons(521);

    if (bind(sockfd, (struct sockaddr *)&bind_address, sizeof(bind_address)))
    {
        fprintf(stderr, "Cannot bind socket\n");
    }

    /**
     * Nastaveni cilove adresy
     */
    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin6_port = htons(521);
    dest_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "ff02::9", &dest_addr.sin6_addr);

    /**
     * Poslani packetu
     */
    sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    /**
     * Uzavreni socketu
     */
    close(sockfd);
}