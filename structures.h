#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdint.h>

/**
 *  Ethernetnetova hlavicka
 **/
struct ethheader
{
    uint8_t dsta[6];
    uint8_t srca[6];
    uint16_t type;
};

/**
 * Hlavicka IPV4 protokolu
 **/
struct ipv4header
{
    uint8_t version_header_length;
    uint8_t dsf;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags;
    uint8_t time_to_live;
    uint8_t procotocol;
    uint16_t header_check_sum;
    uint8_t source[4];
    uint8_t destination[4];
};

/**
 * Hlavicka IPV6 protokolu
 **/
struct ipv6header
{
    uint8_t version_trafic_flow[4];
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source[16];
    uint8_t destination[16];
};

/**
 * Hlavicka UDP
 **/
struct udpheader
{
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

/**
 * Hlavicka RIP protokolu
 **/
struct ripheader
{
    uint8_t command;
    uint8_t version;
    uint16_t zeroes;
};

/**
 * Telo RIPv1 protokolu
 **/
struct ripv1body
{
    uint16_t afi;
    uint16_t zeroes;
    uint8_t ip_address[4];
    uint32_t zeroes_again[2];
    uint32_t metric;
};

/**
 * Entry RIPv1 a RIPv2 protokolu
 **/
struct entry
{
    uint16_t afi;
    uint16_t route_tag;

    /**
     * Jedna z moznosti bud (obycejna autentizace/obycejny entry/MD5 autentizace)
     */
    union {
        struct
        {
            uint8_t auth[16];
        };
        struct
        {
            uint8_t address[4];
            uint8_t subnet_mask[4];
            uint8_t next_hop[4];
            uint32_t metric;
        };
        struct
        {
            uint16_t diggest_offset;
            uint8_t key_id;
            uint8_t auth_data_len;
            uint32_t seq_number;
            uint8_t must_be_zero[8];
        };
    };
};

/**
 * Entry RIPng protokolu
 **/
struct entryng
{
    uint8_t address[16];
    uint16_t route_tag;
    uint8_t prefix_len;
    uint8_t metric;
};

#endif