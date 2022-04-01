#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include "pcap-test.h"

void printEther(struct libnet_ethernet_hdr * eth_hdr)
{
    printf("[*] Ethernet Header - src: ");
    for (int i=0; i<ETHER_ADDR_LEN; ++i)
    {
        printf("%02X", eth_hdr->ether_shost[i]);
        if (i != ETHER_ADDR_LEN - 1)
            printf(":");
    }
    
    printf(" / dst: ");
    for (int i=0; i<ETHER_ADDR_LEN; ++i)
    {
        printf("%02X", eth_hdr->ether_dhost[i]);
        if (i != ETHER_ADDR_LEN - 1)
            printf(":");
    }
    puts("");
}

void printIPv4(struct libnet_ipv4_hdr * ipv4_hdr)
{
    printf("[*] IPv4 Header - src: ");
    for (int i=0; i<IPV4_ADDR_LEN; ++i)
    {
        printf("%d", ipv4_hdr->ip_src[i]);
        if (i != IPV4_ADDR_LEN - 1)
            printf(".");
    }

    printf(" / dst: ");
    for (int i=0; i<IPV4_ADDR_LEN; ++i)
    {
        printf("%d", ipv4_hdr->ip_dst[i]);
        if (i != IPV4_ADDR_LEN - 1)
            printf(".");
    }
    puts("");
}

void printTCP(struct libnet_tcp_hdr * tcp_hdr)
{
    printf("[*] TCP Header - src port: %d / dst port: %d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
}


void printPacket(const u_char* packet, struct pcap_pkthdr *header)
{
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
    if (ntohs(eth_hdr->ether_type) == ETH_TYPE_IPV4)
    {
        struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        if(ipv4_hdr->ip_p == IP_PROTOCOL_TCP)
        {
            struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)((void *)ipv4_hdr + ipv4_hdr->ip_hl * 4);
            printEther(eth_hdr);
            printIPv4(ipv4_hdr);
            printTCP(tcp_hdr);

            uint32_t i = sizeof(struct libnet_ethernet_hdr) + ipv4_hdr->ip_hl * 4 + tcp_hdr->th_off * 4;
            printf("[*] Payload: ");
            for (int cnt = 0; i < header->caplen; ++i, cnt++)
            {
                if(cnt == 8)
                    break;

                printf("%02X ", packet[i]);
            }
            printf("\n\n");
        }
    }
}