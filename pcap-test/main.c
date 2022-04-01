#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>
#include "pcap-test.h"

void printPacket(const u_char* packet, struct pcap_pkthdr *header);
int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("syntax: %s <interface>\n", argv[0]);
        printf("sample: %s wlan0\n", argv[0]);
        return -1;
    }

    char* interface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
        printPacket(packet, header);
    }

    pcap_close(pcap);
}
