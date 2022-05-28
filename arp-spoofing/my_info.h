#ifndef __my_info_h__
#define __my_info_h__
#include <pcap.h>

char* get_my_ip(char *dev);
char* get_my_mac(char *dev);
int get_sender_mac_addresses(pcap_t* handle);

#endif