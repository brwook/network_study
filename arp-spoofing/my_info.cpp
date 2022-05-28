#include "my_info.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <cstring>

char* get_my_mac(char *dev) {
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
		
		printf("[*] my Mac: %s\n", v_mac);
        close(fd);
		return v_mac;
	}

	return 0;
}

char* get_my_ip(char *dev) {
	struct ifreq s;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, dev);

	char *v_ip = (char *)malloc(16);
	if(v_ip == NULL)
		return 0;
	
	if (0 == ioctl(fd, SIOCGIFADDR, &s)) {
		sprintf(v_ip, "%s" , inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
        close(fd);

		printf("[*] my Ip: %s\n", v_ip);
		return v_ip;
	}

	return 0;
}