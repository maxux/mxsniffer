#ifndef __MXSNIFFER_H
	#define __MXSNIFFER_H
	// #define NET_DEVICE	"eth0"
	
	#define SNAP_LEN	1514	/* ethernet */
	#define FILTER		"src port 80 or dst port 80"


	#define FULL_DEBUG	0

	void diep(char *str);
	void diepcap(char *func, char *str);
	
	void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *buff);
	int tcp_packet(unsigned char *buffer, int size);
#endif
