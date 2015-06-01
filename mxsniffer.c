#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h> 
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "mxsniffer.h"
#include "http-parser.h"
#include "debug.h"

int prevCheck = 0;

void diep(char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}

void diepcap(char *func, char *str) {
	fprintf(stderr, "[-] %s: %s\n", func, str);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	char err_buff[PCAP_ERRBUF_SIZE];
	unsigned char *buff = NULL;
	pcap_t *pdes;
	bpf_u_int32 netp, maskp;
	struct bpf_program bp;
	
	if(argc < 2) {
		fprintf(stderr, "Usage: %s interface\n", argv[0]);
		return 1;
	}
	
	printf("[+] Linking to: %s\n", argv[1]);
	if((pdes = pcap_open_live(argv[1], SNAP_LEN, IFF_PROMISC, 1000, err_buff)) == NULL)
		diepcap("pcap_open_live", err_buff);
	
	if(pcap_lookupnet(argv[1], &netp, &maskp, err_buff) == -1)
		diepcap("pcap_lookupnet", err_buff);
	
	printf("[+] Setting Up Filters...\n");
	if(pcap_compile(pdes, &bp, FILTER, 0x100, maskp) < 0)
		diepcap("pcap_compile", pcap_geterr(pdes));
	
	if(pcap_setfilter(pdes, &bp) < 0)
		diepcap("pcap_setfilter", pcap_geterr(pdes)); 

	printf("[+] Listening...\n");
	if(pcap_loop(pdes, -1, callback, buff) < 0)
		diepcap("pcap_loop", pcap_geterr(pdes));
	
	return 0;
}

void callback(unsigned char *user, const struct pcap_pkthdr *h, const u_char *buff) {
	struct ether_header *eptr;
	struct ether_header *ethheader;
	u_char *packet;
	struct iphdr *iph; //, *ipheader;
	(void) *user;
	
	eptr = (struct ether_header *) buff;
	
	/* IP Packet */
	if(eptr->ether_type == 8) {
		ethheader = (struct ether_header *)buff;
		// ipheader = (struct iphdr *)(buff + sizeof(struct ether_header));
		
		packet = (unsigned char*)(buff + sizeof(*ethheader));
		iph = (struct iphdr*) packet;
		
		/* TCP */
		if(iph->protocol == 6)
			tcp_packet(packet, h->len - sizeof(ethheader));
	}
}

int tcp_packet(unsigned char* buffer, int size) {
	unsigned short iphdrlen;
	struct sockaddr_in source;
	struct iphdr *iph = (struct iphdr *)buffer;
	struct tcphdr *tcph;
	
	iphdrlen = iph->ihl * 4;
	tcph = (struct tcphdr *)(buffer + iphdrlen);
	
	/* Prevent Double Packet */
	if(prevCheck == ntohs(tcph->check))
		return 1;
	
	memset(&source, 0x00, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	/* Saving Last Checksum */
	prevCheck = ntohs(tcph->check);
	
	/* dump_tcp(tcph); */
	http_parse(buffer + iphdrlen + (tcph->doff * 4), (size - (tcph->doff * 4) - (iph->ihl * 4) - 6), inet_ntoa(source.sin_addr));
	
	return 0;
}
