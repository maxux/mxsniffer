#include <stdio.h>
#include <stdlib.h>
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

void dump_tcp(struct tcphdr *tcph) {
	printf("\n+ TCP Header\n");
	printf("|- Source Port      : %u\n", ntohs(tcph->source));
	printf("|- Destination Port : %u\n", ntohs(tcph->dest));
	printf("|- Sequence Number  : %u\n", ntohl(tcph->seq));
	printf("|- Header Length    : %d (%d bytes)\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff*4);
	printf("|- Window           : %d\n", ntohs(tcph->window));
	printf("|- Checksum         : %d\n\n", ntohs(tcph->check)); 
}
