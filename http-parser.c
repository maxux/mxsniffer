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

int http_parse(unsigned char *dat_, int size, char *source) {
	char *host, *temp, *data;
	char *path, *server, *cookies;
	size_t len;
	(void) size;

	/* Casting */
	data = (char *) dat_;

	/* Check for GET Request */
	if(strncmp(data, "GET ", 4) != 0)
		return 0;
	
	if(!(temp = strstr(data + 4, " ")))
		return 0;

	/* Diff pointers to get Size */
	len = temp - data - 3;

	path = (char *) malloc(sizeof(char) * (len + 1));
	strncpy(path, data + 4, len);

	path[len] = '\0';

	/* Checking Host: */
	if(!(host = strstr(temp, "Host: ")))
		return 0;

	host += 6;
	temp = host;

	while(*temp != '\r')
		temp++;
	
	len = temp - host;

	if((server = (char *) malloc(sizeof(char) * (len + 1)))) {
		strncpy(server, host, len);

		server[len] = '\0';
		
		printf("[+] %s: http://%s%s\n", source, server, path);
		fflush(stdout);
		free(path);
	}
	
	/* Re-Using previous variables for Cookies */
	temp = strstr(data, "Cookie: ");
	
	/* Checking if there is some cookies */
	if(temp == NULL) {
		free(server);
		return 0;
	}
	
	temp += 8;
	
	path = strstr(temp, "\r\n");
	
	if(path == NULL) {
		free(server);
		return 0;
	}
	
	cookies = (char *) malloc(sizeof(char) * (path - temp) + 1);
	strncpy(cookies, temp, path - temp);
	cookies[path - temp - 1] = '\0';
	
	/* printf("-> %s", cookies); */
	
	free(server);
	free(cookies);
	
	return 0;
}
