#ifndef _packet_h
#define _packet_h
/*header files*/
#include<pacp.h>
#include<malloc.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<netinet/if_ether.h>
#include<time.h>
/*struct*/
struct packet{
	struct pcap_pkthdr *packet_h;
	const u_char packet_data;
};
struct packet_INFO{
	const char *source_ip;
	const char *dest_ip;
	const int source_port; 
	const int dest_port;
	const int ptotocol;
	const int packet_len;
	const time_t receive_time;
};
/*functions*/
pcap_t *handle();
struct packet* receive(pcap_t *handle);
struct packet_info *analysis(struct packet *data);
void info_print(struct packet_INFO *data);
void err_sys(char *info,char *e);
#endif
