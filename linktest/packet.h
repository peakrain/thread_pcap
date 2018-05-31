#ifndef _packet_h
#define _packet_h
/*header files*/
#include<pcap.h>
#include<time.h>
/*struct*/
struct packet{
	struct pcap_pkthdr *packet_h;
	u_char *packet_data;
};
struct packet_info{
	char source_ip[16];
	char dest_ip[16];
	int source_port; 
	int dest_port;
	int protocol;
	int packet_len;
	time_t receive_time;
};
/*functions*/
pcap_t *gethandle();
struct packet* receive(pcap_t *handle);
struct packet_info *analysis(struct packet *data);
void info_print(struct packet_info *data);
#endif
