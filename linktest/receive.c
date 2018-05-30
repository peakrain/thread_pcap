#include"main.h"
#include<malloc.h>
struct packet *receive(pcap_t *p)
{
	int err=0;
	struct pcap_pkthdr *packet_h;
	const u_char *pack;
	struct packet *packet=(struct packet*)malloc(sizeof(struct packet));
	if(packet!=NULL)
	{
		err=pcap_next_ex(p,&packet_h,&pack);
		if(err!=1)
		{
			printf("can't get a packet!\n");
			return NULL;
		}
		else
		{
			packet->packet_h=packet_h;
			packet->packet=pack;
			return packet;
		}
	}
	else
	{
		printf("Memory allocation failed!\n");
		return NULL;
	}
}
