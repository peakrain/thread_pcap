#include"main.h"
#include<netinet/in.h>
#include<netinet/if_ether.h>
struct print_data *analysis(struct packet *p)
{
	struct print_data *output=malloc(sizeof(struct print_data *));
	/*analysis ip header*/
	struct in_addr addr;
	struct iphdr *ip_h=(struct iphdr*)(p->packet+sizeof(struct ether_header));
	addr.s_addr=ip_h->saddr;
	output->sourceip=inet_ntoa(addr);
	addr.s_addr=ip_h->daddr;
	output->destip=inet_ntoa(addr);
	output->protocol=ip_h->protocol;
	/*analysis tcp header*/
	struct tcphdr *tcp_h=(struct tcphdr*)(p->packet+sizeof(struct ether_header)+sizeof(struct iphdr));
	output->sourceport=ntohs(tcp_h->source);
	output->destport=ntohs(tcp_h->dest);	
	/*analysis packet header*/
	output->packet_len=p->packet_h->len;
	output->time=p->packet_h->ts.tv_sec;
	return output;
}
