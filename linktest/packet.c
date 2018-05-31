#include"packet.h"
#include<malloc.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<netinet/if_ether.h>
#include<string.h>
void err_sys(char *info,char *e);
char *format(time_t rtime);
pcap_t *gethandle()
{
	char ebuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *p,*handle=NULL;
	device=pcap_lookupdev(ebuf);
	if(!device)
	{
		err_sys("Can't find available device:",ebuf);
		return NULL;
	}
	p=pcap_open_live(device,65535,1,0,ebuf);
	if(!p)
	{
		err_sys("Can't get handle:",ebuf);
		return NULL;
	}
	handle=(pcap_t *)malloc(sizeof(pcap_t *));
	if(handle==NULL)
	{
		err_sys("handle memory allocation failed!\n",NULL);
		return NULL;
	}
	handle=p;
	return handle;
}
struct packet *receive(pcap_t *handle)
{
	struct packet *packet=NULL;
	packet=(struct packet*)malloc(sizeof(struct packet));
	if(packet==NULL)
	{
		err_sys("packet memory allocation failed!",NULL);
		return NULL;
	}
	struct pcap_pkthdr *p_h;
	const u_char *p;
	int err=0;
	err=pcap_next_ex(handle,&p_h,&p);
	if(err!=1)
	{
		err_sys("get packet failed!",strerror(err));
		free(packet);
		return NULL;
	}
	packet->packet_h=p_h;
	packet->packet_data=(char *)p;
	return packet;
}
struct packet_info *analysis(struct packet *data)
{
	struct packet_info *info=NULL;
	info=(struct packet_info*)malloc(sizeof(struct packet_info));
	if(info==NULL)
	{
		err_sys("info memory allocation failed!",NULL);
		return NULL;
	}
	/*analysis ip header*/
	struct iphdr *ip_h;
	struct in_addr saddr,daddr;
	ip_h=(struct iphdr*)(data->packet_data+sizeof(struct ether_header));
	saddr.s_addr=ip_h->saddr;
	strcpy(info->source_ip,inet_ntoa(saddr));
	daddr.s_addr=ip_h->daddr;
	strcpy(info->dest_ip,inet_ntoa(daddr));
	info->protocol=ip_h->protocol;
	/*analysis tcp header*/
	struct tcphdr *tcp_h;
	tcp_h=(struct tcphdr*)(data->packet_data+sizeof(struct ether_header)+sizeof(struct iphdr));
	info->source_port=ntohs(tcp_h->source);
	info->dest_port=ntohs(tcp_h->dest);
	/*analysis packet header*/
	info->packet_len=data->packet_h->len;
	info->receive_time=data->packet_h->ts.tv_sec;
	/*return data*/
	return info;	
}
void info_print(struct packet_info *data)
{
	printf("Src:%s,",data->source_ip);
	printf("Dst:%s,",data->dest_ip);
	printf("Src Port:%d,",data->source_port);
	printf("Dst Port:%d,",data->dest_port);
	printf("Protocol:%d,",data->protocol);
	printf("Len:%d,",data->packet_len);
	char *time=format(data->receive_time);
	if(time!=NULL)
	{
		printf("Rcv Time:%s\n",format(data->receive_time));
		free(time);
	}
}
char *format(time_t rtime)
{
	struct tm *ptime=localtime(&rtime);
	char ftime[20];
	strftime(ftime,sizeof(ftime),"%Y-%m-%d %H:%M:%S",ptime);
	char *time=NULL;
	time=(char *)malloc(sizeof(char));
	if(time==NULL)
	{
		printf("memory allocation failed!\n");
		return NULL;
	}
	strcpy(time,ftime);
	return time;	
}
void err_sys(char *info,char *e)
{
	if(e==NULL)
		printf("%s\n",info);
	else
		printf("%s %s\n",info,e);
}
