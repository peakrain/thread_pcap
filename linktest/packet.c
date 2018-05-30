#include"packet.h"
pcap_t *handle()
{
	char ebuf[PCAP_ERRBUF_SIZE];
	char *device;
	pacp_t *p,*handle=NULL;
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
	handle=(pacp_t *)malloc(sizeof(pcap_t *));
	if(handle==NULL)
	{
		err_sys("handle memory allocation failed!\n",NULL);
	}
	handle=p;
	return handle;
}
struct packet *receive(pacp_t *handle)
{
	struct packet *packet==NULL;
	packet=(struct packet*)malloc(sizeof(struct packet));
	if(packet==NULL)
	{
		err_sys("packet memory allocation failed!");
		return NULL;
	}
	struct pcap_pkthdr *p_h;
	const u_char *p;
	int err=0;
	err=pcap_next_ex(headle,&p_h,&p);
	if(err!=1)
	{
		err_sys("get packet failed!",strerr(err));
		free(packet);
		return NULL;
	}
	packet->packet_h=p_h;
	packet->packet_info=p;
	return packet;
}
struct packet_info *analysis(struct packet *data)
{
	struct packet_info *info=NULL;
	info=(struct packet_info*)malloc(sizeof(struct packet_info));
	if(info==NULL)
	{
		err_sys("info memory allocation failed!");
		return NULL;
	}
	/*analysis ip header*/
	struct iphdr *ip_h;
	struct in_addr addr;
	ip_h=(struct iphdr*)(data_info+size(struct ether_header));
	addr.s_addr=ip_h->saddr;
	strcpy(info->source_ip,inet_ntoa(addr));
	addr.s_addr=ip_h->daddr;
	strcpy(info->dest_ip,inet_ntoa(addr));
	info->protocol=ip_h->protocol;
	/*analysis tcp header*/
	struct tcphdr *tcp_h;
	tcp_h=(struct tcphdr*)(data->packet_info+sizeof(struct ether_header)+sizeof(struct iphdr));
	info->source_port=ntohs(tcp_h->source);
	info->dest_port=ntohs(tcp_h-dest);
	/*analysis packet header*/
	info->packt_len=data->packet_h->len;
	info->receive_time=data->packet_h->ts.tv.sec;
	/*return data*/
	return info;	
}
void err_sys(char *info,char *e)
{
	if(e==NULL)
		printf("%s\n",info);
	else
		printf("%s %s\n",info,e);
}
