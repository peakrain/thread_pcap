#include<stdlib.h>
#include<pcap.h>
int main()
{
	char ebuf[PCAP_ERRBUF_SIZE];
	char *device=pcap_lookupdev(ebuf);
	if(!device)
		printf("%s\n",ebuf);
	pcap_t *p=pcap_open_live(device,65535,1,0,ebuf);
	if(!p)
		printf("%s\n",ebuf);
	struct pcap_pkthdr *p_h;
	const u_char *packet;
	int err=0;
	while(err!=1)
		err=pcap_next_ex(p,&p_h,&packet); 
	if(err==1)
		printf("get a packet!\n");
	return 0;
}
