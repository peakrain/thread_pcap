#include"main.h"
int main()
{
	
	pcap_t *p=getdriver();
	struct pcap_pkthdr *packet_h;
	const u_char *packet;
	int count=0;
	while(count<10)
	{
		struct packet *pack=receive(p);
		if(pack==NULL)
			printf("Error!\n");
		else
		{
			count++;
			printf("get packet %d\n",count);
			struct print_data *data=analysis(pack);
			print(data);	
		}
	}
	
	pcap_close(p);
	return 0;

}
