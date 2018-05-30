#include"main.h"
#include<malloc.h>
pcap_t *driver;
int main()
{
	
	pcap_t *p=gethandle();
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
			free(data);	
		}
	}
	
	pcap_close(p);
	return 0;

}
