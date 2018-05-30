#include<pcap.h>
#include<stdlib.h>
pcap_t *gethandle()
{
	char ebuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *handle=NULL;
	handle=(pcap_t *)malloc(sizeof(pcap_t*));
	if(handle!=NULL)
	{
		device=pcap_lookupdev(ebuf);
		if(!device)
		{
			printf("Error:%s\n",ebuf);
			return NULL;
		}
		else
			printf("Device:%s\n",device);
		pcap_t *p=pcap_open_live(device,65535,1,0,ebuf);
		if(!p)
		{
			printf("Error:%s\n",ebuf);
			return NULL;
		}
		else
		{
			handle=p;
			return handle;
		}
	}
	else
	{
		printf("Memory allocation failed!\n");
		return NULL;
	}
}
	
