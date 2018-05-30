#include<pcap.h>
#include<stdlib.h>
pcap_t *getdriver()
{
	char ebuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *driver=NULL;
	driver=(pcap_t *)malloc(sizeof(pcap_t*));
	if(driver!=NULL)
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
			driver=p;
			return driver;
		}
	}
	else
	{
		printf("Memory allocation failed!\n");
		return NULL;
	}
}
	
