#include"main.h"
#include<malloc.h>
pcap_t *driver;
int main()
{
	
	handle=gethandle();
	int count=0;
	while(count<10)
	{
		packet_data=receive(handle);
		if(packet_data==NULL)
			printf("Error!\n");
		else
		{
			count++;
			printf("get packet %d\n",count);
			info=analysis(packet_data);
			info_print(info);
			free(info);	
		}
	}
	
	pcap_close(handle);
	return 0;

}
