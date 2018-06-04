#include"thread.h"
#include<malloc.h>
#include<unistd.h>
void *packet_receive(void *arg)
{
	printf("start to get packet...\n");
	handle=gethandle();
	if(handle==NULL)
	{
		printf("get handle failed!\n");
		return;
	}
	receive(handle);
	pcap_close(handle);
	return (void*)1;
	
}
void *packet_printout(void *arg)
{
	while(1)
	{
		info_print();
		sleep(1);
	}
	return (void*)3;
}
