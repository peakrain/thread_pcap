#include"thread.h"
#include<malloc.h>
void *packet_receive(void *arg)
{
	printf("start to get packet...\n");
	handle=gethandle();
	if(handle==NULL)
	{
		printf("get handle failed!\n");
		return;
	}
	while(1)
	{
		pthread_mutex_lock(&r_mutex);
		while(packet_data!=NULL)
		{
			printf("the packet hasn't be analyzed, wait...\n ");
			pthread_cond_wait(&r_cond,&r_mutex);
		}
		while(packet_data==NULL)
			packet_data=receive(handle);
		printf("get a packet\n");	
		pthread_cond_signal(&ra_cond);
		pthread_mutex_unlock(&r_mutex);
	}
	pcap_close(handle);
	return (void*)1;
	
}
void *packet_analysis(void *arg)
{
	while(1)
	{
		pthread_mutex_lock(&r_mutex);
		while(packet_data==NULL)
		{
			printf("no packet can't be analyzed,waint...\n");
			pthread_cond_wait(&ra_cond,&r_mutex);
		}
		pthread_mutex_lock(&p_mutex);
		while(info!=NULL)
		{
			printf("information hasn't print,wait...\n");
			pthread_cond_wait(&ap_cond,&p_mutex);
		}
		printf("analyze packet...\n");
		info=analysis(packet_data);
		packet_data==NULL;
		pthread_cond_signal(&r_cond);
		pthread_cond_signal(&p_cond);
		pthread_mutex_unlock(&p_mutex);
		pthread_mutex_unlock(&r_mutex);
	}	
	return (void*)2;
}
void *packet_printout(void *arg)
{
	while(1)
	{
		pthread_mutex_lock(&p_mutex);
		while(info==NULL)
		{
			printf("no information can't print,waint...\n");
			pthread_cond_wait(&p_cond,&p_mutex);
		}
		printf("print packet information...\n");
		info_print(info);
		info=NULL;
		pthread_cond_signal(&ap_cond);
		pthread_mutex_unlock(&p_mutex);
	}
	return (void*)3;
}
void init_lock()
{
	int err;
	err=pthread_mutex_init(&r_mutex,NULL);
	if(err!=0)
		printf("can't init r_lock!\n");
	err=pthread_mutex_init(&p_mutex,NULL);
	if(err!=0)
		printf("can't init p_lock!\n");
	err=pthread_cond_init(&r_cond,NULL);
	if(err!=0)
		printf("can't init r_cond!\n");
	err=pthread_cond_init(&ra_cond,NULL);
	if(err!=0)
		printf("can't init a_cond!\n");
	err=pthread_cond_init(&ap_cond,NULL);
	if(err!=0)
		printf("can't init a_cond!\n");
	err=pthread_cond_init(&p_cond,NULL);
	if(err!=0)
		printf("can't init p_cond!\n");
} 
void destroy_lock()
{
	pthread_mutex_destroy(&r_mutex);
	pthread_mutex_destroy(&p_mutex);
	pthread_cond_destroy(&r_cond);
	pthread_cond_destroy(&ra_cond);
	pthread_cond_destroy(&ap_cond);
	pthread_cond_destroy(&p_cond);
}
void init()
{
	handle=NULL;
	packet_data=NULL;
	info=NULL;
	init_lock();
}
void clean()
{
	free(handle);
	free(packet_data);
	free(info);
	destroy_lock;
}
