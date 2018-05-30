#include"main.h"
#include<time.h>
char *getformat_time(time_t rtime)
{
	struct tm *ptime=localtime(&rtime);
	char time[128];
	strftime(time,sizeof(time),"%Y-%m-%d %H:%M:%S",ptime);
	char *result=(char *)malloc(sizeof(char));
	if(result==NULL)
	{
		printf("Memory allocation failed!\n");
		return NULL;
	}
	strcpy(result,time);
	return result;
}
void print(struct print_data *data)
{
	printf("sourceip:%s ",data->sourceip);
	printf("destip:%s ",data->destip);
	printf("sourceport:%d ",data->sourceport);
	printf("destport:%d ",data->destport);
	printf("protocol:%d ",data->protocol);
	printf("packet len:%d ",data->packet_len);
	printf("receive time:%s\n",getformat_time(data->time));
}

