#include"main.h"
#include<malloc.h>
int main()
{
	int err;
	init();	
	err=pthread_create(&receive_id,NULL,packet_receive,NULL);
	if(err!=0)
		printf("thread packet_receive can't be create!\n");
	err=pthread_create(&analysis_id,NULL,packet_analysis,NULL);
	if(err!=0)
		printf("thread packet_analysis can't be create!\n");
	err=pthread_create(&print_id,NULL,packet_printout,NULL);
	if(err!=0)
		printf("thread packet_printout can't be create!\n");
	pthread_join(receive_id,NULL);
	pthread_join(analysis_id,NULL);
	pthread_join(print_id,NULL);
	clean();
	return 0;
}
