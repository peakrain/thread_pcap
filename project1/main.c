#include"main.h"
int main()
{
	int err;
	err=pthread_create(&receive_id,NULL,packet_receive,NULL);
	if(err!=0)
		printf("thread packet_receive can't be create!\n");
	err=pthread_create(&print_id,NULL,packet_printout,NULL);
	if(err!=0)
		printf("thread packet_printout can't be create!\n");
	pthread_join(receive_id,NULL);
	pthread_join(print_id,NULL);
	return 0;
}
