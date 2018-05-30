#ifndef _thread_h
#define _thread_h
/*header files*/
#include<pthread.h>
/*functions*/
void *packet_recevice(void *arg);
void *packet_analysis(void *arg);
void *packet_printout(void *arg);

#endif
