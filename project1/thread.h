#ifndef _thread_h
#define _thread_h

#include"packet.h"
#include<pthread.h>

pcap_t *handle;

void *packet_receive(void *arg);
void *packet_printout(void *arg);
#endif
