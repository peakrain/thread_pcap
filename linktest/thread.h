#ifndef _thread_h
#define _thread_h

#include"packet.h"
#include<pthread.h>

pcap_t *handle;
struct packet *packet_data;
struct packet_info *info;
pthread_mutex_t r_mutex;
pthread_mutex_t p_mutex;
pthread_cond_t r_cond;
pthread_cond_t ra_cond;
pthread_cond_t ap_cond;
pthread_cond_t p_cond;

void *packet_receive(void *arg);
void *packet_analysis(void *arg);
void *packet_printout(void *arg);
void init_lock();
void destroy_lock();
#endif
