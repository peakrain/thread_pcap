#ifndef _main_h
#define _main_h

#include<stdio.h>
#include<pcap.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<time.h>
struct packet{
	struct pcap_pkthdr *packet_h;
	const u_char *packet;
};
struct print_data{
	char *sourceip;
	char *destip;
	int sourceport;
	int destport;
	int protocol;
	int packet_len;
	time_t time;	
};
#endif