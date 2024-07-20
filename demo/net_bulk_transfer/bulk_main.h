
#ifndef NETDEMO_MAIN
#define NETDEMO_MAIN

#include "network_system.h"

#define BUF_SIZE 1400
#define PKT_SIZE 1200 

typedef struct pkt_struct {
	int seq_nr;
	char buf[ BUF_SIZE ];
} pkt_struct; 

#endif
