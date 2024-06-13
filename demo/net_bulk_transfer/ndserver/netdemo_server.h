
#ifndef NETDEMO_SERVER
#define NETDEMO_SERVER

#include "network_system.h"

#define BUF_SIZE 1400
#define PKT_SIZE 1200 

typedef struct pkt_struct {
	int seq_nr;
	char buf[ BUF_SIZE ];
} pkt_struct; 

class NDServer : public NetworkSystem {
public:
	NDServer( const char* trace_file_name = NULL ) : NetworkSystem( trace_file_name ) { }
	
	void Start ();
	int Run ();		
	void Close ();
	int Process (Event& e);
	static int NetEventCallback ( Event& e, void* this_ptr );	

private:
	double GetUpTime ( );
	
	TimeX m_startTime;
	int m_pktSize;
	pkt_struct m_rxPkt;
	pkt_struct m_refPkt;
	FILE* m_flowTrace;
};

#endif
