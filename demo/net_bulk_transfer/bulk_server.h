
#ifndef NETDEMO_SERVER
#define NETDEMO_SERVER

#include "network_system.h"
#include "bulk_main.h"

class Server : public NetworkSystem {
public:		
	Server( const char* trace_file_name = NULL ) : NetworkSystem( trace_file_name ) { }

	// Networking functions
	void Start ( bool tcp_only );
	int Run ( );		
	void Close ( );
	int Process ( Event& e );
	static int NetEventCallback ( Event& e, void* this_ptr );	

	// Demo app protocol
	void ReceiveBulkPkt ( Event& e );
	int InitBuf ( char* buf, const int size );
	double GetUpTime ( );

private:
	TimeX m_startTime;
	int m_pktSize;
	pkt_struct m_rxPkt;
	pkt_struct m_refPkt;
	FILE* m_flowTrace;
};

#endif 
