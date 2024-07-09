
#ifndef NETDEMO_CLIENT
#define NETDEMO_CLIENT

#include "network_system.h"

#define BUF_SIZE 1400
#define PKT_SIZE 1200 

typedef struct pkt_struct {
	int seq_nr;
	char buf[ BUF_SIZE ];
} pkt_struct; 

class NDClient : public NetworkSystem {
public:		
	NDClient( const char* trace_file_name = NULL ) : NetworkSystem( trace_file_name ) { }

	void Start ( str srv_addr );
	void Reconnect ( );
	void Close ( );		
	int Run ( );				
	int Process ( Event& e );
	static int NetEventCallback ( Event& e, void* this_ptr );			

	int m_hasConnected;

private:
	int InitBuf ( char* buf, const int size );
	void SendPacket ( );
	double GetUpTime ( );
	
	TimeX m_startTime;
	int m_sock;
	int m_seqNr;
	int m_pktSize;
	int m_pktLimit;
	pkt_struct m_txPkt;
	str mSrvAddr;
	TimeX m_currtime;
	TimeX m_lasttime;
	FILE* m_flowTrace;
};

#endif
