
#include "bulk_client.h"

#define ENABLE_SSL

int Client::NetEventCallback ( Event& e, void* this_pointer ) {
    Client* self = static_cast<Client*>( this_pointer );
    return self->Process ( e );
}

int Client::InitBuf  ( char* buf, const int size ) {
  for ( int i = 0, c = 65; i < size; i++ ) {
    if ( i == size - 1 ) {
      memset ( buf + i, '*', 1 );
      memset ( buf + i + 1, '\0', 1 );
    }
    else if ( i % 50 == 49 ) {
      memset ( buf + i, '\n', 1 );
      c++;
    }
    else if ( i % 10 == 9 ) {
      memset ( buf + i, c, 1 );
    }
    else {
      memset ( buf + i, '-', 1 );
    }
  }
  netPrintf ( PRINT_VERBOSE, "*** Packet content:\n\n%s\n*** Size is %luB \n", buf, strlen ( buf ) );
  return (int)strlen ( buf );
}

double Client::GetUpTime ( ) 
{
	TimeX current_time;
	current_time.SetTimeNSec ( );
	return current_time.GetElapsedSec ( m_startTime );
}

void Client::Start ( std::string srv_addr, bool tcp_only )
{
	m_srvAddr = srv_addr;
	m_startTime.SetTimeNSec ( );
	m_flowTrace = fopen ( "../tcp-app-tx-flow", "w" );
	m_pktSize = InitBuf ( m_txPkt.buf, PKT_SIZE );
	m_txPkt.seq_nr = 1;
	m_pktLimit = 100*1000;
	m_hasConnected = false;
 
	if ( tcp_only ) {
		dbgprintf ( "Using TCP only \n" );
		std::cout << netSetSecurityLevel ( NET_SECURITY_PLAIN_TCP ) << std::endl;	
		std::cout << netSetReconnectLimit ( 10 ) << std::endl;
		std::cout << netSetReconnectInterval ( 500 ) << std::endl;
	} else {
		dbgprintf ( "Using TCP and OpenSSL \n" );
		std::cout << netSetSecurityLevel ( NET_SECURITY_PLAIN_TCP | NET_SECURITY_OPENSSL ) << std::endl;	
		std::cout << netSetReconnectLimit ( 10 ) << std::endl;
		std::cout << netSetReconnectInterval ( 500 ) << std::endl;
		std::cout << netSetPathToPublicKey ( "server_pubkey.pem" ) << std::endl;
	}

	m_currtime.SetTimeNSec ( ); // Start timer
	m_lasttime = m_currtime;
	m_seq = 0;
	srand ( m_currtime.GetMSec ( ) );
	netInitialize ( ); 
	netShowFlow( false );
	netShowVerbose( true );
	int cli_port = 10000 + rand ( ) % 9000; 
	netClientStart ( cli_port, srv_addr );
	netSetUserCallback ( &NetEventCallback );
	m_sock = NET_NOT_CONNECTED; // Not yet connected (see Run func)
	
	dbgprintf ( "App. Client IP: %s\n", getIPStr ( getHostIP ( ) ).c_str ( ) );	
}

void Client::Reconnect ( )
{   
	dbgprintf ( "App. Connecting..\n" );	
	m_sock = netClientConnectToServer ( m_srvAddr, 16101, false ); // Reconnect to server	 
}

void Client::Close ( )
{
	netCloseConnection ( m_sock );
}

int Client::Process ( Event& e )
{
	std::string line;
	eventStr_t sys = e.getTarget ( );
	if ( sys == 'net ' && e.getName ( ) =='nerr' ) { // Check for net error events
		// Enable netShowVerbose ( true ) for detailed messages; handle specific net error codes here..		
		int code = e.getInt ( );
		return 0;
	}
	e.startRead ( ); // Process Network events
	switch ( e.getName ( ) ) {
		case 'sOkT': { // Connection complete. server accepted OK.
			int srv_sock = e.getInt ( ); 
			int cli_sock = e.getInt ( ); 
			dbgprintf( "App. Connected to server: %s, %d\n", getSock( cli_sock )->dest.name.c_str ( ), srv_sock );
			return 1;
		} break;	
	};

	switch ( e.getName ( ) ) {
		case 'sRst': { // Process Application events, send back the words
			std::string words = e.getStr ( );
			dbgprintf ( "App. Result from server: %s\n", words.c_str ( ) );
			return 1;
		} 
		case 'sFIN': { // Server shutdown unexpectedly
			dbgprintf ( "App. Server disconnected.\n" );
			return 1;
		} 
	};
	dbgprintf ( "App. Unhandled message: %s\n", e.getNameStr ( ).c_str ( ) );
	return 0;
}

void Client::SendPackets ( )
{	
	int srv_sock = getServerSock ( m_sock );
	if ( srv_sock == -1 ) {
		return;
	}
	bool outcome = true;
	while ( outcome && m_txPkt.seq_nr < m_pktLimit ) {
		Event e = new_event ( m_pktSize + sizeof(int), 'app ', 'cRqs', 0, getNetPool ( ) );	
		e.attachInt ( m_pktSize );
		e.attachBuf ( (char*)&m_txPkt, m_pktSize + sizeof(int) );
		outcome = netSend ( e );
		if ( outcome ) {
			fprintf ( m_flowTrace, "%.3f:%u:%u\n", GetUpTime ( ), m_txPkt.seq_nr, m_pktSize );
			#ifdef FLOW_FLUSH
				fflush ( m_flowTrace );
			#endif	
			m_txPkt.seq_nr++;
		}
		printf ( "%d\n", m_txPkt.seq_nr );
	}
}

int Client::Run ( ) 
{
	m_currtime.SetTimeNSec ( );	
	float elapsed_sec = m_currtime.GetElapsedSec ( m_lasttime );
	if ( elapsed_sec >= 0.5 ) { // Demo app - request the words for a random number every 2 secs
		m_lasttime = m_currtime;
		if ( netIsConnectComplete ( m_sock ) ) {	
			m_hasConnected = true;		
			SendPackets ( );
		} else if ( ! m_hasConnected ) {
			Reconnect ( ); // If disconnected, try and reconnect
			m_hasConnected = true;	
		}
	}
	return netProcessQueue ( ); // Process event queue
}
