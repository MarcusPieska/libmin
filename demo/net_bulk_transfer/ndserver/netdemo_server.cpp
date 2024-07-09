
#ifdef _WIN32
  #include <conio.h>
#endif

#ifdef __linux__
  #include <stdio.h>
  #include <sys/ioctl.h>
  #include <termios.h>
  #include <sys/stat.h>

  int _kbhit() {
    static const int STDIN = 0;
    static bool kbinit = false;
    if (!kbinit) {
      termios term;
      tcgetattr(STDIN, &term);
      term.c_lflag &= ~ICANON;
      tcsetattr(STDIN, TCSANOW, &term);
      setbuf(stdin, NULL);
      kbinit=true;
    }
    int bytes;
    ioctl(STDIN, FIONREAD, &bytes);
    return bytes;
  }
#endif   

#include "netdemo_server.h"

#define FLOW_FLUSH

FILE* setup_trace ( const char* trace_name ) {
  FILE* trace_ptr;
  trace_ptr = fopen (trace_name, "w");
  //chmod (trace_name, S_IRWXO);
  return trace_ptr;
}

int NDServer::InitBuf ( char* buf, const int size ) {
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

int NDServer::NetEventCallback (Event& e, void* this_pointer) {
    NDServer* self = static_cast<NDServer*>(this_pointer);
    return self->Process ( e );
}


double NDServer::GetUpTime ( ) 
{
	TimeX current_time;
	current_time.SetTimeNSec ( );
	return current_time.GetElapsedSec ( m_startTime );
}


void NDServer::Start ()
{
	m_startTime.SetTimeNSec ( );
	m_flowTrace = setup_trace ( "../tcp-app-rx-flow" );
	m_pktSize = InitBuf ( m_refPkt.buf, PKT_SIZE ) + sizeof ( int );
	m_refPkt.seq_nr = 1;

	if ( 0 ) {
		std::cout << netSetSecurityLevel ( NET_SECURITY_PLAIN_TCP ) << std::endl;
		std::cout << netSetReconnectLimit ( 10 ) << std::endl;
	} else {
		std::cout << netSetSecurityLevel ( NET_SECURITY_PLAIN_TCP | NET_SECURITY_OPENSSL ) << std::endl;
		std::cout << netSetReconnectLimit ( 10 ) << std::endl;
		std::cout << netSetPathToPublicKey ( "/home/w/Downloads/libmin/src/assets/server-server.pem" ) << std::endl;
		std::cout << netSetPathToPrivateKey ( "/home/w/Downloads/libmin/src/assets/server.key" ) << std::endl;
		std::cout << netSetPathToCertDir ( "/etc/ssl/certs" ) << std::endl;
		std::cout << netSetPathToCertFile ( "/etc/ssl/certs/ca-certificates.crt" ) << std::endl;
	}


	// start networking
	netInitialize();

	bool show = true;
	netShowVerbose( show );
  netShowFlow ( show );
	
	// start server listening
	int srv_port = 16101;
	netServerStart ( srv_port );
	netSetUserCallback ( &NetEventCallback );
	
	netPrintf ( PRINT_VERBOSE, "Server IP: %s", getIPStr ( getHostIP ( ) ).c_str ( ) );	
	netPrintf ( PRINT_VERBOSE, "Listening on %d ...", srv_port );
}

void NDServer::Close ( )
{
}


int NDServer::Run ( )
{
	return netProcessQueue ();
}


int NDServer::Process ( Event& e )
{
	int sock;
	str line;
	eventStr_t sys = e.getTarget ( );

	if ( sys == 'net ' && e.getName ( ) == 'nerr' ) { // Check for net error events
		// enable netVerbose(true) for detailed messages.
		// application can gracefully handle specific net error codes here..		
		int code = e.getInt ( );		
		if ( code == NET_DISCONNECTED ) {
			netPrintf ( PRINT_ERROR_HS, "Connection to client closed unexpectedly" );
		}		
		return 0;
	}


	e.startRead ( ); // Process Network events
	switch ( e.getName ( ) ) {
	case 'sOkT': // Connection to client complete. (telling myself)
		sock = e.getInt ( ); // server sock		
		netPrintf ( PRINT_VERBOSE_HS, "Connected to client: #%d", sock );
		return 1;
		break;
	case 'cFIN': // Client closed connection
		sock = e.getInt ( );
		netPrintf ( PRINT_VERBOSE_HS, "Disconnected client: #%d", sock );
		return 1;
		break;		
	};


	switch ( e.getName ( ) ) { // Process Application events
	case 'cRqs': 
		int pktSize = e.getInt ( ) + sizeof( int );
		e.getBuf ( (char*) &m_rxPkt, pktSize );
		int outcome = memcmp ( &m_refPkt, &m_rxPkt, pktSize );
		m_refPkt.seq_nr++;
		fprintf ( m_flowTrace, "%.3f:%u:%u:o:%d\n", GetUpTime ( ), m_rxPkt.seq_nr, pktSize, outcome );
		#ifdef FLOW_FLUSH
			fflush ( m_flowTrace );
		#endif	
		if ( outcome != 0 ) {
			std::cout << "\n=========================================== 1\n" << std::endl;
			std::cout.write( m_refPkt.buf, pktSize );
			std::cout << "\n===========================================\n" << std::endl;
			std::cin.get();
		}
		netPrintf ( PRINT_FLOW, "Received event: %d, SEQ-%d", e.getSerializedLength(), m_rxPkt.seq_nr );
		return 1;
		break;
	};

	netPrintf ( PRINT_ERROR, "Unhandled message: %s", e.getNameStr( ).c_str( ) );
	return 0;
}

int main ( int argc, char* argv [ ] )
{
	NDServer srv ( "../trace-func-call-server" );
	
  srv.Start ( );

	while ( !_kbhit ( ) ) {
		srv.Run ( );
	}
	srv.Close ( );  
	return 1;
}

