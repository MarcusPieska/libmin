
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

FILE* setup_trace ( const char* trace_name ) {
  FILE* trace_ptr;
  trace_ptr = fopen (trace_name, "w");
  chmod (trace_name, S_IRWXO);
  return trace_ptr;
}

int init_buf ( char* buf, const int size ) {
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
  printf ( "*** Packet content:\n\n%s\n*** Size is %luB \n", buf, strlen ( buf ) );
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
	bool bDebug = true;
	bool bVerbose = true;
	m_startTime.SetTimeNSec ( );
	m_flowTrace = setup_trace ( "../tcp-app-rx-flow" );
	m_pktSize = init_buf ( m_refPkt.buf, PKT_SIZE ) + sizeof ( int );
	m_refPkt.seq_nr = 1;

	std::cout << netSetSecurityLevel ( NET_SECURITY_PLAIN_TCP | NET_SECURITY_OPENSSL ) << std::endl;
	std::cout << netSetReconnectLimit ( 10 ) << std::endl;
	std::cout << netSetPathToPublicKey ( "/home/w/Downloads/libmin/src/assets/server-server.pem" ) << std::endl;
	std::cout << netSetPathToPrivateKey ( "/home/w/Downloads/libmin/src/assets/server.key" ) << std::endl;
	std::cout << netSetPathToCertDir ( "/etc/ssl/certs" ) << std::endl;
	std::cout << netSetPathToCertFile ( "/etc/ssl/certs/ca-certificates.crt" ) << std::endl;

	// start networking
	netInitialize();
	netVerbose( bVerbose );
	
	// start server listening
	int srv_port = 16101;
	netServerStart ( srv_port );
	netSetUserCallback ( &NetEventCallback );
	
	dbgprintf ( "Server IP: %s\n", getIPStr ( getHostIP() ).c_str() );	
	dbgprintf ( "Listening on %d..\n", srv_port );
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
			dbgprintf ( "  Connection to client closed unexpectedly.\n" );
		}		
		return 0;
	}

	e.startRead ( ); // Process Network events
	switch ( e.getName ( ) ) {
	case 'sOkT': // Connection to client complete. (telling myself)
		sock = e.getInt ( ); // server sock		
		dbgprintf ( "  Connected to client: #%d\n", sock );
		return 1;
		break;
	case 'cFIN': // Client closed connection
		sock = e.getInt ( );
		dbgprintf ( "  Disconnected client: #%d\n", sock );
		return 1;
		break;		
	};

	switch ( e.getName ( ) ) { // Process Application events
	case 'cRqs': 
		e.getBuf ( (char*)&m_rxPkt, m_pktSize );
		int outcome = memcmp ( &m_refPkt, &m_rxPkt, m_pktSize );
		m_refPkt.seq_nr++;
		fprintf ( m_flowTrace, "%.3f:%u:%u:%d\n", GetUpTime ( ), m_rxPkt.seq_nr, m_pktSize, outcome );
		fflush ( m_flowTrace );
		if ( outcome != 0 ) {
			std::cout << m_rxPkt.buf << std::endl;
		}
		dbgprintf ( "Received packet: SEQ-%d \n", m_rxPkt.seq_nr );
		return 1;
		break;
	};

	dbgprintf ( "   Unhandled message: %s\n", e.getNameStr( ).c_str( ) );
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
