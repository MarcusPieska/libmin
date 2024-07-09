
#ifdef _WIN32
  #include <conio.h>
#endif

#ifdef __linux__
  #include <stdio.h>
  #include <sys/ioctl.h>
  #include <termios.h>
  #include <sys/stat.h>
  
  int _kbhit () {
    static const int STDIN = 0;
    static bool kbinit = false;
    if ( !kbinit) {
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

#include <mutex>

#include "netdemo_client.h"

#define ENABLE_SSL

// #define FLOW_FLUSH

FILE* setup_trace ( const char* trace_name ) {
  FILE* trace_ptr;
  trace_ptr = fopen (trace_name, "w");
  //chmod (trace_name, S_IRWXO);
  return trace_ptr;
}

int NDClient::InitBuf  ( char* buf, const int size ) {
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

int NDClient::NetEventCallback ( Event& e, void* this_pointer ) {
    NDClient* self = static_cast<NDClient*>( this_pointer );
    return self->Process ( e );
}

double NDClient::GetUpTime ( ) 
{
	TimeX current_time;
	current_time.SetTimeNSec ( );
	return current_time.GetElapsedSec ( m_startTime );
}

void NDClient::Start ( str srv_addr )
{
	mSrvAddr = srv_addr;

	m_startTime.SetTimeNSec ( );
	m_flowTrace = setup_trace ( "../tcp-app-tx-flow" );
	m_pktSize = InitBuf ( m_txPkt.buf, PKT_SIZE );
	m_txPkt.seq_nr = 1;
	m_pktLimit = 100*1000;

	if ( 0 ) {
		std::cout << netSetSecurityLevel ( NET_SECURITY_PLAIN_TCP ) << std::endl;
		std::cout << netSetReconnectLimit ( 10 ) << std::endl;
		std::cout << netSetReconnectInterval ( 500 ) << std::endl;
	} else {
		std::cout << netSetSecurityLevel ( NET_SECURITY_PLAIN_TCP | NET_SECURITY_OPENSSL ) << std::endl;
		std::cout << netSetReconnectLimit ( 10 ) << std::endl;
		std::cout << netSetReconnectInterval ( 500 ) << std::endl;
		std::cout << netSetPathToPublicKey ( "/home/w/Downloads/libmin/src/assets/server-client.pem" ) << std::endl;
	}
	
	// start timer
	m_currtime.SetTimeNSec ( );	
	m_lasttime = m_currtime;
	srand ( m_currtime.GetMSec ( ) );

	// start networking
	netInitialize ( );
	
	bool show = true;
	netShowVerbose( show );
	netShowFlow ( show );
	
	// start client on random port
	int cli_port = 10000 + rand ( ) % 9000;
	netClientStart ( cli_port, srv_addr );
	netSetUserCallback ( &NetEventCallback );
	
	netPrintf ( PRINT_VERBOSE, "App. Client IP: %s", getIPStr ( getHostIP() ).c_str() );	

	// not yet connected (see Run func)
	m_sock = NET_NOT_CONNECTED; 
}


void NDClient::Reconnect ()
{   
	// reconnect to server
	std::string serverName = "localhost";  // 192.168.1.78
	int serverPort = 16101;
      
	netPrintf ( PRINT_VERBOSE, "App. Connecting ..." );
	m_sock = netClientConnectToServer ( mSrvAddr, serverPort, false );	
}

void NDClient::Close ()
{
	netCloseConnection ( m_sock );
}

int NDClient::Process ( Event& e )
{
	std::string line;
	eventStr_t sys = e.getTarget ();

	// Check for net error events
	if ( sys == 'net ' && e.getName()=='nerr' ) {
		// enable netVerbose(true) for detailed messages.
		// application can gracefully handle specific net error codes here..		
		int code = e.getInt ();

		return 0;
	}
	
	e.startRead ( ); // Process Network events
	switch ( e.getName ( ) ) {
	case 'sOkT': {
		// Connection complete. server accepted OK.
		int srv_sock = e.getInt ( ); // Server sock
		int cli_sock = e.getInt ( ); // Local socket 
		netPrintf ( PRINT_VERBOSE, "App. Connected to: %s, %d", getSock( cli_sock )->dest.name.c_str ( ), srv_sock );

		return 1;
	  //case 'sOkT': {
	} break;	
	};

	// Process Application events
	switch ( e.getName ( ) ) {
	case 'sRst': { // Server send back the words
		std::string words = e.getStr ( );
		netPrintf ( PRINT_VERBOSE, "App. Result from server: %s", words.c_str ( ) );
		return 1;
		} break;
	case 'sFIN': { // Server shutdown unexpectedly
		netPrintf ( PRINT_VERBOSE, "App. Server disconnected" );
		return 1;
	  } break;
	};

	netPrintf ( PRINT_VERBOSE, "App. Unhandled message: %s", e.getNameStr ( ).c_str ( ) );
	return 0;
}


int NDClient::Run ()
{
	m_currtime.SetTimeNSec();	
	float elapsed_sec = m_currtime.GetElapsedSec ( m_lasttime );
	if ( elapsed_sec >= 0.5 ) {
		m_lasttime = m_currtime;
		if ( netIsConnectComplete ( m_sock ) ) {	
			m_hasConnected = true;		
			SendPacket ( );
		} else if ( ! m_hasConnected ) {
			Reconnect ( ); // If disconnected, try and reconnect
			m_hasConnected = true;	
		}
	}
	return netProcessQueue ();
}


void NDClient::SendPacket ( )
{	
	int srv_sock = getServerSock ( m_sock );
	if ( srv_sock == -1 ) {
		return;
	}
	bool outcome = true;
	std::cout << "#==> New burst <========================================================#" << std::endl;
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
	std::cout << "#==> Burst end <========================================================#" << std::endl;
}


str get_addr( int argc, char **argv ) 
{
	str addr = "127.0.0.1";
	for ( int i = 1; i < argc - 1; ++i ) {
		str arg = argv[ i ];
		if ( arg == "--addr" || arg == "-a" ) {
			addr = argv[ ++i ]; 
		} 
	}
	return addr;
}

int main ( int argc, char* argv[] )
{
	NDClient cli ( "../trace-func-call-client" );
	cli.Start ( get_addr ( argc, argv ) );
	cli.m_hasConnected = false;
	while ( !_kbhit ( ) ) {		
		cli.Run ( );
	}
	cli.Close ( );  
    return 1;
}
