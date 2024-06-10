
#ifdef _WIN32
  #include <conio.h>
#endif

#ifdef __linux__
  #include <stdio.h>
  #include <sys/ioctl.h>
  #include <termios.h>
  
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

//#include <openssl/err.h>
//#include <openssl/md5.h>
//#include <openssl/ssl.h>
//#include <openssl/x509v3.h>
#include <mutex>

#include "netdemo_client.h"

 #define ENABLE_SSL


int NDClient::NetEventCallback (Event& e, void* this_pointer) {
    NDClient* self = static_cast<NDClient*>(this_pointer);
    return self->Process ( e );
}


void NDClient::Start (std::string srv_addr)
{
	mSrvAddr = srv_addr;
	bool bDebug = false;
	bool bVerbose = true;

	std::cout << netSetSecurityLevel ( 1 ) << std::endl;
	std::cout << netAllowFallbackToPlainTCP ( true ) << std::endl;
	std::cout << netSetReconnectLimit ( 10 ) << std::endl;
	std::cout << netSetReconnectInterval ( 500 ) << std::endl;
	std::cout << netSetPathToPublicKey ( "server_pubkey.pem" ) << std::endl;

	// start timer
	m_currtime.SetTimeNSec();	
	m_lasttime = m_currtime;
	mSeq = 0;
	srand ( m_currtime.GetMSec() );

	// start networking
	netInitialize();
	netVerbose( bVerbose );

	// start client on random port
	int cli_port = 10000 + rand() % 9000;
	netClientStart ( cli_port, srv_addr );
	netSetUserCallback ( &NetEventCallback );
	
	dbgprintf ( "Client IP: %s\n", getIPStr ( getHostIP() ).c_str() );	

	// not yet connected (see Run func)
	mSock = NET_NOT_CONNECTED; 
}


void NDClient::Reconnect ()
{   
	// reconnect to server
	std::string serverName = "localhost";  // 192.168.1.78
	int serverPort = 16101;
    
    
	dbgprintf ( "Connecting..\n" );	
	mSock = netClientConnectToServer ( mSrvAddr, serverPort, false );	

	std::cout << "=========================================" << std::endl;

	//netList (true);
}

void NDClient::Close ()
{
	netCloseConnection ( mSock );
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
	// Process Network events
	e.startRead ();
	switch (e.getName()) {
	case 'sOkT': {
		// Connection complete. server accepted OK.
		int srv_sock = e.getInt();		// server sock
		int cli_sock = e.getInt();		// local socket
		dbgprintf( "  Connected to server: %s, %d\n", getSock( cli_sock )->dest.name.c_str ( ), srv_sock );

		return 1;
	  //case 'sOkT': {
	} break;	
	};

	// Process Application events
	switch (e.getName()) {
	case 'sRst': {
		// server send back the words
		std::string words = e.getStr ();
		dbgprintf ("  Result from server: %s\n", words.c_str() );
		return 1;
		} break;
	case 'sFIN': {
		// server shutdown unexpectedly
		dbgprintf ("  Server disconnected.\n" );
		return 1;
	  } break;
	};

	dbgprintf ( "   Unhandled message: %s\n", e.getNameStr().c_str() );
	return 0;
}

int NDClient::Run ()
{
	m_currtime.SetTimeNSec();	

	// demo app - request the words for a random number every 2 secs
	//
	float elapsed_sec = m_currtime.GetElapsedSec ( m_lasttime );
	if ( elapsed_sec >= 0.5 ) {
		m_lasttime = m_currtime;
		if ( netIsConnectComplete ( mSock ) ) {	
			mHasConnected = true;		
			int rnum = rand ( ) % 10000;
			RequestWords ( rnum );
			dbgprintf ( "  Requested words for: %d\n", rnum ); // If connected, make request
		} else if ( ! mHasConnected ) {
			Reconnect ( ); // If disconnected, try and reconnect
			mHasConnected = true;	
		}
	}

	// process event queue
	return netProcessQueue ();
}


void NDClient::RequestWords (int num)
{	
	// demo application protocol:
	//
	// cRqs - request the words for a number (c=msg from client)
	// sRst - here is the result containing the words (s=msg from server)

	// create cRqs app event
	int srv_sock = getServerSock ( mSock );
	if ( srv_sock != -1) {
		Event e = new_event ( 120, 'app ', 'cRqs', 0, getNetPool ( ) );	
		e.attachInt ( srv_sock );  // must always tell server which socket 
		e.attachInt ( mSeq++ ); 
		e.attachStr ( "==========" );
		e.attachInt ( num );		   // payload
		e.attachStr ( "==========" );

		netSend ( e );		// send to server
	}
}

std::string get_addr(int argc, char **argv) 
{
	std::string addr = "127.0.0.1";
	for (int i = 1; i < argc - 1; ++i) {
		std::string arg = argv[i];
		if (arg == "--addr" || arg == "-a") {
			addr = argv[++i]; 
		} 
	}
	return addr;
}

int main (int argc, char* argv[])
{
	//----- network performance profiling	
	// - libmin must be built with PROFILE_NET and USE_NVTX
	// - for CPU netRecv will show >1/ms due to perf printfs, use nvtx markers for better analysis
	// - for NVTX the nvToolsExt64_1.dll must be present
	// - enable this line to see profiling:
	// PERF_INIT ( 64, true, true, true, 0, "" );	

	addSearchPath ( ASSET_PATH );

	NDClient cli ( "../trace-func-call-client" );

	cli.Start (get_addr(argc, argv));
	cli.mHasConnected = false;
	while ( !_kbhit() ) {		

		cli.Run ();
	}

	cli.Close ();  
 
    return 1;
}
