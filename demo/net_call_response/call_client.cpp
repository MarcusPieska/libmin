
#include "call_client.h"

//#include <openssl/err.h>
//#include <openssl/md5.h>
//#include <openssl/ssl.h>
//#include <openssl/x509v3.h>
#include <mutex>

#define ENABLE_SSL

int Client::NetEventCallback (Event& e, void* this_pointer) {
    Client* self = static_cast<Client*>(this_pointer);
    return self->Process ( e );
}


void Client::Start (std::string srv_addr)
{
	mSrvAddr = srv_addr;
	bool bDebug = false;
	bool bVerbose = true;

	std::cout << netSetSecurityLevel(NET_SECURITY_PLAIN_TCP | NET_SECURITY_OPENSSL) << std::endl;	
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
	
	dbgprintf ( "App. Client IP: %s\n", getIPStr ( getHostIP() ).c_str() );	

	// not yet connected (see Run func)
	mSock = NET_NOT_CONNECTED; 
}

void Client::Reconnect ()
{   
	// reconnect to server
	std::string serverName = "localhost";  // 192.168.1.78
	int serverPort = 16101;
    
	dbgprintf ( "App. Connecting..\n" );	
	mSock = netClientConnectToServer ( mSrvAddr, serverPort, false );	
}

void Client::Close ()
{
	netCloseConnection ( mSock );
}


int Client::Process ( Event& e )
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
		dbgprintf( "App. Connected to server: %s, %d\n", getSock( cli_sock )->dest.name.c_str ( ), srv_sock );

		return 1;
	  //case 'sOkT': {
	} break;	
	};

	// Process Application events
	switch (e.getName()) {
	case 'sRst': {
		// server send back the words
		std::string words = e.getStr ();
		dbgprintf ("App. Result from server: %s\n", words.c_str() );
		return 1;
		} break;
	case 'sFIN': {
		// server shutdown unexpectedly
		dbgprintf ("App. Server disconnected.\n" );
		return 1;
	  } break;
	};

	dbgprintf ( "App. Unhandled message: %s\n", e.getNameStr().c_str() );
	return 0;
}

int Client::Run ()
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


void Client::RequestWords (int num)
{	
	// demo application protocol:
	//
	// cRqs - request the words for a number (c=msg from client)
	// sRst - here is the result containing the words (s=msg from server)

	// create cRqs app event
	int srv_sock = getServerSock ( mSock );
	
	if ( srv_sock >= 0) {
		Event e = new_event ( 120, 'app ', 'cRqs', 0, getNetPool ( ) );	
		e.attachInt ( srv_sock );		// must always tell server which socket 
		e.attachInt ( mSeq++ ); 		
		e.attachInt ( num );		   // payload		

		netSend ( e );		// send to server
	}
}

