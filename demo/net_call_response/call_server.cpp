

#include "call_server.h"

#include "network_system.h"

int Server::NetEventCallback (Event& e, void* this_pointer) {
    Server* self = static_cast<Server*>(this_pointer);
    return self->Process ( e );
}

void Server::Start ()
{
	bool bDebug = true;
	bool bVerbose = true;

	std::cout << netSetSecurityLevel (NET_SECURITY_PLAIN_TCP | NET_SECURITY_OPENSSL) << std::endl;	
	std::cout << netSetReconnectLimit ( 10 ) << std::endl;
	std::cout << netSetPathToPublicKey ( "server_pubkey.pem" ) << std::endl;
	std::cout << netSetPathToPrivateKey ( "server_private.pem" ) << std::endl;
	//std::cout << netSetPathToCertDir ( "/etc/ssl/certs" ) << std::endl;
	//std::cout << netSetPathToCertFile ( "/etc/ssl/certs/ca-certificates.crt" ) << std::endl;

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

void Server::Close ()
{
	
}

int Server::Run ()
{
	// process event queue
	return netProcessQueue ();
}

void Server::InitWords ()
{
	// demo app

	for (int n=0; n<10; n++) wordlist.push_back("");

	wordlist[0] = "zero";
	wordlist[1] = "one";
	wordlist[2] = "two";
	wordlist[3] = "three";
	wordlist[4] = "four";
	wordlist[5] = "five";
	wordlist[6] = "six";
	wordlist[7] = "seven";
	wordlist[8] = "eight";
	wordlist[9] = "nine";	
}

std::string Server::ConvertToWords ( int num )
{
	// demo - this is the main task of the server
	
	std::string words = "==========";
	int n = num;
	int v;

	while (n != 0 ) {
		v = n % 10;
		words = wordlist[v] + " " + words;
		n /= 10;
	}
    words = "========== " + words;
	return words;
}

void Server::SendWordsToClient ( std::string msg, int sock )
{
	// demo app protocol:
	//
	// cRqs - request the words for a number (c=msg from client)
	// sRst - here is the result containing the words (s=msg from server)

	// create sRst app event
	Event e = new_event ( 120, 'app ', 'sRst', 0, getNetPool ( ) );	
	e.attachStr ( msg );

	netSend ( e, sock );		// send to specific client
}

int Server::Process ( Event& e )
{
	int sock;
	std::string line;
	eventStr_t sys = e.getTarget ();

	// Check for net error events
	if ( sys == 'net ' && e.getName()=='nerr' ) {
		// enable netVerbose(true) for detailed messages.
		// application can gracefully handle specific net error codes here..		
		int code = e.getInt ();		
		if (code==NET_DISCONNECTED) {
			dbgprintf ( "  Connection to client closed unexpectedly.\n" );
		}		
		return 0;
	}

	// Process Network events
	e.startRead ();
	switch (e.getName()) {
	case 'sOkT': 
		// Connection to client complete. (telling myself)
		sock = e.getInt();		// server sock		
		dbgprintf ( "  Connected to client: #%d\n", sock );
		return 1;
		break;
	case 'cFIN': 
		// Client closed connection
		sock = e.getInt();
		dbgprintf ( "  Disconnected client: #%d\n", sock );
		return 1;
		break;		
	};

	// Process Application events
	switch (e.getName()) {
	case 'cRqs': 
		// client requested words for num
		int sock = e.getInt ();     // which client 
		int seq = e.getInt (); 		
		int num = e.getInt ();	

		// convert the num to words 
		std::string words = ConvertToWords ( num );

		// send words back to client
		SendWordsToClient ( words, sock );

		dbgprintf ( "  Sent words to #%d: SEQ-%d: %d, %s\n", sock, seq, num, words.c_str() );
		return 1;
		break;
	};

	dbgprintf ( "   Unhandled message: %s\n", e.getNameStr().c_str() );
	return 0;
}
