//---------------------------------------------------------------------
//
// Network System
// Quanta Sciences, Rama Hoetzlein (c) 2007-2020
//
//---------------------------------------------------------------------

#include <assert.h>

#include "network_system.h"

#ifdef __linux__
  #include <net/if.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h> 
  #include <sys/stat.h>
#elif __ANDROID__
  #include <net/if.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h> 
#endif

#ifdef BUILD_OPENSSL
	#include <openssl/opensslv.h>
  #include <openssl/crypto.h>
	#include <openssl/pem.h>
	#include <openssl/err.h>
	#include <openssl/md5.h>
	#include <openssl/ssl.h>	
	#include <openssl/x509v3.h>
#endif

//----------------------------------------------------------------------
// TRACING FUNCTIONS
//----------------------------------------------------------------------

double NetworkSystem::get_time ( ) 
{
	struct timespec t;
	clock_gettime ( CLOCK_REALTIME, &t );
	double nsec_comp = ( t.tv_nsec - mRefTime.tv_nsec );
	return t.tv_sec - mRefTime.tv_sec + nsec_comp / 1.0e9;	
}

void NetworkSystem::trace_setup ( const char* f )
{
	debug_print ( "NetworkSystem::setup_trace: ", f );
	mTrace = fopen ( f, "w" );
	if ( mTrace == 0 ) {
		debug_print ( "ERROR: Could not open trace file: Errno: ", errno );
		return;
	}
	clock_gettime ( CLOCK_REALTIME, &mRefTime );
	#ifdef __linux__
		chmod ( f, S_IRWXO ); 
	#endif
}

void NetworkSystem::trace_enter ( const char* f ) 
{
	if ( mTrace == 0 ) {
		debug_print ( "TRACE_EXIT: Trace file not yet opened: Call from: ", f );
		return;
	}
	std::string pad ( mIndentCount * 2, ' ' );
	fprintf ( mTrace, "%.9f:i:%s:%s\n", get_time ( ),  pad.c_str ( ), f );
	fflush ( mTrace );
	mIndentCount++;
}

void NetworkSystem::trace_exit ( const char* f )
{
	if ( mTrace == 0 ) {
		debug_print ( "TRACE_ENTER: Trace file not yet opened: Call from: ", f );
		return;
	}
	mIndentCount--;
	if ( mIndentCount < 0 ) {
		debug_print ( "TRACE_ENTER: Bad indent: Call from: ", f);
		mIndentCount = 0;
	}
	std::string pad ( mIndentCount * 2, ' ' );
	fprintf ( mTrace, "%.9f:o:%s:%s\n", get_time ( ), pad.c_str ( ), f );
	fflush ( mTrace );
}

//----------------------------------------------------------------------
// TRACING HOOKS
//----------------------------------------------------------------------

// #define TRACE_FUNCTION_CALLS

#ifdef TRACE_FUNCTION_CALLS
	#define TRACE_SETUP(msg) trace_setup(msg)
	#define TRACE_ENTER(msg) trace_enter(msg)
	#define TRACE_EXIT(msg) trace_exit(msg)
#else 
	#define TRACE_SETUP(msg) (void)0
	#define TRACE_ENTER(msg) (void)0
	#define TRACE_EXIT(msg) (void)0
#endif 

//----------------------------------------------------------------------
// SMALL HELPER FUNCTIONS
//----------------------------------------------------------------------

template<typename... Args> 
void NetworkSystem::verbose_print ( const char* fmt, Args... args )
{
	std::string fmt_str ( fmt );
	fmt_str += "\n";
	if ( mPrintVerbose ) {
		dbgprintf ( fmt_str.c_str ( ), args... );
	}
}

template<typename... Args> 
void NetworkSystem::debug_print ( const char* fmt, Args... args )
{
	std::string fmt_str ( fmt );
	fmt_str += "\n";
	if ( mPrintDebugNet ) {
		dbgprintf  ( fmt_str.c_str ( ), args... );
	}
}

template<typename... Args> 
void NetworkSystem::handshake_print ( const char* fmt, Args... args )
{
	std::string fmt_str ( fmt );
	fmt_str += "\n";
	if ( mPrintHandshake ) {
		dbgprintf ( fmt_str.c_str ( ), args... );
	}
}

template<typename... Args> 
void NetworkSystem::verbose_debug_print ( const char* fmt, Args... args )
{
	std::string fmt_str ( fmt );
	fmt_str += "\n";
	if ( mPrintDebugNet && mPrintVerbose ) {
		dbgprintf  ( fmt_str.c_str ( ), args... );
	}
}

//----------------------------------------------------------------------
// MAIN CODE
//----------------------------------------------------------------------

NetworkSystem* net;

NetworkSystem::NetworkSystem ()
{
	mHostType = ' ';
	mHostIP = 0;
	mReadyServices = 0;
	mUserEventCallback = 0;
	mPrintVerbose = false;
	mPrintDebugNet = false;
	mPrintHandshake = false;
	mTrace = 0;
}

void sleep_ms ( int time_ms ) {    
	TRACE_ENTER ( (__func__) ); 
	TimeX t;
	t.SleepNSec ( time_ms * 1e6 );  
	TRACE_EXIT ( (__func__) );
}

unsigned long NetworkSystem::get_read_ready_bytes ( SOCKET sock ) 
{   
	TRACE_ENTER ( (__func__) ); 
	#ifdef _WIN32 // windows
		unsigned long bytes_avail;
		if ( ioctlsocket ( sock, FIONREAD, &bytes_avail) == -1 ) {
			perror ( "ioctl FIONREAD" );
			TRACE_EXIT ( (__func__) );
			return -1; // Return -1 on error
		}
		TRACE_EXIT ( (__func__) );
		return bytes_avail;
	#else		
	    int bytes_avail;
		if ( ioctl ( sock, FIONREAD, &bytes_avail ) == -1 ) {
			perror ( "ioctl FIONREAD" );
			TRACE_EXIT ( (__func__) );
			return -1; // Return -1 on error
		}
		TRACE_EXIT ( (__func__) );
		return (unsigned long) bytes_avail;
	#endif    
}

void NetworkSystem::make_sock_no_delay ( SOCKET sock ) 
{
	int no_delay = 1;
	if ( setsockopt ( sock, IPPROTO_TCP, TCP_NODELAY, (char *)&no_delay, sizeof ( no_delay ) ) < 0) {
		perror( "Call to no delay FAILED" );
		exit ( EXIT_FAILURE );
	}  
	else {
		verbose_debug_print ( "Call to no delay succeded" );
	} 
} 

void NetworkSystem::make_sock_block ( SOCKET sock )
{
	#ifdef _WIN32 // windows
		unsigned long block_mode = 0; // (s.blocking ? 0 : 1);  // 0=blocking, 1=non-blocking
		ioctlsocket ( sock, FIONBIO, &block_mode);	// FIONBIO = non-blocking mode	
	#else // linux
		int flags = fcntl ( sock, F_GETFL, 0 );
		if ( flags == -1 ) {
			perror ( "get flags failed" );
			exit ( EXIT_FAILURE );
		} else {
			verbose_print ( "Call to get flags succeded" );
		}
		flags &= ~O_NONBLOCK;
		if ( fcntl ( sock, F_SETFL, flags ) == -1 ) {
			perror ( "set blocking option failed" );
			exit( EXIT_FAILURE );
		} else {
			verbose_print ( "Call to set blocking succeded" );
		}
	#endif
}

void NetworkSystem::make_sock_non_block ( SOCKET sock )
{
	#ifdef _WIN32 // windows
		unsigned long block_mode = 1; // (s.blocking ? 0 : 1);  // 0=blocking, 1=non-blocking
		ioctlsocket ( sock, FIONBIO, &block_mode);	// FIONBIO = non-blocking mode	
	#else // linux
		int flags = fcntl(sock, F_GETFL, 0);
		if (flags == -1) {
			perror("get flags failed");
			exit(EXIT_FAILURE);
		} else {
			verbose_print ( "Call to get flags succeded" );
		}	
		flags |= O_NONBLOCK;
		if (fcntl(sock, F_SETFL, flags) == -1) {
			perror("set non-blocking option failed");
			exit(EXIT_FAILURE);
		} else {
			verbose_print ( "Call to set non-blocking succeded" );
		}
	#endif
}

//--------------------------------------------------- NETWORK SERVER
//

#ifdef BUILD_OPENSSL
	
	void NetworkSystem::free_openssl ( int sock ) 
	{
		TRACE_ENTER ( (__func__) );
		NetSock& s = mSockets [ sock ];
		if ( s.ssl != 0 ) {
			if ( SSL_shutdown ( s.ssl ) == 0 ) {
				SSL_shutdown ( s.ssl );
			} 
			SSL_free ( s.ssl ); 
			s.ssl = 0;
		}
		if ( s.ctx != 0 ) {
			SSL_CTX_free ( s.ctx );
			s.ctx = 0;
		}
		TRACE_EXIT ( (__func__) );
	}

	// MP: new, should be called by server after accept
	int NetworkSystem::setupServerOpenssl ( int sock ) 
	{
		TRACE_ENTER ( (__func__) );
		NetSock& s = mSockets [ sock ];
		make_sock_no_delay ( s.socket );
		int ret = 0, exp;
		make_sock_non_block ( s.socket ); // MP: From what I can tell, socket is already non-blocking
		//make_sock_block ( s.socket ); 
	
		if ( ( s.ctx = SSL_CTX_new ( TLS_server_method () ) ) == 0 ) {
			perror( "get new ssl ctx failed" );
			free_openssl ( sock );
			TRACE_EXIT ( (__func__) );
			return 0;
		}
	
		dbgprintf ( "OpenSSL: %s", OPENSSL_VERSION_TEXT ); // openssl version 

		exp = SSL_OP_SINGLE_DH_USE;
		if (((ret = SSL_CTX_set_options( s.ctx, exp )) & exp) != exp ) {
			perror( "set ssl option failed" );
			free_openssl ( sock );
			TRACE_EXIT ( (__func__) );
			return 0;
		} else {
			handshake_print ( "Call to set ssl option succeded" );
		}

		// specify CA veryify locations for trusted certs
		if ( ( ret = SSL_CTX_set_default_verify_paths ( s.ctx ) ) <= 0 ) {
			netPrintError( ret, "Default verify paths failed" );
		} else {
			handshake_print ( "Call to default verify paths succeded" );
		}
		if ( ( ret = SSL_CTX_load_verify_locations ( s.ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs" ) ) <= 0) {
			netPrintError ( ret, "Load verify locations failed" );
		} else {
			handshake_print ( "Call to load verify locations succeded" );
		}

		SSL_CTX_set_verify ( s.ctx, SSL_VERIFY_PEER, NULL );

		// dbgprintf ( "  Cert file path: %s\n", ASSET_PATH );

		// NOTE: For now the /assets path is hardcoded because libmin cannot know the 
		// assets folder of the final app (eg. netdemo). This means the app must be
		// run from the same working directory as the binary.
		// Will be fixed once we have a netSetCertPath API function and let the app tell us.

		// load server public & private keys
		char fpath[2048];
		sprintf ( fpath, "src/assets/server-server.pem" );

		if ( ( ret = SSL_CTX_use_certificate_file ( s.ctx, fpath, SSL_FILETYPE_PEM ) ) <= 0 ) {
			netPrintError ( ret, "Use certificate failed" );	
			free_openssl ( sock ); 
			TRACE_EXIT ( (__func__) );	
			return 0;
		} else {
			handshake_print ( "Call to use certificate succeded" );
		}

		sprintf ( fpath, "src/assets/server.key" );

		if ( ( ret = SSL_CTX_use_PrivateKey_file ( s.ctx, fpath, SSL_FILETYPE_PEM ) ) <= 0) {
			netPrintError ( ret, "Use private key failed" );
			free_openssl ( sock ); 
			TRACE_EXIT ( (__func__) );
			return 0;
		} else {
			handshake_print ( "Call to use private key succeded" );
		}

		s.ssl = SSL_new ( s.ctx );
		if ( SSL_set_fd ( s.ssl, s.socket ) <= 0 ) {
			perror( "set ssl fd failed" );
			free_openssl ( sock ); 
			TRACE_EXIT ( (__func__) );
			return 0;
		} else {
			handshake_print ( "Call to set ssl fd succeded" );
		}
		TRACE_EXIT ( (__func__) );
		return acceptServerOpenssl ( sock );
	}
	      
	int NetworkSystem::acceptServerOpenssl ( int sock ) 
	{ 
		TRACE_ENTER ( (__func__) );
		NetSock& s = mSockets[ sock ];	   
		int ret;
		if ( ( ret = SSL_accept ( s.ssl ) ) < 0 ) {
			if ( checkOpensslError ( sock, ret ) ) {
				handshake_print ( "Non-blocking call to ssl accept returned" );
				handshake_print ( "Ready for safe transfer: ", SSL_is_init_finished ( s.ssl ) );
				TRACE_EXIT ( (__func__) );
				return 3;
			} else {	
				netPrintError ( ret, "SSL_accept failed", s.ssl );
				free_openssl ( sock ); 
				TRACE_EXIT ( (__func__) );
				return 0;   
			}
		} else if ( ret == 0 ) {
			handshake_print ( "Call to ssl accept failed (2)" );
			free_openssl ( sock );
			TRACE_EXIT ( (__func__) );
			return 0; 
		} 
		handshake_print ( "Call to ssl accept succeded" );
		handshake_print ( "Ready for safe transfer: ", SSL_is_init_finished ( s.ssl ) );
		TRACE_EXIT ( (__func__) );
		return 4;
	}
	
#endif

void NetworkSystem::netStartServer ( netPort srv_port )
{
	if ( mTrace == 0 ) {
		TRACE_SETUP (( "../trace-func-server" ));
	}
	
	TRACE_ENTER ( (__func__) );
	handshake_print ( "Start Server:" );
	mHostType = 's';
	netIP srv_anyip = inet_addr ("0.0.0.0");

	int srv_sock = netAddSocket ( NET_SRV, NET_TCP, NET_ENABLE, false, 
									NetAddr(NET_ANY, mHostName, srv_anyip, srv_port),
		                            NetAddr(NET_BROADCAST, "", 0, srv_port ) );

	const char reuse = 1;
	if ( setsockopt( mSockets[srv_sock].socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)		
		handshake_print ( "netSys Error: Setting server socket as SO_REUSEADDR." );

	netSocketBind ( srv_sock );
	netSocketListen ( srv_sock );	
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netServerListen ( int sock )
{
	TRACE_ENTER ( (__func__) );
	int srv_sock_svc = netFindSocket ( NET_SRV, NET_TCP, NET_ANY );
	if ( srv_sock_svc == -1 ) {
		netPrintError ( 0, "Unable to find server listen socket." );
	}

	// get server name & port;
	std::string srv_name = mSockets[ srv_sock_svc ].src.name;
	netPort srv_port = mSockets[ srv_sock_svc ].src.port;

	netIP cli_ip = 0;
	netPort cli_port = 0;

	// Accept TCP on a service socket (open port)

	SOCKET newSOCK;			// new literal socket

	int result = netSocketAccept ( srv_sock_svc, newSOCK, cli_ip, cli_port );
	if ( result < 0 ) {
		verbose_print ( "Connection not accepted." );
		TRACE_EXIT ( (__func__) );
		return;
	}

	// Get server IP. Listen/accept happens on ANY address (0.0.0.0)
	// we want the literal server IP for final connection
	netIP srv_ip = mHostIP;

	// Create new socket
	int srv_sock_tcp = netAddSocket ( NET_SRV, NET_TCP, NET_CONNECT, false,
										NetAddr(NET_CONNECT, srv_name, srv_ip, srv_port), 
										NetAddr(NET_CONNECT, "", cli_ip, cli_port) );

	NetSock& s = mSockets[ srv_sock_tcp ];

	make_sock_non_block ( newSOCK );

	s.socket = newSOCK;					// assign literal socket
	s.dest.ipL = cli_ip;				// assign client IP
	s.dest.port = cli_port;			// assign client port
	s.status = NET_CONNECTED;		// connected

	#ifdef BUILD_OPENSSL
		if ( s.security == 1 ) { // MP: this should be the right spot; setup ssl if security is larger than zero
			s.security = setupServerOpenssl( srv_sock_tcp );
			if ( s.security == 0 ) 
			{
				netTerminateSocket ( srv_sock_tcp, 1 );
			}
		}
	#endif

	// complete connection. both TCP/IP and SSL
	if ( s.security == 4 ) {
		netServerListenReturnSig ( sock );
	}
	TRACE_EXIT ( (__func__) ); 	
} 
	
void NetworkSystem::netServerListenReturnSig ( int sock )
{
	TRACE_ENTER ( (__func__) );
	int srv_sock_svc = netFindSocket ( NET_SRV, NET_TCP, NET_ANY );
	if ( srv_sock_svc == -1 ) {
	   netPrintError ( 0, "Unable to find server listen socket." );
	}
	netPort srv_port = mSockets[ srv_sock_svc ].src.port;
	NetSock& s = mSockets[sock];

	// Send TCP connected event to client
	Event e;
	e = netMakeEvent ( 'sOkT', 0 );
	e.attachInt64 ( s.dest.ipL ); // client IP
	e.attachInt64 ( s.dest.port ); // client port assigned by server!
	e.attachInt64 ( mHostIP ); // server IP
	e.attachInt64 ( srv_port ); // server port
	e.attachInt ( sock ); // connection ID (goes back to the client)
	netSend ( e, NET_CONNECT, sock );

	// Inform the user-app (server) of the event
	Event ue = new_event ( 120, 'app ', 'sOkT', 0, mEventPool );	
	ue.attachInt ( sock );
	ue.attachInt ( -1 );										// cli_sock not known
	ue.startRead ();
	(*mUserEventCallback) ( ue, this );		// send to application

	verbose_print ( "  %s %s: Accepted ip %s, port %i on port %d", (s.side == NET_CLI) ? "Client" : "Server", getIPStr(mHostIP).c_str(), getIPStr(s.dest.ipL).c_str(), s.dest.port, s.src.port );
	netPrint ( );
	TRACE_EXIT ( (__func__) );
}


//----------------------------------------------------------- NETWORK CLIENT
//
// MP: new, should be called by client after connect
	
#ifdef BUILD_OPENSSL
	int NetworkSystem::setupClientOpenssl ( int sock ) 
	{ 
		TRACE_ENTER ( (__func__) );
		int ret=0, exp;
		NetSock& s = mSockets[sock];
		make_sock_no_delay ( s.socket );
		make_sock_non_block ( s.socket ); // MP: From what I can tell, socket is already non-blocking
		//make_sock_block( s.socket ); 
		#if OPENSSL_VERSION_NUMBER < 0x10100000L
			// version 1.1
			SSL_load_error_strings();	 
			SSL_library_init();
		#else
			// version 3.0+
			OPENSSL_init_ssl ( OPENSSL_INIT_LOAD_SSL_STRINGS, NULL );
		#endif

		// openssl version 
		dbgprintf ( "OpenSSL: %s", OPENSSL_VERSION_TEXT );
	
		//s.bio = BIO_new_socket(s.socket, BIO_NOCLOSE);
	
		s.ctx = SSL_CTX_new ( TLS_client_method () );
		if (!s.ctx) {
			perror ( "ctx failed" );
			ERR_print_errors_fp ( stderr );
			free_openssl ( sock );
			TRACE_EXIT ( (__func__) );
			return 0;
		} else {
			handshake_print ( "Call to ctx succeded" );
		}

		//----- deprecated as of 1.1.0, use SSL_CTX_set_min_proto_version
		/* exp = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
		if (((ret = SSL_CTX_set_options(s.ctx, exp)) & exp) != exp) {	
			perror("set ssl option failed");
			TRACE_EXIT ( (__func__) );
			return 0;
		} else {
			handshake_print ( "Call to set ssl option succeded" );
		} */

		//-- use TLS 1.2+ only, since we have custom client-server protocols
		SSL_CTX_set_min_proto_version ( s.ctx, TLS1_2_VERSION );
		SSL_CTX_set_max_proto_version ( s.ctx, TLS1_3_VERSION );
		SSL_CTX_set_verify ( s.ctx, SSL_VERIFY_PEER, NULL );

		if ( !SSL_CTX_load_verify_locations( s.ctx, "src/assets/server-client.pem", NULL ) ) {
			perror ( "load verify locations failed" );
			ERR_print_errors_fp ( stderr );
			free_openssl ( sock );
			TRACE_EXIT ( (__func__) );
			return 0;
		} else {
			handshake_print ( "Call to load verify locations succeded" );
		}		

		s.ssl = SSL_new ( s.ctx );
		if ( !s.ssl ) {
			perror ( "ssl failed" );
			ERR_print_errors_fp ( stderr );
			free_openssl ( sock ); 
			TRACE_EXIT ( (__func__) );
			return 0;
		} else {
			handshake_print ( "Call to ssl succeded" );
		}	
	
		if ( SSL_set_fd ( s.ssl, s.socket ) != 1 ) {
			perror ( "ssl set fd failed" );	
			free_openssl ( sock );
			TRACE_EXIT ( (__func__) ); 	
			return 0;
		} else {
			handshake_print ( "Call to ssl set fd succeded" );
		}	
	
		TRACE_EXIT ( (__func__) );
		return connectClientOpenssl ( sock );
	}	

	int NetworkSystem::connectClientOpenssl ( int sock )
	{
		TRACE_ENTER ( (__func__) );
		int ret=0, exp;
		NetSock& s = mSockets[sock];
	
		if ( ( ret = SSL_connect ( s.ssl ) ) < 0 ) {
			if ( checkOpensslError ( sock, ret ) ) {
				handshake_print ( "Non-blocking call to ssl connect tentatively succeded" );
				handshake_print ( "Ready for safe transfer: ", SSL_is_init_finished ( s.ssl ) );
				TRACE_EXIT ( (__func__) );
				return 2;
			} else {
				netPrintError ( ret, "SSL_connect failed", s.ssl );	
				free_openssl ( sock ); 	
				TRACE_EXIT ( (__func__) );
				return 0;	
			}
		} else if ( ret == 0 ) {
			handshake_print ( "Call to ssl connect failed (2)" );
			free_openssl ( sock ); 	
			TRACE_EXIT ( (__func__) );
			return 0;
		}

		handshake_print ( "Call to ssl connect succeded" );
		handshake_print ( "Ready for safe transfer: ", SSL_is_init_finished ( s.ssl ) );
		TRACE_EXIT ( (__func__) );
		return 4;	
	}
#endif

void NetworkSystem::netStartClient ( netPort cli_port, std::string srv_addr )
{
	if ( mTrace == 0 ) {
		TRACE_SETUP (( "../trace-func-client" ));
	}
	
	TRACE_ENTER ( (__func__) );
	// Network System is running in client mode
	eventStr_t sys = 'net ';
	mHostType = 'c';
	verbose_print ( "Start Client:" );

	// Start a TCP listen socket on Client
	struct HELPAPI NetAddr netAddr = NetAddr();
	netAddr.convertIP ( ntohl( inet_addr( srv_addr.c_str() ) ) );
	netAddr.ipL = inet_addr( srv_addr.c_str() );
	netAddSocket ( NET_CLI, NET_TCP, NET_OFF, false, 
					NetAddr(NET_ANY, mHostName, mHostIP, cli_port), netAddr );
	TRACE_EXIT ( (__func__) );
}

int NetworkSystem::netClientConnectToServer (std::string srv_name, netPort srv_port, bool blocking )
{
	TRACE_ENTER ( (__func__) );
	NetSock cs;
	std::string cli_name;
	netIP cli_ip, srv_ip;
	int cli_port, cli_sock_svc, cli_sock_tcp, cli_sock;

	// check server name for dots
	int dots = 0;
	for (int n = 0; n < srv_name.length(); n++)
		if ( srv_name.at(n) == '.' ) dots++;

	if (srv_name.compare ( "localhost" ) == 0) {
		// server is localhost
		srv_ip = mHostIP;
	} else if (dots == 3) {
		// three dots, translate srv_name to literal IP		
		srv_ip = getStrToIP(srv_name);
	} else {
		// fewer dots, lookup host name
		// resolve the server address and port
		addrinfo* pAddrInfo;
		char portname[64];
		sprintf(portname, "%d", srv_port);
		int result = getaddrinfo ( srv_name.c_str(), portname, 0, &pAddrInfo );
		if (result != 0) {
			TRACE_EXIT ( (__func__) );
			return netError ( "Unable to resolve server name: " + srv_name, result );
		}	
		// translate addrinfo to IP string
		char ipstr[INET_ADDRSTRLEN];
		for (addrinfo* p = pAddrInfo; p != NULL; p = p->ai_next) {
			struct in_addr* addr;
			if (p->ai_family == AF_INET) {
				struct sockaddr_in* ipv = (struct sockaddr_in*)p->ai_addr;
				addr = &(ipv->sin_addr);
			}
			else {
				struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
				addr = (struct in_addr*) & (ipv6->sin6_addr);
			}
			inet_ntop ( p->ai_family, addr, ipstr, sizeof ipstr );
		}		
		srv_ip = getStrToIP ( ipstr );
	}

	// find a local TCP socket service
	cli_sock_svc = netFindSocket ( NET_CLI, NET_TCP, NET_ANY );
	cs = getSock(cli_sock_svc);
	cli_name = cs.src.name;
	cli_ip = mHostIP;
	cli_port = cs.src.port;

	// find or create a socket, connect it if needed
	NetAddr srv_addr = NetAddr ( NET_CONNECT, srv_name, srv_ip, srv_port );
	cli_sock_tcp = netFindSocket ( NET_CLI, NET_TCP, srv_addr );
	if ( cli_sock_tcp == NET_ERR ) { 
		NetAddr cli_addr = NetAddr ( NET_CONNECT, cli_name, cli_ip, cli_port );
		cli_sock_tcp = netAddSocket ( NET_CLI, NET_TCP, NET_ENABLE, blocking, cli_addr, srv_addr );
		if ( cli_sock_tcp == NET_ERR ) {	
			TRACE_EXIT ( (__func__) );		
			return netError ( "Unable to add socket." );
		}
	}

	const char reuse = 1;
	if ( setsockopt( mSockets[cli_sock_tcp].socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int) ) < 0 ) {
		verbose_print ( "netSys: Setting server socket as SO_REUSEADDR." );
	}

	// try to connect	
	if ( mSockets[cli_sock_tcp].status != NET_CONNECTED ) {
		int result = netSocketConnect ( cli_sock_tcp );
		if (result !=0 ) netReportError ( result );
	}

	// SSL handshake
	#ifdef BUILD_OPENSSL	
		// MP: this should be the right spot; setup ssl if security is larger that zero
		if ( mSockets[cli_sock_tcp].security == 1 ) {
			mSockets[cli_sock_tcp].security = setupClientOpenssl ( cli_sock_tcp );
			if ( mSockets[cli_sock_tcp].security == 0 ) 
			{
				netTerminateSocket ( cli_sock_tcp, 1 );
			}
		}
		if ( mSockets[cli_sock_tcp].security == 2 ) {
			mSockets[cli_sock_tcp].security = connectClientOpenssl ( cli_sock_tcp );
			if ( mSockets[cli_sock_tcp].security == 0 ) 
			{
				netTerminateSocket ( cli_sock_tcp, 1 );
			}
		}
	#endif
	
	TRACE_EXIT ( (__func__) );
	return cli_sock_tcp;		// return socket for this connection
}

int NetworkSystem::netCloseAll ()
{
	TRACE_ENTER ( (__func__) );
	for (int n=0; n < mSockets.size(); n++) {
		netCloseConnection ( n );
	}
	netPrint( );
	TRACE_EXIT ( (__func__) );
	return 1;
}

int NetworkSystem::netCloseConnection ( int sock )
{
	TRACE_ENTER ( (__func__) );
	if ( sock < 0 || sock >= mSockets.size() ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}

	if ( mSockets[sock].side == NET_CLI ) {
		if ( mSockets[sock].mode == NET_CONNECT ) {
			// client inform server we're done		
			Event e = netMakeEvent ( 'sExT', 'net ' );
			e.attachUInt ( mSockets[sock].dest.sock );		// server (remote) socket
			e.attachUInt ( sock );							// client (local) socket
			netSend ( e );
			netProcessQueue ();				// process queue once to flush it
		}
	} else {
		// server inform client we're done
		if ( mSockets[sock].mode == NET_CONNECT ) {
			int dest_sock = mSockets[sock].dest.sock;
			Event e = netMakeEvent ( 'cExT', 'net ' );
			e.attachUInt ( mSockets[sock].dest.sock );	// client (remote) socket
			e.attachUInt ( sock );						// server (local) socket
			netSend ( e );
			netProcessQueue ();				// process queue once to flush it
		}
	}

	// terminate local socket
	netTerminateSocket ( sock );	
	TRACE_EXIT ( (__func__) );
	return 1;
}

// Process network-related events
void NetworkSystem::netProcessEvents ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	switch ( e.getName() ) {
		case 'sOkT': {				// received OK from server. connection complete.

			// Client received accept from server
			int cli_sock = e.getSrcSock();

			// Get connection data from Event
			netIP cli_ip = e.getInt64();
			netPort cli_port = e.getInt64();
			netIP srv_ip = e.getInt64();		// server given in Event payload
			int srv_port = e.getInt64();
			int srv_sock = e.getInt();

			// Update client socket with server socket & client port
			mSockets[cli_sock].status = NET_CONNECTED;		// mark connected
			mSockets[cli_sock].dest.sock = srv_sock;		// assign server socket
			mSockets[cli_sock].src.port = cli_port;			// assign client port from server

			// Verify client and server IPs
			netIP srv_ip_chk = e.getSrcIP();		// source IP from the socket event came on
			netIP cli_ip_chk = mSockets[cli_sock].src.ipL;	// original client IP

			/*
			if ( srv_ip != srv_ip_chk ) {	// srv IP from event. srvchk IP from packet origin
				dbgprintf ( "NET ERROR: srv %s and srvchk %s IP mismatch.", getIPStr(srv_ip).c_str(), getIPStr(srv_ip_chk).c_str() );
				exit(-1);
			}
			if ( cli_ip != cli_ip_chk ) {	// cli IP from event. clichk IP from original request
				dbgprintf ( "NET ERROR: cli %s and clichk %s IP mismatch.", getIPStr(cli_ip).c_str(), getIPStr(cli_ip_chk).c_str() );
				exit(-1);
			}
			*/

			// Inform the user-app (client) of the event
			Event e = new_event ( 120, 'app ', 'sOkT', 0, mEventPool );
			e.attachInt ( srv_sock );
			e.attachInt ( cli_sock );		
			e.startRead ();
			(*mUserEventCallback) ( e, this );		// send to application

			verbose_print ("  Client:   Linked TCP. %s:%d, sock: %d --> Server: %s:%d, sock: %d", getIPStr(cli_ip).c_str(), cli_port, cli_sock, getIPStr(srv_ip).c_str(), srv_port, srv_sock);
			netPrint();
			break;
		} 
		case 'sExT': {			// server recv, Exit TCP from client. sEnT
			int local_sock = e.getUInt (); // socket to close
			int remote_sock = e.getUInt (); // remote socket
			netIP cli_ip = mSockets[local_sock].dest.ipL;
			verbose_print ( "  Server: Client closed ok. %s", getIPStr ( cli_ip ).c_str ( ) );
			netTerminateSocket ( local_sock );
			netPrint ();
			break;
		}
	}
	TRACE_EXIT ( (__func__) );
}



//---------------------------------------------- NETWORK CORE - Client & Server
//
void NetworkSystem::netInitialize ( )
{
	TRACE_ENTER ( (__func__) );
	mCheck = 0;
	verbose_print ( "Network Initialize." );

	// Create an Event Memory Pool
	//mEventPool = new EventPool();
	mEventPool = 0x0; // NO EVENT POOLING
	netStartSocketAPI ( ); // Low-level API
	netGetHostname ( ); // Low-level gethostname
	TRACE_EXIT ( (__func__) );
}

// Add socket (abstracted)
int NetworkSystem::netAddSocket ( int side, int mode, int status, bool block, NetAddr src, NetAddr dest )
{
	TRACE_ENTER ( (__func__) );
	NetSock s;
	s.sys = 'net ';
	s.side = side;
	s.mode = mode;
	s.status = status;
	s.src = src;
	s.dest = dest;
	s.socket = 0;
	s.timeout.tv_sec = 0; s.timeout.tv_usec = 0;
	s.blocking = block;
	s.broadcast = 1;
	s.security = 1; // MP: use openssl by default

	s.ctx = 0;
	s.ssl = 0;
	s.bio = 0;

	int n = mSockets.size ();
	mSockets.push_back ( s );
	netUpdateSocket ( n );
	TRACE_EXIT ( (__func__) );
	return n;
}


#ifdef __linux__
	int clearSocketError ( int fd ) {
	   int err = 1;
	   socklen_t len = sizeof err;
	   if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
		  printf ( "getSO_ERROR" );
	   if (err)
		  errno = err;              // set errno to the socket SO_ERROR
	   return err;
	}
#endif

// Terminate Socket
// Note: This does not erase the socket from std::vector because we don't want to
// shift around the other socket IDs. Instead it disables the socket ID, making it available
// to another client later. Only the very last socket could be actually removed from list.

int NetworkSystem::netTerminateSocket ( int sock, int force )
{
	TRACE_ENTER ( (__func__) );
	if ( sock < 0 || sock >= mSockets.size() ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}
	verbose_print ( "netTerminating: %d", sock );
	if ( mSockets[ sock ].status != NET_CONNECT && mSockets[ sock ].status != NET_CONNECTED && force == 0 ) {
		 TRACE_EXIT ( (__func__) );
		 return 0;
	}
	
	// close the socket
	NetSock* s = &mSockets[sock];

	#ifdef _WIN32
		shutdown ( s->socket, SD_BOTH );					
		closesocket ( s->socket );
	#else
		clearSocketError ( s->socket );
		shutdown ( s->socket, SHUT_RDWR );				
		close ( s->socket );
	#endif

	// mark as terminated
	mSockets[sock].status = NET_TERMINATED;

	// remove sockets at end of list
	// --- FOR NOW, THIS IS NECESSARY ON CLIENT (which may have only 1 socket),
	// BUT IN FUTURE CLIENTS SHOULD BE ABLE TO HAVE ANY NUMBER OF PREVIOUSLY TERMINATED SOCKETS
	if ( mSockets.size() > 0 ) {
		while ( mSockets[ mSockets.size() -1 ].status == NET_TERMINATED )
			mSockets.erase ( mSockets.end() -1 );
	}
	
	// inform the app
	if ( mHostType == 's' ) {
		// server noticed - client terminated a socket
		Event e = new_event(120, 'app ', 'cFIN', 0, mEventPool);
		e.attachInt(sock);
		e.startRead();
		(*mUserEventCallback) (e, this);		// send to application
	} else {
		// client noticed - server terminated a socket
		Event e = new_event(120, 'app ', 'sFIN', 0, mEventPool);
		e.attachInt(sock);
		e.startRead();
		(*mUserEventCallback) (e, this);		// send to application
	}
	
	TRACE_EXIT ( (__func__) );
	return 1;
}


// Handle incoming events, Client or Server
// this function dispatches either to the application-level callback,
// or the the network system event handler based on the Event system target
int NetworkSystem::netEventCallback ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	eventStr_t	sys = e.getTarget ();				// target system

	// Application should handle event
	if ( sys != 'net ' ) {								// not intended for network system
		if ( mUserEventCallback != 0x0 ) {				// pass user events to application
			TRACE_EXIT ( (__func__) );
			return (*mUserEventCallback) ( e, this );
		}
	}
	// Network system should handle event
	netProcessEvents ( e );
	TRACE_EXIT ( (__func__) );
	return 0; // only return >0 on user event completion
}

void NetworkSystem::netReportError ( int result )
{
	TRACE_ENTER ( (__func__) );
	// create a network error event and set it to the user
	Event e = netMakeEvent ( 'nerr', 'net ' );
	e.attachInt ( result );
	e.startRead();
	(*mUserEventCallback) ( e, this );
	TRACE_EXIT ( (__func__) );
}


std::string NetworkSystem::netPrintError ( int ret, std::string msg, SSL* sslsock ) 
{		 
	TRACE_ENTER ( (__func__) );
	msg = "ERROR: " + msg + "\n ";

	// append, error code for SSL socket
	#ifdef BUILD_OPENSSL
		if (sslsock != 0x0) { 	
			 int code = SSL_get_error (sslsock, ret );
			 switch (code)
			 {
			 case SSL_ERROR_NONE:					msg += "The TLS/SSL I/O operation completed."; break;
			 case SSL_ERROR_ZERO_RETURN:  msg += "The TLS/SSL connection has been closed."; break;
			 case SSL_ERROR_WANT_READ:    msg += "The read operation did not complete; the same TLS/SSL I/O function should be called again later.";    break;
			 case SSL_ERROR_WANT_WRITE:   msg += "The write operation did not complete; the same TLS/SSL I/O function should be called again later.";     break;
			 case SSL_ERROR_WANT_CONNECT: msg += "The connect operation did not complete; the same TLS/SSL I/O function should be called again later.";      break;
			 case SSL_ERROR_WANT_ACCEPT:  msg += "The accept operation did not complete; the same TLS/SSL I/O function should be called again later.";      break;
			 case SSL_ERROR_WANT_X509_LOOKUP:  msg += "The operation did not complete because an application callback set"
						" by SSL_CTX_set_client_cert_cb() has asked to be called again. "
						"The TLS/SSL I/O function should be called again later.";
						break;
			 case SSL_ERROR_SYSCALL: msg += "Some I/O error occurred. The OpenSSL error queue is here:";     break;
			 case SSL_ERROR_SSL:     msg += "A failure in the SSL library occurred, usually a protocol error. The OpenSSL error queue is here:"; break;
			 default: msg = "Unknown error"; break;
			 };		 
			 msg += "\n ";
		 }	 	

	 // append, SSL error queue 
	 char buf[512];
	 unsigned long err = ERR_get_error();
	 if (err==0) {
		 msg += "No additional SSL error info.\n";
	 } else {
		 while ( err != 0 ) {
			 ERR_error_string ( err, buf );
			 msg += std::string(buf) + "\n ";
			 err = ERR_get_error();
		 }	 
	 }
	#endif

	printf ( "%s\n", msg.c_str() );
	TRACE_EXIT ( (__func__) );
	return msg;
}

#ifdef BUILD_OPENSSL
	int NetworkSystem::checkOpensslError ( int sock, int ret ) 
	{
		TRACE_ENTER ( (__func__) );
		NetSock& s = mSockets [ sock ];
		int err = SSL_get_error ( s.ssl, ret ), code;
		switch ( err ) {
		case SSL_ERROR_WANT_READ:
			code = 1;
			break;
		case SSL_ERROR_WANT_WRITE:
			code = 1;
			break;
		case SSL_ERROR_ZERO_RETURN:
			debug_print ( "SSL_read returned SSL_ERROR_ZERO_RETURN: The connection has been closed" );
			code = 0;
			break;
		case SSL_ERROR_SYSCALL:
			debug_print ( "SSL_read returned SSL_ERROR_SYSCALL: Some I/O error occurred" );
			code = 0;
			break;
		case SSL_ERROR_SSL:
			debug_print ( "SSL_read returned SSL_ERROR_SSL: A failure in the SSL library occurred" );
			code = 0;
			break;
		default:
			debug_print ( "SSL_read returned an unexpected error:", err );
			code = 0;
			break;
		}
		TRACE_EXIT ( (__func__) );
		return code;  
	}
#endif

// Process Queue
int NetworkSystem::netProcessQueue ( void )
{
	// TRACE_ENTER ( (__func__) );
	// Recieve incoming data	
	#ifdef PROFILE_NET
		PERF_PUSH ( "netRecv" );
	#endif
	netRecieveData ();
	
	#ifdef PROFILE_NET	
		PERF_POP();
	#endif

	// Handle incoming events on queue
	int iOk = 0;

	Event e;

	while ( mEventQueue.size() > 0 ) {
		e = mEventQueue.front ();
		e.startRead ();
		iOk += netEventCallback ( e );	// count each user event handled ok
		mEventQueue.pop ();				// pop causes event & payload deletion!
		e.bOwn = false;
	}
	// TRACE_EXIT ( (__func__) );
	return iOk;
}

// Receive Data
int NetworkSystem::netRecieveData ()
{
	// TRACE_ENTER ( (__func__) );
	if ( mSockets.size() == 0 ) {
		// TRACE_EXIT ( (__func__) );
		return 0;
	}

	bool bDeserial;
	int event_alloc;
	int curr_socket;
	int result, maxfd=-1;

	// Get all sockets that are Enabled or Connected
	redo_select:
	#ifdef PROFILE_NET
		PERF_PUSH ( "socklist" );
	#endif
	FD_ZERO (&sock_set);
	for (int n = 0; n < (int) mSockets.size (); n++) {
		if ( mSockets[n].status != NET_OFF && mSockets[n].status != NET_TERMINATED ) {		// look for NET_ENABLE or NET_CONNECT
			if ( mSockets[n].security < 2 ) { // MP: this if-else has to be worked out
				FD_SET (mSockets[n].socket, &sock_set);
				if ( (int) mSockets[n].socket > maxfd ) maxfd = mSockets[n].socket;
			} else { 
				#ifdef BUILD_OPENSSL
			    int fd = SSL_get_fd( mSockets[n].ssl );
			    FD_SET (fd, &sock_set);	
			    if ( (int) fd > maxfd ) maxfd = fd;
				#endif
			}
		}
	}
	#ifdef PROFILE_NET
		PERF_POP();
	#endif
	maxfd++;
	if ( maxfd == 0 ) {
		// TRACE_EXIT ( (__func__) );
		return 0; // no sockets
	}
	//if ( sock_set.fd_count == 0 ) return 0;		// no sockets

	// Select all sockets that have changed
	#ifdef PROFILE_NET
		PERF_PUSH ( "select" );
	#endif

	result = select ( maxfd, &sock_set, NULL, NULL, &mSockets[0].timeout );

	#ifdef PROFILE_NET
		PERF_POP();
	#endif

	if (result < 0 ) {
		// Select failed. Report net error
		netReportError ( result );
		// TRACE_EXIT ( (__func__) );
		return 0;
	}

	// Select ok.
	// Find next updated socket
	#ifdef PROFILE_NET
		PERF_PUSH ( "findsock" );
	#endif

	curr_socket = 0;
	//for (; curr_socket != (int) mSockets.size() && !FD_ISSET( mSockets[curr_socket].socket, &sock_set); ) {
	//	curr_socket++;
	//}
	while ( curr_socket != (int) mSockets.size() ) { 
		if ( mSockets[curr_socket].security < 2 ) { // MP: this if-else has to be worked out
			if ( FD_ISSET( mSockets[curr_socket].socket, &sock_set ) ) {
				break;
			}
		} else {
			#ifdef BUILD_OPENSSL
				int fd = SSL_get_fd( mSockets[curr_socket].ssl );
				if ( FD_ISSET( fd, &sock_set ) ) {
					break;
				}
			#endif
		}		
		curr_socket++;
	}

	#ifdef PROFILE_NET
		PERF_POP();
	#endif

	// Check on valid socket. Silent error if not.
	if (curr_socket >= mSockets.size()) {
		// TRACE_EXIT ( (__func__) );
		return 0;
	}

	// Listen for TCP connections on socket
	if ( mSockets[curr_socket].src.type == NET_ANY ) {
		netServerListen ( curr_socket );
	}

	#ifdef BUILD_OPENSSL
		if ( mSockets[ curr_socket ].security == 3 ) { // MP: new
			mSockets[ curr_socket ].security = acceptServerOpenssl ( curr_socket );
			if ( mSockets[ curr_socket ].security == 4 ) {
				netServerListenReturnSig ( curr_socket );
			} else if ( mSockets[ curr_socket ].security == 0 ) {
				netTerminateSocket ( curr_socket, 1 );
			}
			// TRACE_EXIT ( (__func__) );
			return 0;
		}

		if ( mSockets[ curr_socket ].security == 2 ) { // MP: new
			mSockets[ curr_socket ].security = connectClientOpenssl ( curr_socket );
			if ( mSockets[ curr_socket ].security == 0 ) {
				netTerminateSocket ( curr_socket, 1 );
			}
			// TRACE_EXIT ( (__func__) );
			return 0;
		}
	#endif

	// Receive incoming data on socket
	#ifdef PROFILE_NET
		PERF_PUSH ( "recv" );
	#endif
	
	result = netSocketRecv ( curr_socket, mBuffer, NET_BUFSIZE-1, mBufferLen );
	if ( result == SSL_ERROR_WANT_READ && mSockets[curr_socket].security > 1 ) { // MP: this is a little hacky
	  //goto redo_select;	
	}
	if ( result != 0 || mBufferLen == 0 ) {
		netReportError ( result );		// Recv failed. Report net error
		// TRACE_EXIT ( (__func__) );
		return 0;
	}
	#ifdef PROFILE_NET
		PERF_POP();
	#endif

	// Data packet found. mBufferLen > 0
	mBufferPtr = &mBuffer[0];

	while ( mBufferLen > 0 ) {

		if ( mEvent.isEmpty() ) {

			// Check the type of incoming socket
			if (mSockets[curr_socket].blocking) {

				// Blocking socket. NOT an Event socket.
				// Attach arbitrary data onto a new event.
				mEventLen = mBufferLen;
				mEvent = new_event(mEventLen + 128, 'app ', 'HTTP', 0, mEventPool);
				mEvent.rescope("nets");
				mEvent.attachInt(mBufferLen);				// attachInt+Buf = attachStr
				mEvent.attachBuf(mBufferPtr, mBufferLen);
				mDataLen = mEvent.mDataLen;

			} else {
				// Non-blocking socket. Receive a complete Event.
				// directly read length-of-event info from incoming data (mDataLen value)
				mDataLen = *((int*) (mBufferPtr + Event::staticOffsetLenInfo() ));

				// compute total event length, including header
				mEventLen = mDataLen + Event::staticSerializedHeaderSize();

				if ( mDataLen == 0 ) {					
					// dbgprintf ( "WARNING: Received event with 0 payload.");
				}
				// Event is allocated with no name/target as this will be set during deserialize
				#ifdef PROFILE_NET
					PERF_PUSH ( "newevent" );
				#endif
				mEvent = new_event( mDataLen, 0, 0, 0, mEventPool);

				#ifdef PROFILE_NET
					PERF_POP();
				#endif
				mEvent.rescope("nets");		// belongs to network now

				// Deserialize of actual buffer length (EventLen or BufferLen)
				#ifdef PROFILE_NET
					PERF_PUSH ( "header" );
				#endif
				mEvent.deserialize(mBufferPtr, imin(mEventLen, mBufferLen));	// Deserialize header

				#ifdef PROFILE_NET
					PERF_POP();
				#endif
			}
			mEvent.setSrcSock(curr_socket);		// <--- tag event /w socket
			mEvent.setSrcIP(mSockets[curr_socket].src.ipL); // recover sender address from socket
			bDeserial = true;

		} else {
			// More data for existing Event..
			bDeserial = false;
		}

		// BufferLen = actual bytes received at this time (may be partial)
		// EventLen = size of event in *network*, serialized event including data payload
		//    bufferLen > eventLen      multiple events
		//    bufferLen = eventLen      one event, or end of event
		//    bufferLen < eventLen 			part of large event

		if ( mBufferLen >= mEventLen ) {

			// One event, multiple, or end of large event..
			if ( !bDeserial )	{
				// not start of event, attach more data
				#ifdef PROFILE_NET
					PERF_PUSH ( "attach" );
				#endif
				mEvent.attachBuf ( mBufferPtr, mBufferLen );
				#ifdef PROFILE_NET
					PERF_POP ();
				#endif
			}
			// End of event
			mBufferLen -= mEventLen;			// advance buffer
			mBufferPtr += mEventLen;
			mEventLen = 0;
			int hsz = Event::staticSerializedHeaderSize();
			verbose_debug_print ( "recv: %d bytes, %s", mEvent.mDataLen + hsz, mEvent.getNameStr().c_str() );
			
			// Confirm final size received matches indicated payload size
			if ( mEvent.mDataLen != mDataLen ) {
				verbose_print ( "netSys ERROR: Event recv length %d does not match expected %d.", mEvent.mDataLen + hsz, mEventLen + hsz);
			}
			// Push completed event to the queue
			#ifdef PROFILE_NET
				PERF_PUSH ( "queue" );
			#endif
			netQueueEvent ( mEvent );
			#ifdef PROFILE_NET
				PERF_POP();
			#endif

			// Delete event
			#ifdef PROFILE_NET
				PERF_PUSH ( "delete" );
			#endif
			delete_event ( mEvent );
			#ifdef PROFILE_NET
				PERF_POP();
			#endif

		} else {
			// Partial event..
			if ( !bDeserial )	{
				// not start of event, attach more data
				#ifdef PROFILE_NET
					PERF_PUSH ( "attach" );
				#endif
				mEvent.attachBuf ( mBufferPtr, mBufferLen );
				#ifdef PROFILE_NET
					PERF_POP ();
				#endif
			}
			mEventLen -= mBufferLen;
			mBufferPtr += mBufferLen;
			mBufferLen = 0;
		}
	}	// end while
	
	// TRACE_EXIT ( (__func__) );
	return mBufferLen;
}

// Put event onto Event Queue
void NetworkSystem::netQueueEvent ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	Event eq;
	eq = e;						// eq now owns the data
	eq.rescope ( "nets" );		
	mEventQueue.push ( eq );	// data payload is owned by queued event
	eq.bOwn = false;			// local ref no longer owns payload
	e.bOwn = false;				// source ref no longer owns payload
	TRACE_EXIT ( (__func__) );
}

// Sent Event over network
bool NetworkSystem::netSend ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	// find a fully-connected socket
	int sock = netFindOutgoingSocket ( true );
	if ( sock == -1 ) { 
		verbose_print ( "Unable to find outgoing socket." );
		netReportError ( 111 );		// return disconnection error
		TRACE_EXIT ( (__func__) );
		return false; 
	}

	//dbgprintf ( "%s send: name %s, len %d (%d data)\n", nameToStr(mHostType).c_str(), nameToStr(e->getName()).c_str(), e->getEventLength(), e->getDataLength() );

  NetSock& s = mSockets[sock];
  redo_send:

	int result = netSend ( e, NET_CONNECT, sock );
	if ( result == SSL_ERROR_WANT_WRITE && s.security == 4 ) {
		//s.security = 0;
		//goto redo_send;
	}
	TRACE_EXIT ( (__func__) );
	return true;
}

Event NetworkSystem::netMakeEvent ( eventStr_t name, eventStr_t sys )
{
	TRACE_ENTER ( (__func__) );
	Event e = new_event ( 120, sys, name, 0, mEventPool  );
	e.setSrcIP ( mHostIP );		// default to local IP if protocol doesn't transmit sender
	e.setTarget ( 'net ' );		// all network configure events have a 'net ' target name
	e.setName ( name );
	e.startWrite ();
	e.bOwn = false;		// dont kill on destructor
	TRACE_EXIT ( (__func__) );
	return e;
}

// Find socket by mode & type
int NetworkSystem::netFindSocket ( int side, int mode, int type )
{
	TRACE_ENTER ( (__func__) );
	for (int n=0; n < mSockets.size(); n++) {
		if ( mSockets[n].mode == mode && mSockets[n].side == side && mSockets[n].src.type==type ) {
			TRACE_EXIT ( (__func__) );
			return n;
		}
	}
	TRACE_EXIT ( (__func__) );
	return -1;
}

// Find socket with specific destination
int NetworkSystem::netFindSocket ( int side, int mode, NetAddr dest )
{
	TRACE_ENTER ( (__func__) );
	for (int n=0; n < mSockets.size(); n++) {
		if ( mSockets[n].mode == mode && mSockets[n].side == side && mSockets[n].dest.type==dest.type &&
			 mSockets[n].dest.ipL == dest.ipL && mSockets[n].dest.port == dest.port ) {
				TRACE_EXIT ( (__func__) );
				return n;
		}
	}
	TRACE_EXIT ( (__func__) );
	return -1;
}

// Find first fully-connected outgoing socket
int NetworkSystem::netFindOutgoingSocket ( bool bTcp )
{
	TRACE_ENTER ( (__func__) );
	for (int n=0; n < mSockets.size(); n++) {
		if ( mSockets[n].mode==NET_TCP && mSockets[n].status==NET_CONNECTED ) {
			TRACE_EXIT ( (__func__) );
			return n;
		}
	}
	TRACE_EXIT ( (__func__) );
	return -1;
}
// Return true if any complete connection is valid
bool NetworkSystem::netIsConnected (int sock)
{
	TRACE_ENTER ( (__func__) );
	if (sock < 0 || sock >= mSockets.size()) { 
		TRACE_EXIT ( (__func__) );
		return false;
	}
	
	NetSock& s = mSockets[sock];

	// check connection was already made
	if ( s.status != NET_CONNECTED ) {
		TRACE_EXIT ( (__func__) );
		return false;
	}

	// confirm still connected - not sure how..
	/* char buf = 'k';
	if ( s.mode==NET_TCP ) {
		result = send ( s.socket, &buf, 1, 0 );		// TCP/IP
	} else {
		int addr_size = sizeof( s.dest.addr );
		result = sendto ( s.socket, &buf, 1, 0, (sockaddr*) &s.dest.addr, addr_size);		// UDP
	}*/
	
	TRACE_EXIT ( (__func__) );
	return true;
}


std::string NetworkSystem::netPrintAddr ( NetAddr adr )
{
	TRACE_ENTER ( (__func__) );
	char buf[128];
	std::string type;
	switch ( adr.type ) {
	case NET_ANY:			type = "any  ";	break;
	case NET_BROADCAST:		type = "broad";	break;
	case NET_SEARCH:		type = "srch";	break;
	case NET_CONNECT:		type = "conn";	break;
	};
	sprintf ( buf, "%s,%s:%d", type.c_str(), getIPStr(adr.ipL).c_str(), adr.port );
	TRACE_EXIT ( (__func__) );
	return buf;
}

void NetworkSystem::netPrint ( bool verbose )
{
	TRACE_ENTER ( (__func__) );
	if ( mPrintVerbose || verbose ) { // Print the network
		std::string side, mode, stat, src, dst, msg;
		dbgprintf ( "\n------ NETWORK SOCKETS. MyIP: %s, %s\n", mHostName.c_str(), getIPStr(mHostIP).c_str() );
		for (int n=0; n < mSockets.size(); n++) {
			side = (mSockets[n].side==NET_CLI) ? "cli" : "srv";
			mode = (mSockets[n].mode==NET_TCP) ? "tcp" : "udp";
			switch ( mSockets[n].status ) {
				case NET_OFF:		stat = "off      ";	break;
				case NET_ENABLE:	stat = "enable   "; break;
				case NET_CONNECTED:	stat = "connected"; break;
				case NET_TERMINATED: stat = "terminatd";	break;
			};
			src = netPrintAddr ( mSockets[n].src );
			dst = netPrintAddr ( mSockets[n].dest );
			msg = "";
			if (mSockets[n].side==NET_CLI && mSockets[n].status==NET_CONNECTED )
				msg = "<-- to Server";
			if (mSockets[n].side==NET_SRV && mSockets[n].status==NET_CONNECTED )
				msg = "<-- to Client";
			if (mSockets[n].side==NET_SRV && mSockets[n].status==NET_ENABLE && mSockets[n].src.ipL == 0 )
				msg = "<-- Server Listening Port";

			dbgprintf ( "%d: %s %s %s src[%s] dst[%s] %s\n", n, side.c_str(), mode.c_str(), stat.c_str(), src.c_str(), dst.c_str(), msg.c_str() );
		}
		dbgprintf ( "------\n");
	}
	TRACE_EXIT ( (__func__) );
}


//----------------------------------------------- NETWORK LOW-LEVEL SOCKETS
// This section provides platform-specific
// wrappers around the socket functions.
//

// start a low-level socket API
void NetworkSystem::netStartSocketAPI ()
{
	TRACE_ENTER ( (__func__) );
	FD_ZERO (&sock_set);

	#ifdef _MSC_VER

		// Winsock startup
		WSADATA WSAData;
		int status;
		if ( ( status = WSAStartup ( MAKEWORD ( 1,1 ), &WSAData ) ) == 0) {
			verbose_print ( "Started Winsock." );
		} else {
			netError ( "Unable to start Winsock.");
		}

	#else   

		// sockets lib, Linux & Android
		int sock;
		struct sockaddr_in serv_addr;
		char c;

		sock = (socket(AF_INET, SOCK_STREAM, 0));
		if ( sock == -1 ) {
			dbgprintf ( "  ERROR: Unable to create sockets.\n");
		}		
		dbgprintf ( "  Started BSD sockets.\n");

	#endif
	TRACE_EXIT ( (__func__) );
}

// get hostname
void NetworkSystem::netGetHostname ()
{
	TRACE_ENTER ( (__func__) );
	struct hostent *phe;
	struct in_addr addr;
	char name[512];

	if ( gethostname(name, sizeof(name)) != 0 ) {
		netError ( "Cannot get local host name." );
	}
   #ifdef _WIN32
	//----- NOTE: Host may have multiple interfaces (-Marty)
	// This is just to get one valid local IP address
	phe = gethostbyname( name );
	if (phe == 0) {
		netError ( "Bad host lookup in gethostbyname." );
	}
	for (int i = 0; phe->h_addr_list[i] != 0; ++i) {
		memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
                mHostIP = addr.S_un.S_addr;
	}
   #else
        int sock;
	struct ifreq ifreqs[20];
	struct ifconf ic;

	ic.ifc_len = sizeof (ifreqs);
	ic.ifc_req = ifreqs;

	sock = socket( AF_INET, SOCK_DGRAM, 0);
	if ( sock < 0 ) {
	  dbgprintf ( "netSys ERROR: Cannot create socket to get host name.\n" );
	}
	if ( ioctl ( sock, SIOCGIFCONF, &ic ) < 0 ) {
	  dbgprintf ( "netSys ERROR: Cannot do ioctl to get host name.\n" );
	}

       	for ( int i = 0; i  < ic.ifc_len / sizeof ( struct ifreq ); i++ ) {
	  netIP ip = (netIP) ((struct sockaddr_in*) &ifreqs[i].ifr_addr)->sin_addr.s_addr;
	  dbgprintf ( " %s: %s\n", ifreqs[i].ifr_name, getIPStr(ip).c_str() );
	  if ( ifreqs[i].ifr_name[0] != 'l' ) {  // skip loopback, get first eth0
	    mHostIP = ip;
	    break;
	  }
	}
    #endif
	mHostName = name;
	verbose_print ( "  Local Host: %s, %s", mHostName.c_str(), getIPStr(mHostIP).c_str() );
	TRACE_EXIT ( (__func__) );
}

bool NetworkSystem::netSendLiteral ( std::string str, int sock )
{
	TRACE_ENTER ( (__func__) );
	int len = str.length ( ), error;
	char* buf = (char*) malloc ( str.length ( ) + 1 );
	strcpy ( buf, str.c_str ( ) );	
	
	// send over socket
	int result;
	NetSock& s = mSockets [ sock ];
	if (mSockets [ sock ].mode == NET_TCP) {
		if ( s.security < 2 ) {
			result = send ( s.socket, buf, len, 0 ); // TCP/IP
		} else {
			#ifdef BUILD_OPENSSL
				result = SSL_write ( s.ssl, buf, len );
				if ( result <= 0 ) {	
					error = SSL_get_error ( s.ssl, result );
					if ( error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ) { 
						TRACE_EXIT ( (__func__) );
						return SSL_ERROR_WANT_WRITE;
					}
				}
			#endif
		} 
	}
	else {
		int addr_size = sizeof ( mSockets[ sock ].dest.addr );
		result = sendto ( s.socket, buf, len, 0, (sockaddr*)&s.dest.addr, addr_size );		// UDP
	}
	free( buf );
	TRACE_EXIT ( (__func__) );
	return netCheckError ( result, sock );		
}


bool NetworkSystem::netCheckError ( int result, int sock )
{
	TRACE_ENTER ( (__func__) );
	// error checking
	#ifdef _MSC_VER
	if ( result == SOCKET_ERROR ) {
	#else
	if ( result < 0 ) {
	#endif
		// peer has shutdown (unexpected shutdown)
		netTerminateSocket ( sock );
		netError ( "Unexpected shutdown." );
		TRACE_EXIT ( (__func__) );
		return false;
	}
	TRACE_EXIT ( (__func__) );
	return true;
}

// socket send()
bool NetworkSystem::netSend ( Event& e, int mode, int sock )
{
	TRACE_ENTER ( (__func__) );
	if ( sock == 0 ) {	// caller wishes to send on any outgoing socket
		sock = netFindOutgoingSocket ( true );
		if ( sock==-1 ) { 
			TRACE_EXIT ( (__func__) );
			return false;
		}
	}
	int result, error;
	e.rescope ( "nets" );

	if ( e.mData == 0x0 ) { 
		TRACE_EXIT ( (__func__) );
		return false;
	}

	// prepare serialized buffer
	e.serialize ( );
	char* buf = e.getSerializedData ( );
	int len = e.getSerializedLength ( );
	verbose_debug_print ( "send: %d bytes, %s", e.getSerializedLength ( ), e.getNameStr ( ).c_str ( ) );

	// send over socket
	NetSock& s = mSockets[sock];
	if ( mSockets[sock].mode==NET_TCP ) {
		if ( s.security < 2 ) {
			result = send ( s.socket, buf, len, 0 ); // TCP/IP
		} else {
			#ifdef BUILD_OPENSSL
				result = SSL_write ( s.ssl, buf, len );
				if ( result <= 0 ) {	
					error = SSL_get_error ( s.ssl, result );
					if ( error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ) { 
						TRACE_EXIT ( (__func__) );
						return SSL_ERROR_WANT_WRITE;
					}
				}
			#endif
		}  
	} else {
		int addr_size = sizeof( mSockets[ sock ].dest.addr );
		result = sendto ( s.socket, buf, len, 0, (sockaddr*) &s.dest.addr, addr_size); // UDP
	}
	// check connection
	TRACE_EXIT ( (__func__) );
	return netCheckError ( result, sock );
}

// update socket. handles all platform-specific address translation
int NetworkSystem::netUpdateSocket ( int sock )
{
	TRACE_ENTER ( (__func__) );
	int ret;
	NetSock& s = mSockets[sock];	    
	unsigned long ioval = (s.blocking ? 0 : 1);   // 0=blocking, 1=non-blocking
	int optval;

	if ( s.status==NET_OFF ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}

	//---- create socket
	if ( s.socket==0 ) {
		if ( s.mode==NET_TCP ) {
			s.socket = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP);		// TCP socket
		} else {
			s.socket = socket ( AF_INET, SOCK_DGRAM, IPPROTO_UDP);		// UDP socket
		}
	}

	//---- source address update
#ifdef _WIN32
	//---- Windows
	switch (s.src.type) {
	case NET_BROADCAST:	s.src.ip.S_un.S_addr = htonl(INADDR_BROADCAST);	optval = 1;	break;
	case NET_ANY:		s.src.ip.S_un.S_addr = htonl(INADDR_ANY); optval = 0;		break;
	case NET_CONNECT:	s.src.ip.S_un.S_addr = s.src.ipL; optval = 0;				break;
	};
	if ( s.src.type != NET_OFF ) {
		if ( s.broadcast )
			ret = setsockopt ( s.socket, SOL_SOCKET, SO_BROADCAST,  (const char*) &optval, sizeof(optval));		

		ioctlsocket ( s.socket, FIONBIO, &ioval);	// FIONBIO = non-blocking mode		
	}
#else
	//------ Linux/Other
	switch (s.mode) {
	case NET_BROADCAST: s.src.ip.s_addr =  htonl(INADDR_BROADCAST); optval = 1;	break;
	case NET_ANY:		s.src.ip.s_addr = htonl(INADDR_ANY); optval = 0;		break;
	case NET_CONNECT:	s.src.ip.s_addr = s.src.ipL; optval = 0;				break;
	}
	if ( s.src.type != NET_OFF ) {
		ret = setsockopt ( s.socket, SOL_SOCKET, SO_BROADCAST,  (const char*) &optval, sizeof(optval));
		//if ( ret < 0 ) netError ( "Cannot set socket opt" );
		ret = ioctl ( s.socket, FIONBIO, &ioval);
		//if ( ret < 0 ) netError ( "Cannot set socket ctrl" );
	}
#endif
	s.src.addr.sin_family = AF_INET;
	s.src.addr.sin_port = htons( s.src.port );
	s.src.addr.sin_addr = s.src.ip;
	memset (s.src.addr.sin_zero, 0, sizeof (s.src.addr.sin_zero));

	//---- dest address update
#ifdef _WIN32
	//---- Windows
	switch (s.dest.type) {
	case NET_BROADCAST:	s.dest.ip.S_un.S_addr = htonl(INADDR_BROADCAST); optval = 1;	break;
	case NET_ANY:		s.dest.ip.S_un.S_addr = htonl(INADDR_ANY); optval = 0;		break;
	case NET_CONNECT:	s.dest.ip.S_un.S_addr = s.dest.ipL; optval = 0;				break;
	};
	if ( s.dest.type != NET_OFF ) {
		if (s.broadcast)
			ret = setsockopt ( s.socket, SOL_SOCKET, SO_BROADCAST,  (const char*) &optval, sizeof(optval));		

		ioctlsocket ( s.socket, FIONBIO, &ioval);	 // FIONBIO = non-blocking mode		
	}
#else
	//------ Linux/Other
	switch (s.dest.type) {
	case NET_BROADCAST: s.dest.ip.s_addr =  htonl(INADDR_BROADCAST); optval = 1;	break;
	case NET_ANY:		s.dest.ip.s_addr = htonl(INADDR_ANY); optval = 0;		    break;
	case NET_CONNECT:	s.dest.ip.s_addr = s.dest.ipL; optval = 0;				    break;
	}
	if ( s.dest.type != NET_OFF ) {
		ret = setsockopt ( s.socket, SOL_SOCKET, SO_BROADCAST,  (const char*) &optval, sizeof(optval));
		//if ( ret < 0 ) netError ( "Cannot set socket opt" );

		ret = ioctl ( s.socket, FIONBIO, &ioval);
		//if ( ret < 0 ) netError ( "Cannot set socket ctrl" );
	}
#endif
	s.dest.addr.sin_family = AF_INET;
	s.dest.addr.sin_port = htons( s.dest.port );
	s.dest.addr.sin_addr = s.dest.ip;
	memset (s.dest.addr.sin_zero, 0, sizeof (s.dest.addr.sin_zero));
	
	TRACE_EXIT ( (__func__) );
	return 1;
}

// socket connect()
int NetworkSystem::netSocketConnect ( int sock )
{
	TRACE_ENTER ( (__func__) );
	NetSock* s = &mSockets[sock];
	int addr_size = sizeof ( s->dest.addr );
	int result;

	verbose_print ( "  %s connect: ip %s, port %i", (s->side==NET_CLI) ? "cli" : "srv", getIPStr(s->dest.ipL).c_str(), s->dest.port );

	result = connect ( s->socket, (sockaddr*) &s->dest.addr, addr_size );
	if (result < 0) {
		TRACE_EXIT ( (__func__) );
		return netError ( "Socket connect error." );
	}	
	TRACE_EXIT ( (__func__) );
	return 0;
}

// socket bind()
int NetworkSystem::netSocketBind ( int sock )
{
	TRACE_ENTER ( (__func__) );
	NetSock* s = &mSockets [ sock ];
	int addr_size = sizeof ( s->src.addr );
	verbose_print ( "Bind: %s, port %i", ( s->side==NET_CLI ) ? "cli" : "srv", s->src.port );
	int result = bind ( s->socket, (sockaddr*) &s->src.addr, addr_size );
	if ( netIsError(result) ) {
		netError ( "Cannot bind to source.");
	}
	TRACE_EXIT ( (__func__) );
	return result;
}


// socket accept()
int NetworkSystem::netSocketAccept ( int sock, SOCKET& tcp_sock, netIP& cli_ip, netPort& cli_port )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = mSockets [ sock ];
	struct sockaddr_in sin;
	int addr_size = sizeof ( sin );
	tcp_sock = accept ( s.socket, (sockaddr*) &sin, (socklen_t *) (&addr_size) );

#ifdef _WIN32
	if ( tcp_sock == INVALID_SOCKET ) {
#else
	if ( tcp_sock < 0) {
#endif
		netError ( "TCP Accept error" );
		TRACE_EXIT ( (__func__) );
		return -1;
	}
	
	cli_ip = sin.sin_addr.s_addr;		// IP address of connecting client
	cli_port = sin.sin_port;			// accepting TCP does not know/care what the client port is
	TRACE_EXIT ( (__func__) );
	return 1;
}

// socket listen()
int NetworkSystem::netSocketListen ( int sock )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = mSockets[sock];
	verbose_print ( "Listen: port %i", s.src.port );
	int result = listen ( s.socket, SOMAXCONN );

	#ifdef _WIN32
		if (result==SOCKET_ERROR) netError ( "TCP Listen error\n" );
	#else
		if (result<0) netError ( "TCP Listen error\n" );
	#endif
	TRACE_EXIT ( (__func__) );
	return result;
}

// socket recv()
// return value: success=0, or an error in errno.h.
// on success recvlen is set to bytes recieved
int NetworkSystem::netSocketRecv ( int sock, char* buf, int buflen, int& recvlen )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32
		int addr_size;
	#else
		socklen_t addr_size;
	#endif
	int result;
	NetSock& s = mSockets[sock];
	if ( s.src.type != NET_CONNECT ) {
		TRACE_EXIT ( (__func__) );
		return 0;		// recv only on connection sockets
	}

	addr_size = sizeof ( s.src.addr );
	if ( s.mode == NET_TCP ) {
		if ( s.security < 2 ) { // MP: on the else here is where the current issue is
			result = recv ( s.socket, buf, buflen, 0 );		// TCP/IP
		} else {
			#ifdef BUILD_OPENSSL
				result = SSL_read( s.ssl, buf, buflen );
				if ( result <= 0 ) {	
					if ( SSL_get_error ( s.ssl, result ) == SSL_ERROR_WANT_READ ) {
						TRACE_EXIT ( (__func__) );
						return SSL_ERROR_WANT_READ;
					}
				}
			#endif
		}
	} else {
		result = recvfrom ( s.socket, buf, buflen, 0, (sockaddr*) &s.src.addr, &addr_size );	// UDP
	}
	if ( result == 0 ) {
		netTerminateSocket ( sock ); // peer has unexpected shutdown
		netError ( "Unexpected shutdown");
		TRACE_EXIT ( (__func__) );
		return ECONNREFUSED;
	}	
	netCheckError ( result, sock ); // check connection
	recvlen = result;
	TRACE_EXIT ( (__func__) );
	return 0;
}

// API-specific error checking
int NetworkSystem::netError ( std::string msg, int error_id )
{
	TRACE_ENTER ( (__func__) );
	std::string error_str;	

	#ifdef _WIN32
	  // get error on windows
		if (error_id==0) {
			error_id = WSAGetLastError();		// windows get last error
		}		
		// proper way to retrieve error string on Windows
		LPTSTR errorText = NULL;
		FormatMessage ( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, error_id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &errorText, 0, NULL );
		error_str = std::string(errorText);
		LocalFree ( errorText );
		// gai_strerror();   //-- another way

	#else	
	  // get error on linux/android
		if (error_id==0) {
			error_id = errno;								// linux error code
		}
		char buf[2048];
		char* error_buf = (char*) strerror_r ( error_id, buf, 2048 );
		error_str = std::string(error_buf);
	#endif	

	verbose_print ( "  netSys ERROR: %s\n  %s (%d)\n", msg.c_str ( ), error_str.c_str ( ), error_id );
	TRACE_EXIT ( (__func__) );
	return error_id;
}

// API-specific check for error
bool NetworkSystem::netIsError ( int result )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32
		if ( result == SOCKET_ERROR ) { 
			TRACE_EXIT ( (__func__) );
			return true; // windows error
		}
	#else
		if ( result < 0 ) { 
			TRACE_EXIT ( (__func__) );
			return true; // linux/other error
		}
	#endif
	TRACE_EXIT ( (__func__) );
	return false;
}

std::string NetworkSystem::getIPStr ( netIP ip )
{
	TRACE_ENTER ( (__func__) );
	char ipname [ 1024 ];
	in_addr addr;
	#ifdef _MSC_VER
		addr.S_un.S_addr = ip;
	#else
		addr.s_addr = ip;
	#endif
	sprintf ( ipname, "%s", inet_ntoa ( addr ) );
	TRACE_EXIT ( (__func__) );
	return std::string ( ipname );
}

netIP NetworkSystem::getStrToIP ( std::string name )
{
	TRACE_ENTER ( (__func__) );
	char ipname [ 1024 ];
	strcpy ( ipname, name.c_str ( ) );
	TRACE_EXIT ( (__func__) );
	return inet_addr ( ipname );
}

/*void NetworkSystem::setMaxPacketLen ( int sock )
{
	TRACE_ENTER ( (__func__) );
	int optval;

	#ifdef _MSC_VER
		int optlen = sizeof(int);
		int result = getsockopt ( mSockList[sock]->GetSocket(), SOL_SOCKET, SO_MAX_MSG_SIZE, (char*) &optval, &optlen );
		mMaxPacketLen = optval;
	#else
		mMaxPacketLen = 65535;		// Upper limit for UDP. Not queryable with BSD sockets (?)
	#endif

	// dbgprintf ( "  net", "  Maximum UDP Packet Size: %d\n", mMaxPacketLen);
	TRACE_EXIT ( (__func__) );
}*/
