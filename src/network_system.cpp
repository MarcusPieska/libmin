//----------------------------------------------------------------------------------------------------------------------
//
// Network System
// Quanta Sciences, Rama Hoetzlein (c) 2007-2020
//
//----------------------------------------------------------------------------------------------------------------------

#include <assert.h>
#include <filesystem>
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

//----------------------------------------------------------------------------------------------------------------------
// TRACING FUNCTIONS
//----------------------------------------------------------------------------------------------------------------------

double NetworkSystem::get_time ( ) 
{
	TimeX current_time;
	current_time.SetTimeNSec ( );
	return current_time.GetElapsedSec ( m_refTime );
}

void NetworkSystem::trace_setup ( const char* function_name )
{
	m_trace = fopen ( function_name, "w" );
	if ( m_trace == 0 ) {
		debug_print ( "ERROR: Could not open trace file: Errno: ", errno );
		return;
	}
	m_refTime.SetTimeNSec ( );
	#ifdef __linux__
		chmod ( function_name, S_IRWXO ); 
	#endif
}

void NetworkSystem::trace_enter ( const char* function_name ) 
{
	if ( m_trace == 0 ) {
		debug_print ( "TRACE_EXIT: Trace file not yet opened: Call from: ", function_name );
		return;
	}
	str pad ( m_indentCount * 2, ' ' );
	fprintf ( m_trace, "%.9f:i:%s:%s\n", get_time ( ),  pad.c_str ( ), function_name );
	fflush ( m_trace );
	m_indentCount++;
}

void NetworkSystem::trace_exit ( const char* function_name )
{
	if ( m_trace == 0 ) {
		debug_print ( "TRACE_ENTER: Trace file not yet opened: Call from: ", function_name );
		return;
	}
	m_indentCount--;
	if ( m_indentCount < 0 ) {
		debug_print ( "TRACE_ENTER: Bad indent: Call from: ", function_name );
		m_indentCount = 0;
	}
	str pad ( m_indentCount * 2, ' ' );
	fprintf ( m_trace, "%.9f:o:%s:%s\n", get_time ( ), pad.c_str ( ), function_name );
	fflush ( m_trace );
}

void NetworkSystem::net_perf_push ( const char* msg )
{
	#ifdef PROFILE_NET
		PERF_PUSH ( msg );
	#endif
}

void NetworkSystem::net_perf_pop ( )
{
	#ifdef PROFILE_NET
		PERF_POP ( );
	#endif
}

//----------------------------------------------------------------------------------------------------------------------
// -> TRACING HOOKS <-
//----------------------------------------------------------------------------------------------------------------------

#define TRACE_FUNCTION_CALLS

#ifdef TRACE_FUNCTION_CALLS
	#define TRACE_SETUP(msg) trace_setup(msg)
	#define TRACE_ENTER(msg) trace_enter(msg)
	#define TRACE_EXIT(msg) trace_exit(msg)
	#define NET_PERF_PUSH(msg) net_perf_push(msg)
	#define NET_PERF_POP(msg) net_perf_pop()
#else 
	#define TRACE_SETUP(msg) (void)0
	#define TRACE_ENTER(msg) (void)0
	#define TRACE_EXIT(msg) (void)0
	#define NET_PERF_PUSH(msg) (void)0
	#define NET_PERF_POP(msg) (void)0
#endif 

//----------------------------------------------------------------------------------------------------------------------
// -> CROSS-COMPATIBILITY <-
//----------------------------------------------------------------------------------------------------------------------

inline void NetworkSystem::SET_HOSTNAME ( )
{
	TRACE_ENTER ( (__func__) );
	// NOTE: Host may have multiple interfaces, this is just to get one valid local IP address (-Marty)
	struct in_addr addr;
	char name [ 512 ];
	if ( gethostname ( name, sizeof ( name ) ) != 0 ) {
		netPrintError ( "Cannot get local host name." );
	}
	
	#ifdef _WIN32
		struct hostent* phe = gethostbyname ( name );
		if ( phe == 0 ) {
			netPrintError ( "Bad host lookup in gethostbyname." );
		}
		for ( int i = 0; phe->h_addr_list [ i ] != 0; ++i ) {
			memcpy ( &addr, phe->h_addr_list [ i ], sizeof ( struct in_addr ) );
			m_hostIp = addr.S_un.S_addr;
		}
	#else
		int sock_fd;
		struct ifreq ifreqs [ 20 ];
		struct ifconf ic;
		ic.ifc_len = sizeof ( ifreqs );
		ic.ifc_req = ifreqs;
		sock_fd = socket ( AF_INET, SOCK_DGRAM, 0 );
		if ( sock_fd < 0 ) {
			dbgprintf ( "netSys ERROR: Cannot create socket to get host name.\n" );
		}
		if ( ioctl ( sock_fd, SIOCGIFCONF, &ic ) < 0 ) {
			dbgprintf ( "netSys ERROR: Cannot do ioctl to get host name.\n" );
		}

		for ( int i = 0; i  < ic.ifc_len / sizeof ( struct ifreq ); i++ ) {
			netIP ip = (netIP) ((struct sockaddr_in*) &ifreqs[ i ].ifr_addr)->sin_addr.s_addr;
			dbgprintf ( " %s: %s\n", ifreqs[ i ].ifr_name, getIPStr ( ip ).c_str ( ) );
			if ( ifreqs[i].ifr_name [ 0 ] != 'l' ) {  // skip loopback, get first eth0
				m_hostIp = ip;
				break;
			}
		}
		close ( sock_fd );
    #endif
	m_hostName = name;
	TRACE_EXIT ( (__func__) );
}

inline void NetworkSystem::SOCK_API_INIT ( )
{
	TRACE_ENTER ( (__func__) );
	#if defined(_MSC_VER) || defined(_WIN32) // Winsock startup
		WSADATA WSAData;
		int status;
		if ( ( status = WSAStartup ( MAKEWORD ( 1,1 ), &WSAData ) ) == 0 ) {
			verbose_print ( "Started Winsock." );
		} else {
			netPrintError ( "Unable to start Winsock.");
		}
	#endif
	TRACE_EXIT ( (__func__) );
}

inline void NetworkSystem::SOCK_MAKE_BLOCK ( SOCKET sock_h, bool block )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32 // windows
		unsigned long block_mode = block ? 1 : 0; 
		ioctlsocket ( sock_h, FIONBIO, &block_mode ); // FIONBIO = non-blocking mode	
	#else // linux
		int flags = fcntl ( sock_h, F_GETFL, 0 );
		if ( flags == -1 ) {
			perror ( "get flags failed" );
			return;
			TRACE_EXIT ( (__func__) );
		} else {
			verbose_print ( "Call to get flags succeded" );
		}
		
		if ( block ) {
			flags &= ~O_NONBLOCK;
		} else {
			flags |= O_NONBLOCK;
		}

		if ( fcntl ( sock_h, F_SETFL, flags ) == -1 ) {
			perror ( "set blocking option failed" );
		} else {
			verbose_print ( "Call to set blocking succeded" );
		}
	#endif
	TRACE_EXIT ( (__func__) );
}

unsigned long NetworkSystem::SOCK_READ_BYTES ( SOCKET sock_h ) 
{   
	TRACE_ENTER ( (__func__) );
	unsigned long bytes_avail;
	#ifdef _WIN32 // windows
		if ( ioctlsocket ( sock_h, FIONREAD, &bytes_avail) == -1 ) {
			perror ( "ioctl FIONREAD" );
			bytes_avail = -1;
		} 
	#else		
	    int bytes_avail_int;
		if ( ioctl ( sock_h, FIONREAD, &bytes_avail_int ) == -1 ) {
			perror ( "ioctl FIONREAD" );
			bytes_avail = -1;
		} else {
			bytes_avail = (unsigned long) bytes_avail_int;
		}
	#endif    
	TRACE_EXIT ( (__func__) );
	return bytes_avail;
}

inline int NetworkSystem::SOCK_INVALID ( int sock )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32
		TRACE_EXIT ( (__func__) );
		return sock == SOCK_INVALIDET;
	#else
		TRACE_EXIT ( (__func__) );
		return sock < 0;
	#endif
}

inline int NetworkSystem::SOCK_ERROR ( int sock )
{
	TRACE_ENTER ( (__func__) );
	#if defined(_MSC_VER) || defined(_WIN32)
		TRACE_EXIT ( (__func__) );
		return sock == SOCKET_ERROR;
	#else
		TRACE_EXIT ( (__func__) );
		return sock < 0;
	#endif
}

str NetworkSystem::GET_ERROR_MSH ( int& error_id )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32 // get error on windows
		if ( error_id == 0 ) {
			error_id = WSAGetLastError ( ); // windows get last error
		}		
		LPTSTR errorText = NULL;
		DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
		DWORD lang_id = MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT );
		FormatMessage ( flags, NULL, error_id, lang_id, (LPSTR)&errorText, 0, NULL );
		str error_str = str ( errorText );
		LocalFree ( errorText );
	#else // get error on linux/android
		if (error_id == 0) {
			error_id = errno; // linux error code
		}
		char buf [ 2048 ];
		char* error_buf = (char*) strerror_r ( error_id, buf, 2048 );
		str error_str = str ( error_buf );
	#endif	
	TRACE_EXIT ( (__func__) );
	return error_str;
}

inline void NetworkSystem::SOCK_UPDATE_ADDR ( int sock_i, bool src )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];	   
	int optval = 0, ret;
	unsigned long ioval = ( s.blocking ? 0 : 1 ); // 0 = blocking, 1 = non-blocking
	#ifdef _WIN32 // Windows
		int case_key = ( src ) ? s.src.type : s.dest.type;
		switch ( case_key ) {
			case NTYPE_BROADCAST:		s.src.ip.S_un.S_addr = htonl( INADDR_BROADCAST ); 	optval = 1;	break;
			case NTYPE_ANY:			s.src.ip.S_un.S_addr = htonl( INADDR_ANY ); 		optval = 0;	break;
			case NTYPE_CONNECT:		s.src.ip.S_un.S_addr = s.src.ipL; 					optval = 0; break;
		};
		if ( s.src.type != STATE_NONE ) {
			if ( s.broadcast ) {
				ret = setsockopt ( s.socket, SOL_SOCKET, SO_BROADCAST,  (const char*) &optval, sizeof ( optval ) );	
			}
			ioctlsocket ( s.socket, FIONBIO, &ioval ); // FIONBIO = non-blocking mode		
		}
	#else // Linux and others
		int case_key = ( src ) ? s.mode : s.dest.type;
		switch ( case_key ) {
			case NTYPE_BROADCAST: 	s.src.ip.s_addr = htonl( INADDR_BROADCAST );		optval = 1; break;
			case NTYPE_ANY:			s.src.ip.s_addr = htonl( INADDR_ANY ); 				optval = 0;	break;
			case NTYPE_CONNECT:		s.src.ip.s_addr = s.src.ipL; 						optval = 0;	break;
		}
		if ( s.src.type != STATE_NONE ) {
			ret = setsockopt ( s.socket, SOL_SOCKET, SO_BROADCAST,  (const char*) &optval, sizeof ( optval ) );
			//if ( ret < 0 ) netPrintError ( "Cannot set socket opt" );
			ret = ioctl ( s.socket, FIONBIO, &ioval );
			//if ( ret < 0 ) netPrintError ( "Cannot set socket ctrl" );
		}
	#endif
	
	if ( src ) {
		s.src.addr.sin_family = AF_INET;
		s.src.addr.sin_port = htons ( s.src.port );
		s.src.addr.sin_addr = s.src.ip;
		memset ( s.src.addr.sin_zero, 0, sizeof ( s.src.addr.sin_zero ) );		
	} else {
		s.dest.addr.sin_family = AF_INET;
		s.dest.addr.sin_port = htons ( s.dest.port );
		s.dest.addr.sin_addr = s.dest.ip;
		memset ( s.dest.addr.sin_zero, 0, sizeof ( s.dest.addr.sin_zero ) );
	}
	TRACE_EXIT ( (__func__) );
}

inline void NetworkSystem::SOCK_CLOSE ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32
		shutdown ( sock_h, SD_BOTH );					
		closesocket ( sock_h );
	#else
		int err = 1;
		socklen_t len = sizeof ( err );
		if ( -1 == getsockopt ( sock_h, SOL_SOCKET, SO_ERROR, (char*)&err, &len ) ) {
			debug_print ( "getSO_ERROR" );
		}
		if ( err ) {
			errno = err;  
		}
		shutdown ( sock_h, SHUT_RDWR );				
		close ( sock_h );
	#endif
	TRACE_EXIT ( (__func__) );
}

inline str NetworkSystem::GET_IP_STR ( netIP ip )
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
	return str ( ipname );
}

//----------------------------------------------------------------------------------------------------------------------
// -> SMALL HELPER FUNCTIONS <-
//----------------------------------------------------------------------------------------------------------------------

template<typename... Args> void NetworkSystem::verbose_print ( const char* fmt, Args... args )
{
	str fmt_str ( fmt );
	fmt_str += "\n";
	if ( m_printVerbose ) {
		dbgprintf ( fmt_str.c_str ( ), args... );
	}
}

template<typename... Args> void NetworkSystem::debug_print ( const char* fmt, Args... args )
{
	str fmt_str ( fmt );
	fmt_str += "\n";
	if ( m_printDebugNet ) {
		dbgprintf  ( fmt_str.c_str ( ), args... );
	}
}

template<typename... Args> void NetworkSystem::handshake_print ( const char* fmt, Args... args )
{
	str fmt_str ( fmt );
	fmt_str += "\n";
	if ( m_printHandshake ) {
		dbgprintf ( fmt_str.c_str ( ), args... );
	}
}

template<typename... Args> void NetworkSystem::verbose_debug_print ( const char* fmt, Args... args )
{
	str fmt_str ( fmt );
	fmt_str += "\n";
	if ( m_printDebugNet && m_printVerbose ) {
		dbgprintf  ( fmt_str.c_str ( ), args... );
	}
}

//----------------------------------------------------------------------------------------------------------------------
// -> MAIN CODE <-
//----------------------------------------------------------------------------------------------------------------------

NetworkSystem::NetworkSystem ( )
{
	m_hostType = ' ';
	m_hostIp = 0;
	m_readyServices = 0;
	m_userEventCallback = 0;
	m_rcvSelectTimout.tv_sec = 0;
	m_rcvSelectTimout.tv_usec = 1e3;
	m_lastClientConnectCheck.SetTimeNSec ( );

	m_security = NET_SECURITY_PLAIN_TCP;
	m_tcpFallbackAllowed = true;
	m_pathPublicKey = str("");
	m_pathPrivateKey = str("");
	m_pathCertDir = str("");
	m_pathCertFile = str("");
	
	m_printVerbose = true;
	m_printDebugNet = true;
	m_printHandshake = true;
	m_trace = 0;
}

void NetworkSystem::sleep_ms ( int time_ms ) 
{    
	TRACE_ENTER ( (__func__) ); 
	TimeX t;
	t.SleepNSec ( time_ms * 1e6 );  
	TRACE_EXIT ( (__func__) );
}

unsigned long NetworkSystem::get_read_ready_bytes ( SOCKET sock_h ) 
{   
	TRACE_ENTER ( (__func__) ); 
	unsigned long bytes_avail = SOCK_READ_BYTES ( sock_h );
	TRACE_EXIT ( (__func__) );
	return bytes_avail;
}

void NetworkSystem::make_sock_no_delay ( SOCKET sock_h ) 
{
	TRACE_ENTER ( (__func__) );
	int no_delay = 1;
	if ( setsockopt ( sock_h, IPPROTO_TCP, TCP_NODELAY, (char *)&no_delay, sizeof ( no_delay ) ) < 0) {
		perror( "Call to no delay FAILED" );
	}  
	else {
		verbose_debug_print ( "Call to no delay succeded" );
	} 
	TRACE_EXIT ( (__func__) );
} 

void NetworkSystem::make_sock_block ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	SOCK_MAKE_BLOCK ( sock_h, true );
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::make_sock_non_block ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	SOCK_MAKE_BLOCK ( sock_h, false );
	TRACE_EXIT ( (__func__) );
}

bool NetworkSystem::invalid_socket_index ( int sock_i ) 
{
	return sock_i < 0 || sock_i >= m_socks.size ( );
}

//----------------------------------------------------------------------------------------------------------------------
//
// -> CLIENT & SERVER SPECIFIC CONNECTION MANAGEMENT <-
//
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// -> OPENSSL SERVER CONNECTION MANAGEMENT <-
//----------------------------------------------------------------------------------------------------------------------

#ifdef BUILD_OPENSSL
	
void NetworkSystem::free_openssl ( int sock_i ) 
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];
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

void NetworkSystem::netServerSetupHandshakeSSL ( int sock_i ) 
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];
	make_sock_no_delay ( s.socket );
	int ret = 0, exp;
	make_sock_non_block ( s.socket ); 
	s.security = NET_SECURITY_FAIL; // Assume failure until end of this function
	s.state = STATE_FAILED; 

	if ( ( s.ctx = SSL_CTX_new ( TLS_server_method ( ) ) ) == 0 ) {
		perror ( "get new ssl ctx failed" );
		free_openssl ( s.socket );
		TRACE_EXIT ( (__func__) );
		return;
	}

	dbgprintf ( "OpenSSL: %s\n", OPENSSL_VERSION_TEXT ); // Openssl version 

	exp = SSL_OP_SINGLE_DH_USE;
	if (((ret = SSL_CTX_set_options( s.ctx, exp )) & exp) != exp ) {
		perror( "set ssl option failed" );
		free_openssl ( sock_i );
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		handshake_print ( "Call to set ssl option succeded" );
	}

	if ( ( ret = SSL_CTX_set_default_verify_paths ( s.ctx ) ) <= 0 ) { // Set CA veryify locations for trusted certs
		netPrintError( ret, "Default verify paths failed" );
	} else {
		handshake_print ( "Call to default verify paths succeded" );
	}
	if ( ( ret = SSL_CTX_load_verify_locations ( s.ctx, m_pathCertFile.c_str ( ) , m_pathCertDir.c_str ( ) ) ) <= 0) {
		netPrintError ( ret, "Load verify locations failed" );
	} else {
		handshake_print ( "Call to load verify locations succeded" );
	}

	SSL_CTX_set_verify ( s.ctx, SSL_VERIFY_PEER, NULL );

	if ( ( ret = SSL_CTX_use_certificate_file ( s.ctx, m_pathPublicKey.c_str ( ), SSL_FILETYPE_PEM ) ) <= 0 ) {
		netPrintError ( ret, "Use certificate failed" );	
		free_openssl ( sock_i ); 
		TRACE_EXIT ( (__func__) );	
		return;
	} else {
		handshake_print ( "Call to use certificate succeded" );
	}

	if ( ( ret = SSL_CTX_use_PrivateKey_file ( s.ctx, m_pathPrivateKey.c_str ( ), SSL_FILETYPE_PEM ) ) <= 0 ) {
		netPrintError ( ret, "Use private key failed" );
		free_openssl ( sock_i ); 
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		handshake_print ( "Call to use private key succeded" );
	}

	s.ssl = SSL_new ( s.ctx );
	if ( SSL_set_fd ( s.ssl, s.socket ) <= 0 ) {
		perror( "set ssl fd failed" );
		free_openssl ( sock_i ); 
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		handshake_print ( "Call to set ssl fd succeded" );
	}
	
	s.security = NET_SECURITY_OPENSSL;
	s.state = STATE_SSL_HANDSHAKE;
	TRACE_EXIT ( (__func__) );
}
	      
void NetworkSystem::netServerAcceptSSL ( int sock_i ) 
{ 
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];	   
	int ret;
	if ( ( ret = SSL_accept ( s.ssl ) ) < 0 ) {
		if ( netCheckOpensslError ( sock_i, ret ) ) {
			handshake_print ( "Non-blocking call to ssl accept returned" );
			handshake_print ( "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
		} else {	
			netPrintError ( ret, "SSL_accept failed (1)", s.ssl );
			free_openssl ( sock_i ); 
			s.security = NET_SECURITY_FAIL;
		}
	} else if ( ret == 0 ) {
		handshake_print ( "Call to ssl accept failed (2)" );
		free_openssl ( sock_i );
		s.security = NET_SECURITY_FAIL;
	} else {
		handshake_print ( "Call to ssl accept succeded" );
		handshake_print ( "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
		s.state = STATE_CONNECTED;
	}
	if ( s.security == NET_SECURITY_FAIL ) {
		netHandshakeError ( sock_i );
	} else if ( s.state == STATE_CONNECTED ) {
		netServerCompleteConnection ( sock_i );
	}
	TRACE_EXIT ( (__func__) );
}
	
#endif

//----------------------------------------------------------------------------------------------------------------------
// -> TCP SERVER CONNECTION MANAGEMENT <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netStartServer ( netPort srv_port, int security )
{
	if ( m_trace == 0 ) {
		TRACE_SETUP (( "../trace-func-server" ));
	}
	
	TRACE_ENTER ( (__func__) );
	handshake_print ( "Start Server:" );
	m_hostType = 's';
	netIP srv_anyip = inet_addr ( "0.0.0.0" );
	
	NetAddr addr1 ( NTYPE_ANY, m_hostName, srv_anyip, srv_port );
	NetAddr addr2 ( NTYPE_BROADCAST, "", 0, srv_port );
	int srv_sock_i = netAddSocket ( NET_SRV, NET_TCP, STATE_START, false, addr1, addr2 );
	const char reuse = 1;
	if ( setsockopt( m_socks[ srv_sock_i ].socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof ( int ) ) < 0 ) {	
		handshake_print ( "netSys Error: Setting server socket as SO_REUSEADDR." );
	}
	if ( security != NET_SECURITY_UNDEF ) {
		m_socks[ srv_sock_i ].security = security;
	}
	
	netSocketBind ( srv_sock_i );
	netSocketListen ( srv_sock_i );	
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netServerAcceptClient ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	/* int srv_sock_svc = netFindSocket ( NET_SRV, NET_TCP, NTYPE_ANY ); // MP: Check that this is OK
	if ( srv_sock_svc == -1 ) {
		netPrintError ( 0, "Unable to find server listen socket." );
	} */

	str srv_name = m_socks[ sock_i ].src.name;
	netPort srv_port = m_socks[ sock_i ].src.port;
	netIP cli_ip = 0;
	netPort cli_port = 0;

	SOCKET sock_h;	// New literal socket
	int result = netSocketAccept ( sock_i, sock_h, cli_ip, cli_port );
	if ( result < 0 ) {
		verbose_print ( "Connection not accepted." );
		TRACE_EXIT ( (__func__) );
		return;
	}

	netIP srv_ip = m_hostIp; // Listen/accept on ANY address (0.0.0.0), final connection needs the server IP
	NetAddr addr1 ( NTYPE_CONNECT, srv_name, srv_ip, srv_port );
	NetAddr addr2 ( NTYPE_CONNECT, "", cli_ip, cli_port );
	int cli_sock_i = netAddSocket ( NET_SRV, NET_TCP, NTYPE_CONNECT, false, addr1, addr2 ); // Create new socket

	NetSock& s = m_socks[ cli_sock_i ];
	make_sock_non_block ( sock_h );
	s.security = m_socks[ sock_i ].security;
	s.socket = sock_h; // Assign literal socket
	s.dest.ipL = cli_ip; // Assign client IP
	s.dest.port = cli_port;	// Assign client port
	s.state = STATE_START;

	if ( s.security == NET_SECURITY_PLAIN_TCP ) { // Complete TCP or SSL connection
		netServerCompleteConnection ( cli_sock_i );
	}
	else if ( s.security == NET_SECURITY_OPENSSL ) {
		netServerSetupHandshakeSSL ( cli_sock_i );
		if ( s.security == NET_SECURITY_FAIL ) {
			netHandshakeError ( sock_i );
		}
	}
	TRACE_EXIT ( (__func__) ); 	
} 
	
void NetworkSystem::netServerCompleteConnection ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	int srv_sock_svc = netFindSocket ( NET_SRV, NET_TCP, NTYPE_ANY );
	if ( srv_sock_svc == -1 ) {
	   netPrintError ( 0, "Unable to find server listen socket." );
	}
	netPort srv_port = m_socks[ srv_sock_svc ].src.port;
	NetSock& s = m_socks [ sock_i ];
	s.state = STATE_CONNECTED; 

	Event e; 
	e = netMakeEvent ( 'sOkT', 0 );
	e.attachInt64 ( s.dest.ipL ); // Client IP
	e.attachInt64 ( s.dest.port ); // Client port assigned by server!
	e.attachInt64 ( m_hostIp ); // Server IP
	e.attachInt64 ( srv_port ); // Server port
	e.attachInt ( sock_i ); // Connection ID (goes back to the client)
	netSend ( e, NTYPE_CONNECT, sock_i ); // Send TCP connected event to client

	Event ue = new_event ( 120, 'app ', 'sOkT', 0, m_eventPool ); // Inform the user-app (server) of the event	
	ue.attachInt ( sock_i );
	ue.attachInt ( -1 ); // cli_sock not known
	ue.startRead ( );
	(*m_userEventCallback) ( ue, this ); // Send to application

	verbose_print ( "  %s %s: Accepted ip %s, port %i on port %d", (s.side == NET_CLI) ? "Client" : "Server", getIPStr(m_hostIp).c_str(), getIPStr(s.dest.ipL).c_str(), s.dest.port, s.src.port );
	netPrint ( );
	TRACE_EXIT ( (__func__) );
}

//----------------------------------------------------------------------------------------------------------------------
// -> OPENSSL CLIENT CONNECTION MANAGEMENT <-
//----------------------------------------------------------------------------------------------------------------------

#ifdef BUILD_OPENSSL
	
void NetworkSystem::netClientSetupHandshakeSSL ( int sock_i ) 
{ 
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	if ( s.ctx != 0 ) {
		free_openssl ( sock_i ); 
		handshake_print ( "Call to free old context made" );
	}
	
	int ret = 0, exp;
	make_sock_no_delay ( s.socket );
	make_sock_non_block ( s.socket ); 
	s.security = NET_SECURITY_FAIL; // Assume failure until end of this function
	s.state = STATE_FAILED; 
	
	#if OPENSSL_VERSION_NUMBER < 0x10100000L // Version 1.1
		SSL_load_error_strings();	 
		SSL_library_init();
	#else // version 3.0+
		OPENSSL_init_ssl ( OPENSSL_INIT_LOAD_SSL_STRINGS, NULL );
	#endif

	dbgprintf ( "OpenSSL: %s\n", OPENSSL_VERSION_TEXT ); // Openssl version 

	//s.bio = BIO_new_socket ( s.socket, BIO_NOCLOSE );

	s.ctx = SSL_CTX_new ( TLS_client_method ( ) );
	if ( !s.ctx ) {
		perror ( "ctx failed" );
		ERR_print_errors_fp ( stderr );
		free_openssl ( sock_i );
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		handshake_print ( "Call to ctx succeded" );
	}

	// Use TLS 1.2+ only, since we have custom client-server protocols
	SSL_CTX_set_min_proto_version ( s.ctx, TLS1_2_VERSION );
	SSL_CTX_set_max_proto_version ( s.ctx, TLS1_3_VERSION );
	SSL_CTX_set_verify ( s.ctx, SSL_VERIFY_PEER, NULL );

	if ( !SSL_CTX_load_verify_locations( s.ctx, m_pathPublicKey.c_str ( ), NULL ) ) {
		perror ( "load verify locations failed" );
		ERR_print_errors_fp ( stderr );
		free_openssl ( sock_i );
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		handshake_print ( "Call to load verify locations succeded" );
	}		

	s.ssl = SSL_new ( s.ctx );
	if ( !s.ssl ) {
		perror ( "ssl failed" );
		ERR_print_errors_fp ( stderr );
		free_openssl ( sock_i ); 
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		handshake_print ( "Call to ssl succeded" );
	}	

	if ( SSL_set_fd ( s.ssl, s.socket ) != 1 ) {
		perror ( "ssl set fd failed" );	
		free_openssl ( sock_i );
		TRACE_EXIT ( (__func__) ); 	
		return;
	} else {
		handshake_print ( "Call to ssl set fd succeded" );
	}	

	s.security = NET_SECURITY_OPENSSL;
	s.state = STATE_SSL_HANDSHAKE;
	TRACE_EXIT ( (__func__) );
}	

void NetworkSystem::netClientConnectSSL ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	ERR_clear_error ( );
	int ret = 0, exp;
	NetSock& s = m_socks[ sock_i ];
	if ( ( ret = SSL_connect ( s.ssl ) ) < 0 ) {
		if ( netCheckOpensslError ( sock_i, ret ) ) {
			handshake_print ( "Non-blocking call to ssl connect tentatively succeded" );
			handshake_print ( "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
		} else {
			handshake_print ( "Call to ssl connect failed (1)" );
			netPrintError ( ret, "SSL_connect failed (1)", s.ssl );	
			free_openssl ( sock_i ); 
			s.security = NET_SECURITY_FAIL;	
		}
	} else if ( ret == 0 ) {
		handshake_print ( "Call to ssl connect failed (2)" );
		free_openssl ( sock_i ); 
		s.security = NET_SECURITY_FAIL;	
	} else {
		handshake_print ( "Call to ssl connect succeded" );
		handshake_print ( "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
		s.state = STATE_CONNECTED;
	}
	if ( s.security == NET_SECURITY_FAIL ) {
		netHandshakeError ( sock_i );
	}
	TRACE_EXIT ( (__func__) );
}

#endif

//----------------------------------------------------------------------------------------------------------------------
// -> TCP CLIENT CONNECTION MANAGEMENT <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netStartClient ( netPort cli_port, str srv_addr )
{
	if ( m_trace == 0 ) {
		TRACE_SETUP (( "../trace-func-client" ));
	}
	
	TRACE_ENTER ( (__func__) );
	eventStr_t sys = 'net '; 
	m_hostType = 'c'; // Network System is running in client mode
	verbose_print ( "Start Client:" );

	struct HELPAPI NetAddr netAddr = NetAddr ( ); // Start a TCP listen socket on Client
	netAddr.convertIP ( ntohl ( inet_addr ( srv_addr.c_str ( ) ) ) );
	netAddr.ipL = inet_addr ( srv_addr.c_str ( ) );
	netAddSocket ( NET_CLI, NET_TCP, STATE_NONE, false, NetAddr ( NTYPE_ANY, m_hostName, m_hostIp, cli_port ), netAddr );
	TRACE_EXIT ( (__func__) );
}

int NetworkSystem::netClientConnectToServer ( str srv_name, netPort srv_port, bool block, int sock_i )
{
	TRACE_ENTER ( (__func__) );
	str cli_name;
	netIP cli_ip, srv_ip;
	int cli_port, cli_sock_svc, cli_sock_i, cli_sock, adjusted_security, connect_result;
	if ( VALID_INDEX ( sock_i ) ) {
		adjusted_security = m_socks[ sock_i ].security;
	} 

	int dots = 0; // Check server name for dots
	for ( int n = 0; n < srv_name.length ( ); n++ ) {
		if ( srv_name.at ( n ) == '.' ) dots++;
	}
	if ( srv_name.compare ( "localhost" ) == 0 ) { // Derver is localhost
		srv_ip = m_hostIp;
	} else if ( dots == 3 ) { // Three dots, translate srv_name to literal IP		
		srv_ip = getStrToIP ( srv_name );
	} else { // Fewer dots, lookup host name resolve the server address and port
		addrinfo* pAddrInfo;
		char portname[ 64 ];
		sprintf ( portname, "%d", srv_port );
		int result = getaddrinfo ( srv_name.c_str ( ), portname, 0, &pAddrInfo );
		if ( result != 0 ) {
			TRACE_EXIT ( (__func__) );
			return netPrintError ( "Unable to resolve server name: " + srv_name, result );
		}	
		
		char ipstr[ INET_ADDRSTRLEN ];
		for ( addrinfo* p = pAddrInfo; p != NULL; p = p->ai_next ) { // Translate addrinfo to IP string
			struct in_addr* addr;
			if ( p->ai_family == AF_INET ) {
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

	cli_sock_svc = netFindSocket ( NET_CLI, NET_TCP, NTYPE_ANY ); // Find a local TCP socket service
	cli_name = m_socks[ cli_sock_svc ].src.name;
	cli_port = m_socks[ cli_sock_svc ].src.port;
	cli_ip = m_hostIp;

	NetAddr srv_addr = NetAddr ( NTYPE_CONNECT, srv_name, srv_ip, srv_port ); // Find or create socket
	cli_sock_i = netFindSocket ( NET_CLI, NET_TCP, srv_addr );
	if ( cli_sock_i == NET_ERR ) { 
		NetAddr cli_addr = NetAddr ( NTYPE_CONNECT, cli_name, cli_ip, cli_port );
		cli_sock_i = netAddSocket ( NET_CLI, NET_TCP, STATE_START, block, cli_addr, srv_addr );
		if ( cli_sock_i == NET_ERR ) {	
			TRACE_EXIT ( (__func__) );		
			return netPrintError ( "Unable to add socket." );
		}
	}

	const char reuse = 1;
	NetSock& s = m_socks[ cli_sock_i ];
	s.srvAddr = srv_name;
	s.srvPort = srv_port;
	if ( VALID_INDEX ( sock_i ) ) {
		m_socks[ cli_sock_i ].security = adjusted_security;
		m_socks[ cli_sock_i ].srvPort = srv_port;
	} 
	
	if ( setsockopt ( s.socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof ( int ) ) < 0 ) {
		verbose_print ( "netSys: Setting server socket as SO_REUSEADDR." );
	}
	if ( s.state != STATE_CONNECTED ) { // Try to connect if needed
		connect_result = netSocketConnect ( cli_sock_i );
		if ( connect_result != 0 ) {
			netReportError ( connect_result );
		} 
	} else {
		s.reconnectBudget = s.reconnectLimit;
	}
	if ( s.security == NET_SECURITY_OPENSSL ) { // SSL handshake
		netClientSetupHandshakeSSL ( cli_sock_i );
		if ( s.security == NET_SECURITY_FAIL ) {	
			netHandshakeError ( cli_sock_i );
		}
	}
	TRACE_EXIT ( (__func__) );
	return cli_sock_i; // Return socket for this connection
}

//----------------------------------------------------------------------------------------------------------------------
//
// -> CLIENT & SERVER COMMON FUNCTIONS <-
//
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// -> CONNECTION MANAGEMENT <-
//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netIsConnectComplete ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	bool outcome = VALID_INDEX(sock_i) && m_socks[ sock_i ].state == STATE_CONNECTED;
	TRACE_EXIT ( (__func__) );
	return outcome;
}

int NetworkSystem::netCloseAll ( )
{
	TRACE_ENTER ( (__func__) );
	for ( int n = 0; n < m_socks.size ( ); n++ ) {
		netCloseConnection ( n );
	}
	netPrint( );
	TRACE_EXIT ( (__func__) );
	return 1;
}

int NetworkSystem::netCloseConnection ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	if ( sock_i < 0 || sock_i >= m_socks.size ( ) ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}
	NetSock& s = m_socks[ sock_i ];
	if ( s.side == NET_CLI ) {
		if ( s.mode == NTYPE_CONNECT ) { // Client informs server we are done		
			Event e = netMakeEvent ( 'sExT', 'net ' );
			e.attachUInt ( m_socks [ sock_i ].dest.sock );
			e.attachUInt ( sock_i ); 
			netSend ( e );
			netProcessQueue ( ); 
		}
	} else { 
		if ( s.mode == NTYPE_CONNECT ) { // Server inform client we are done
			int dest_sock = s.dest.sock;
			Event e = netMakeEvent ( 'cExT', 'net ' );
			e.attachUInt ( s.dest.sock ); 
			e.attachUInt ( sock_i ); 
			netSend ( e );
			netProcessQueue ( );
		}
	}
	netTerminateSocket ( sock_i ); // Terminate local socket	 
	TRACE_EXIT ( (__func__) );
	return 1;
}

#ifdef BUILD_OPENSSL

int NetworkSystem::netCheckOpensslError ( int sock, int ret ) 
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock ];
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

//----------------------------------------------------------------------------------------------------------------------
// -> CORE CODE <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netProcessEvents ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	switch ( e.getName ( ) ) {
		case 'sOkT': { // Received OK from server. connection complete.
			int cli_sock = e.getSrcSock ( ); // Client received accept from server
			netIP cli_ip = e.getInt64 ( ); // Get connection data from Event
			netPort cli_port = e.getInt64 ( );
			netIP srv_ip = e.getInt64 ( ); // Server given in Event payload
			int srv_port = e.getInt64 ( );
			int srv_sock = e.getInt ( );

			// Update client socket with server socket & client port
			m_socks[ cli_sock ].state = STATE_CONNECTED; // mark connected
			m_socks[ cli_sock ].dest.sock = srv_sock; // assign server socket
			m_socks[ cli_sock ].src.port = cli_port; // assign client port from server

			// Verify client and server IPs
			netIP srv_ip_chk = e.getSrcIP ( ); // source IP from the socket event came on
			netIP cli_ip_chk = m_socks[ cli_sock ].src.ipL; // original client IP

			Event e = new_event ( 120, 'app ', 'sOkT', 0, m_eventPool ); // Inform the user-app (client) of the event
			e.attachInt ( srv_sock );
			e.attachInt ( cli_sock );		
			e.startRead ( );
			(*m_userEventCallback) ( e, this ); // Send to application

			verbose_print ("  Client:   Linked TCP. %s:%d, sock: %d --> Server: %s:%d, sock: %d", getIPStr(cli_ip).c_str(), cli_port, cli_sock, getIPStr(srv_ip).c_str(), srv_port, srv_sock);
			netPrint ( );
			break;
		} 
		case 'sExT': { // Server recv, exit TCP from client. sEnT
			int local_sock = e.getUInt ( ); // Socket to close
			int remote_sock = e.getUInt ( ); // Remote socket
			netIP cli_ip = m_socks[ local_sock ].dest.ipL;
			verbose_print ( "  Server: Client closed ok. %s", getIPStr ( cli_ip ).c_str ( ) );
			netTerminateSocket ( local_sock );
			netPrint ( );
			break;
		}
	}
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netInitialize ( )
{
	TRACE_ENTER ( (__func__) );
	m_check = 0;
	verbose_print ( "Network Initialize." );
	m_eventPool = 0x0; // No event pooling
	netStartSocketAPI ( ); 
	netSetHostname ( ); 
	TRACE_EXIT ( (__func__) );
}

int NetworkSystem::netAddSocket ( int side, int mode, int state, bool block, NetAddr src, NetAddr dest )
{
	TRACE_ENTER ( (__func__) );
	NetSock s;
	s.sys = 'net ';
	s.side = side;
	s.mode = mode;
	s.state = state;
	s.src = src;
	s.dest = dest;
	s.socket = 0;
	s.timeout.tv_sec = 0; 
	s.timeout.tv_usec = 0;
	s.blocking = block;
	s.broadcast = 1;
	s.security = m_security; 
	s.reconnectBudget = s.reconnectLimit = m_reconnectLimit; 
	s.tcpFallback = m_tcpFallbackAllowed; 

	s.ctx = 0;
	s.ssl = 0;
	s.bio = 0;

	int n = m_socks.size ( );
	m_socks.push_back ( s );
	netSocketAdd ( n );
	TRACE_EXIT ( (__func__) );
	return n;
}

int NetworkSystem::netHandshakeError ( int sock_i ) 
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	int outcome = 0;
	if ( s.tcpFallback ) {
		s.security = NET_SECURITY_PLAIN_TCP;
		s.srvPort += 1;
	} else {
		outcome = netTerminateSocket ( sock_i, 1 );
	}
	TRACE_EXIT ( (__func__) );
	return outcome;
}

// Terminate Socket
// Note: This does not erase the socket from std::vector because we don't want to
// shift around the other socket IDs. Instead it disables the socket ID, making it available
// to another client later. Only the very last socket could be actually removed from list.

int NetworkSystem::netTerminateSocket ( int sock_i, int force )
{
	TRACE_ENTER ( (__func__) );
	if ( sock_i < 0 || sock_i >= m_socks.size ( ) ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}
	NetSock& s = m_socks[ sock_i ];
	verbose_print ( "netTerminating: %d", sock_i );
	if ( s.state != NTYPE_CONNECT && s.state != STATE_CONNECTED && force == 0 ) {
		 TRACE_EXIT ( (__func__) );
		 return 0;
	}
	if ( m_hostType == 'c' && s.reconnectBudget > 0 ) {
		s.state = STATE_START;
		if ( s.ctx != 0 ) {
			free_openssl ( sock_i ); 
			handshake_print ( "Call to free old context made (1)" );
		}
		SOCK_CLOSE ( s.socket );
		s.socket = 0;
		netSocketAdd ( sock_i );
		TRACE_EXIT ( (__func__) );
		return 0;	
	}
	
	SOCK_CLOSE ( s.socket );
	s.state = STATE_TERMINATED;
	
	// remove sockets at end of list
	// --- FOR NOW, THIS IS NECESSARY ON CLIENT (which may have only 1 socket),
	// BUT IN FUTURE CLIENTS SHOULD BE ABLE TO HAVE ANY NUMBER OF PREVIOUSLY TERMINATED SOCKETS
	if ( m_socks.size ( ) > 0 ) {
		while ( m_socks[ m_socks.size() -1 ].state == STATE_TERMINATED ) {
			m_socks.erase ( m_socks.end ( ) -1 );
		}
	}
	
	if ( m_hostType == 's' ) { // Inform the app; server noticed client terminated a socket
		Event e = new_event ( 120, 'app ', 'cFIN', 0, m_eventPool );
		e.attachInt ( sock_i );
		e.startRead ( );
		(*m_userEventCallback) (e, this); // Send to application
	} else { // Inform the app; client noticed server terminated a socket
		Event e = new_event ( 120, 'app ', 'sFIN', 0, m_eventPool );
		e.attachInt ( sock_i );
		e.startRead ( );
		(*m_userEventCallback) (e, this); // Send to application
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
		if ( m_userEventCallback != 0x0 ) {				// pass user events to application
			TRACE_EXIT ( (__func__) );
			return (*m_userEventCallback) ( e, this );
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
	(*m_userEventCallback) ( e, this );
	TRACE_EXIT ( (__func__) );
}

str NetworkSystem::netPrintError ( int ret, str msg, SSL* sslsock ) 
{		 
	TRACE_ENTER ( (__func__) );
	msg = "ERROR: " + msg + "\n ";

	// append, error code for SSL socket
	#ifdef BUILD_OPENSSL
		if ( sslsock != 0x0 ) { 	
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
	 char buf[ 512 ];
	 unsigned long err = ERR_get_error ( );
	 if ( err==0 ) {
		 msg += "No additional SSL error info.\n";
	 } else {
		 while ( err != 0 ) {
			 ERR_error_string ( err, buf );
			 msg += str ( buf ) + "\n ";
			 err = ERR_get_error ( );
		 }	 
	 }
	#endif
	
	debug_print ( "%s\n", msg.c_str ( ) );
	TRACE_EXIT ( (__func__) );
	return msg;
}

//----------------------------------------------------------------------------------------------------------------------
// -> PRIMARY ENTRY POINT <-
//----------------------------------------------------------------------------------------------------------------------

int NetworkSystem::netProcessQueue ( void )
{
	// TRACE_ENTER ( (__func__) );	
	if ( m_socks.size ( ) > 0 ) {
		if ( m_hostType == 'c' ) {
			netClientCheckConnectionHandshakes ( );
			netClientProcessIO ( );
		} else {
			netServerProcessIO ( );
		}
	}
	int iOk = 0; // Handle incoming events on queue
	while ( m_eventQueue.size ( ) > 0 ) {
		Event e = m_eventQueue.front ( );
		e.startRead ( );
		iOk += netEventCallback ( e ); // Count each user event handled ok
		m_eventQueue.pop ( ); // Pop causes event & payload deletion!
		e.bOwn = false;
	}
	// TRACE_EXIT ( (__func__) );
	return iOk;
}

//----------------------------------------------------------------------------------------------------------------------
// -> RECIEVE CODE <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netClientCheckConnectionHandshakes ( )
{
	TRACE_ENTER ( (__func__) );
	TimeX current_time;
	current_time.SetTimeNSec ( );	
	if ( current_time.GetElapsedMSec ( m_lastClientConnectCheck ) > m_reconnectInterval ) {
		m_lastClientConnectCheck.SetTimeNSec ( );
		for ( int sock_i = 1; sock_i < (int) m_socks.size ( ); sock_i++ ) {
			NetSock& s = m_socks[ sock_i ];
			if ( s.security == NET_SECURITY_OPENSSL && s.state == STATE_SSL_HANDSHAKE ) {
				netClientConnectSSL ( sock_i ); // This call is MORE important than the other
			}
			else if ( ( s.state != STATE_CONNECTED ) && s.reconnectBudget > 0 ) {	
				s.reconnectBudget--;
				netClientConnectToServer ( s.srvAddr, s.srvPort, false, sock_i ); // If disconnected, try and reconnect
			}
		}
	}
	TRACE_EXIT ( (__func__) );
}
	
	
void NetworkSystem::netClientProcessIO ( )
{
	TRACE_ENTER ( (__func__) );
	fd_set sockSet;
	int rcv_events = netSocketSelectRead ( &sockSet );
	NET_PERF_PUSH ( "findsocks" );
	for ( int sock_i = 0; sock_i < (int) m_socks.size ( ); sock_i++ ) { 
		if ( netSocketSetForRead ( &sockSet, sock_i ) ) {
			NetSock& s = m_socks[ sock_i ];
			if ( s.security == NET_SECURITY_PLAIN_TCP || s.state == STATE_CONNECTED ) {
				netRecieveData ( sock_i );
			} else if ( s.security == NET_SECURITY_OPENSSL && s.state == STATE_SSL_HANDSHAKE ) {
				netClientConnectSSL ( sock_i ); // This call is LESS important than the other
			}
		}
	}
	NET_PERF_POP ( );
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netServerProcessIO ( )
{
	TRACE_ENTER ( (__func__) );
	fd_set sockSet;
	int rcv_events = netSocketSelectRead ( &sockSet );
	NET_PERF_PUSH ( "findsocks" );
	for ( int sock_i = 0; sock_i < (int) m_socks.size ( ); sock_i++ ) { 
		NetSock& s = m_socks[ sock_i ];
		if ( netSocketSetForRead ( &sockSet, sock_i ) ) {
			if ( s.src.type == NTYPE_ANY ) { // Listen for TCP connections on socket
				netServerAcceptClient ( sock_i );
			} else {
				if ( s.security == NET_SECURITY_PLAIN_TCP || s.state == STATE_CONNECTED ) {
					netRecieveData ( sock_i );
				} else {
					netServerAcceptSSL ( sock_i );
				}
			}
		}
	}
	NET_PERF_POP ( );
	TRACE_EXIT ( (__func__) );
}

int NetworkSystem::netRecieveData ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	NET_PERF_PUSH ( "recv" ); // Receive incoming data on socket
	int result = netSocketRecv ( sock_i, m_buffer, NET_BUFSIZE-1, m_bufferLen );
	if ( result != 0 || m_bufferLen == 0 ) {
		netReportError ( result ); // Recv failed. Report net error
		TRACE_EXIT ( (__func__) );
		return 0;
	}
	NET_PERF_POP ( );

	m_bufferPtr = &m_buffer[ 0 ];
	bool bDeserial;
	while ( m_bufferLen > 0 ) {
		if ( m_event.isEmpty ( ) ) { // Check the type of incoming socket
			if (m_socks[ sock_i ].blocking) {
				// Blocking socket. NOT an Event socket. Attach arbitrary data onto a new event.
				m_eventLen = m_bufferLen;
				m_event = new_event(m_eventLen + 128, 'app ', 'HTTP', 0, m_eventPool);
				m_event.rescope( "nets" );
				m_event.attachInt( m_bufferLen ); // attachInt+Buf = attachStr
				m_event.attachBuf( m_bufferPtr, m_bufferLen );
				m_dataLen = m_event.mDataLen;
			} else {
				// Non-blocking socket. Receive a complete Event.
				// directly read length-of-event info from incoming data (m_dataLen value)
				m_dataLen = *((int*) (m_bufferPtr + Event::staticOffsetLenInfo ( ) ));

				// compute total event length, including header
				m_eventLen = m_dataLen + Event::staticSerializedHeaderSize ( );

				// Event is allocated with no name/target as this will be set during deserialize
				NET_PERF_PUSH ( "newevent" );
				m_event = new_event ( m_dataLen, 0, 0, 0, m_eventPool );
				NET_PERF_POP ( );
				m_event.rescope ( "nets" ); // Belongs to network now

				// Deserialize of actual buffer length (EventLen or BufferLen)
				NET_PERF_PUSH ( "header" );
				m_event.deserialize ( m_bufferPtr, imin(m_eventLen, m_bufferLen ) ); // Deserialize header
				NET_PERF_POP ( );
			}
			m_event.setSrcSock ( sock_i );		// <--- tag event /w socket
			m_event.setSrcIP ( m_socks[ sock_i ].src.ipL ); // recover sender address from socket
			bDeserial = true;

		} else { // More data for existing Event..
			bDeserial = false;
		}

		// BufferLen = actual bytes received at this time (may be partial)
		// EventLen = size of event in *network*, serialized event including data payload
		//    bufferLen > eventLen      multiple events
		//    bufferLen = eventLen      one event, or end of event
		//    bufferLen < eventLen 			part of large event

		if ( m_bufferLen >= m_eventLen ) { // One event, multiple, or end of large event..
			if ( ! bDeserial )	{ // Not start of event, attach more data
				NET_PERF_PUSH ( "attach" );
				m_event.attachBuf ( m_bufferPtr, m_bufferLen );
				NET_PERF_POP ( );
			}
			// End of event
			m_bufferLen -= m_eventLen; // Advance buffer
			m_bufferPtr += m_eventLen;
			m_eventLen = 0;
			int hsz = Event::staticSerializedHeaderSize();
			verbose_debug_print ( "recv: %d bytes, %s", m_event.mDataLen + hsz, m_event.getNameStr().c_str() );
			
			if ( m_event.mDataLen != m_dataLen ) { // Confirm final size received matches indicated payload size
				verbose_print ( "netSys ERROR: Event recv length %d does not match expected %d.", m_event.mDataLen + hsz, m_eventLen + hsz);
			}
			NET_PERF_PUSH ( "queue" );
			netQueueEvent ( m_event );
			NET_PERF_POP ( );
			NET_PERF_PUSH ( "delete" );
			delete_event ( m_event );
			NET_PERF_POP ( );

		} else { // Partial event..
			if ( ! bDeserial ) { // Not start of event, attach more data
				NET_PERF_PUSH ( "attach" );
				m_event.attachBuf ( m_bufferPtr, m_bufferLen );
				NET_PERF_POP ( );
			}
			m_eventLen -= m_bufferLen;
			m_bufferPtr += m_bufferLen;
			m_bufferLen = 0;
		}
	} // end while

	TRACE_EXIT ( (__func__) );
	return m_bufferLen;
}

//----------------------------------------------------------------------------------------------------------------------
// -> Send CODE <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netQueueEvent ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	Event eq;
	eq = e;						// eq now owns the data
	eq.rescope ( "nets" );		
	m_eventQueue.push ( eq );	// data payload is owned by queued event
	eq.bOwn = false;			// local ref no longer owns payload
	e.bOwn = false;				// source ref no longer owns payload
	TRACE_EXIT ( (__func__) );
}

bool NetworkSystem::netSend ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	int sock = netFindOutgoingSocket ( true ); // Find a fully-connected socket
	if ( sock == -1 ) { 
		verbose_print ( "Unable to find outgoing socket." );
		netReportError ( 111 ); // Return disconnection error
		TRACE_EXIT ( (__func__) );
		return false; 
	}

	//dbgprintf ( "%s send: name %s, len %d (%d data)\n", nameToStr(m_hostType).c_str(), nameToStr(e->getName()).c_str(), e->getEventLength(), e->getDataLength() );
	int result = netSend ( e, NTYPE_CONNECT, sock );
	TRACE_EXIT ( (__func__) );
	return true;
}

Event NetworkSystem::netMakeEvent ( eventStr_t name, eventStr_t sys )
{
	TRACE_ENTER ( (__func__) );
	Event e = new_event ( 120, sys, name, 0, m_eventPool  );
	e.setSrcIP ( m_hostIp );	// default to local IP if protocol doesn't transmit sender
	e.setTarget ( 'net ' );	// all network configure events have a 'net ' target name
	e.setName ( name );
	e.startWrite ();
	e.bOwn = false;	// dont kill on destructor
	TRACE_EXIT ( (__func__) );
	return e;
}

int NetworkSystem::netFindSocket ( int side, int mode, int type )
{
	TRACE_ENTER ( (__func__) );
	for ( int n = 0; n < m_socks.size ( ); n++ ) { // Find socket by mode & type
		if ( m_socks[ n ].mode == mode && m_socks[ n ].side == side && m_socks[ n ].src.type==type ) {
			TRACE_EXIT ( (__func__) );
			return n;
		}
	}
	TRACE_EXIT ( (__func__) );
	return -1;
}

int NetworkSystem::netFindSocket ( int side, int mode, NetAddr dest )
{
	TRACE_ENTER ( (__func__) );
	for ( int n = 0; n < m_socks.size ( ); n++ ) { // Find socket with specific destination
		if ( m_socks[ n ].mode == mode && m_socks[ n ].side == side && m_socks[ n ].dest.type == dest.type &&
			 m_socks[ n ].dest.ipL == dest.ipL && m_socks[ n ].dest.port == dest.port ) {
				TRACE_EXIT ( (__func__) );
				return n;
		}
	}
	TRACE_EXIT ( (__func__) );
	return -1;
}

int NetworkSystem::netFindOutgoingSocket ( bool bTcp )
{
	TRACE_ENTER ( (__func__) );
	for ( int n=0; n < m_socks.size ( ); n++ ) { // Find first fully-connected outgoing socket
		if ( m_socks[ n ].mode==NET_TCP && m_socks[ n ].state == STATE_CONNECTED ) {
			TRACE_EXIT ( (__func__) );
			return n;
		}
	}
	TRACE_EXIT ( (__func__) );
	return -1;
}

str NetworkSystem::netPrintAddr ( NetAddr adr )
{
	TRACE_ENTER ( (__func__) );
	char buf[128];
	str type;
	switch ( adr.type ) {
	case NTYPE_ANY:			type = "any  ";	break;
	case NTYPE_BROADCAST:		type = "broad";	break;
	case NTYPE_SEARCH:		type = "srch";	break;
	case NTYPE_CONNECT:		type = "conn";	break;
	};
	sprintf ( buf, "%s,%s:%d", type.c_str(), getIPStr(adr.ipL).c_str(), adr.port );
	TRACE_EXIT ( (__func__) );
	return buf;
}

void NetworkSystem::netPrint ( bool verbose )
{
	TRACE_ENTER ( (__func__) );
	if ( m_printVerbose || verbose ) { // Print the network
		str side, mode, stat, src, dst, msg;
		dbgprintf ( "\n------ NETWORK SOCKETS. MyIP: %s, %s\n", m_hostName.c_str ( ), getIPStr ( m_hostIp ).c_str ( ) );
		for ( int n = 0; n < m_socks.size ( ); n++ ) {
			side = ( m_socks[ n ].side == NET_CLI ) ? "cli" : "srv";
			mode = ( m_socks[ n ].mode == NET_TCP ) ? "tcp" : "udp";
			switch ( m_socks[ n ].state ) {
				case STATE_NONE:		stat = "off      ";	break;
				case STATE_START:	stat = "enable   "; break;
				case STATE_CONNECTED:	stat = "connected"; break;
				case STATE_TERMINATED: stat = "terminatd"; break;
			};
			src = netPrintAddr ( m_socks[n].src );
			dst = netPrintAddr ( m_socks[n].dest );
			msg = "";
			if ( m_socks[ n ].side==NET_CLI && m_socks[ n ].state == STATE_CONNECTED )
				msg = "<-- to Server";
			if ( m_socks[ n ].side==NET_SRV && m_socks[ n ].state == STATE_CONNECTED )
				msg = "<-- to Client";
			if ( m_socks[ n ].side==NET_SRV && m_socks[ n ].state == STATE_START && m_socks[ n ].src.ipL == 0 )
				msg = "<-- Server Listening Port";

			dbgprintf ( "%d: %s %s %s src[%s] dst[%s] %s\n", n, side.c_str(), mode.c_str(), stat.c_str(), src.c_str(), dst.c_str(), msg.c_str() );
		}
		dbgprintf ( "------\n");
	}
	TRACE_EXIT ( (__func__) );
}

//----------------------------------------------------------------------------------------------------------------------
// -> LOW-LEVEL WRAPPER <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netStartSocketAPI ( )
{
	TRACE_ENTER ( (__func__) );
	SOCK_API_INIT ( );
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netSetHostname ()
{
	TRACE_ENTER ( (__func__) );
	SET_HOSTNAME ( );
	verbose_print ( "  Local Host: %s, %s", m_hostName.c_str ( ), getIPStr ( m_hostIp ).c_str ( ) );
	TRACE_EXIT ( (__func__) );
}

bool NetworkSystem::netSendLiteral ( str str_lit, int sock )
{
	TRACE_ENTER ( (__func__) );
	int len = str_lit.length ( ), error, result;
	char* buf = (char*) malloc ( str_lit.length ( ) + 1 );
	strcpy ( buf, str_lit.c_str ( ) );	
	
	NetSock& s = m_socks [ sock ]; // Send over socket
	if ( m_socks [ sock ].mode == NET_TCP ) {
		if ( s.state < STATE_SSL_HANDSHAKE || s.security == NET_SECURITY_PLAIN_TCP ) {
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
		int addr_size = sizeof ( m_socks[ sock ].dest.addr );
		result = sendto ( s.socket, buf, len, 0, (sockaddr*)&s.dest.addr, addr_size ); // UDP
	}
	free( buf );
	TRACE_EXIT ( (__func__) );
	return netCheckError ( result, sock );		
}

bool NetworkSystem::netCheckError ( int result, int sock )
{
	TRACE_ENTER ( (__func__) );
	if ( SOCK_ERROR ( result ) ) {
		netTerminateSocket ( sock ); // peer has shutdown (unexpected shutdown)
		netPrintError ( "Unexpected shutdown." );
		TRACE_EXIT ( (__func__) );
		return false;
	}
	TRACE_EXIT ( (__func__) );
	return true;
}

bool NetworkSystem::netSend ( Event& e, int mode, int sock_i )
{
	TRACE_ENTER ( (__func__) );
	if ( sock_i == 0 ) { // Caller wishes to send on any outgoing socket
		sock_i = netFindOutgoingSocket ( true );
		if ( sock_i == -1 ) { 
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

	e.serialize ( ); // Prepare serialized buffer
	char* buf = e.getSerializedData ( );
	int len = e.getSerializedLength ( );
	verbose_debug_print ( "send: %d bytes, %s", e.getSerializedLength ( ), e.getNameStr ( ).c_str ( ) );

	NetSock& s = m_socks[ sock_i ];
	if ( m_socks[ sock_i ].mode == NET_TCP ) { // Send over socket
		if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) {
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
		int addr_size = sizeof( m_socks[ sock_i ].dest.addr );
		result = sendto ( s.socket, buf, len, 0, (sockaddr*) &s.dest.addr, addr_size ); // UDP
	}
	TRACE_EXIT ( (__func__) );
	return netCheckError ( result, sock_i ); // Check connection
}

int NetworkSystem::netSocketAdd ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];	    
	if ( s.state == STATE_NONE ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}
	if ( s.socket == 0 ) {
		if ( s.mode == NET_TCP ) {
			s.socket = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP ); 
		} else {
			s.socket = socket ( AF_INET, SOCK_DGRAM, IPPROTO_UDP ); 
		}
	}
	SOCK_UPDATE_ADDR ( sock_i, true );
	SOCK_UPDATE_ADDR ( sock_i, false );
	TRACE_EXIT ( (__func__) );
	return 1;
}

int NetworkSystem::netSocketBind ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock* s = &m_socks [ sock_i ];
	int addr_size = sizeof ( s->src.addr );
	verbose_print ( "Bind: %s, port %i", ( s->side==NET_CLI ) ? "cli" : "srv", s->src.port );
	int result = bind ( s->socket, (sockaddr*) &s->src.addr, addr_size );
	if ( netIsError(result) ) {
		netPrintError ( "Cannot bind to source.");
	}
	TRACE_EXIT ( (__func__) );
	return result;
}

int NetworkSystem::netSocketConnect ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock* s = &m_socks[ sock_i ];
	int addr_size = sizeof ( s->dest.addr );
	int result;

	verbose_print ( "  %s connect: ip %s, port %i", (s->side==NET_CLI) ? "cli" : "srv", getIPStr(s->dest.ipL).c_str(), s->dest.port );

	result = connect ( s->socket, (sockaddr*) &s->dest.addr, addr_size );
	if (result < 0) {
		TRACE_EXIT ( (__func__) );
		return netPrintError ( "Socket connect error." );
	}	
	TRACE_EXIT ( (__func__) );
	return 0;
}

int NetworkSystem::netSocketListen ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];
	verbose_print ( "Listen: port %i", s.src.port );
	int result = listen ( s.socket, SOMAXCONN );
	if ( SOCK_ERROR ( result ) ) {
		netPrintError ( "TCP Listen error\n" );
	}
	TRACE_EXIT ( (__func__) );
	return result;
}

int NetworkSystem::netSocketAccept ( int sock_i, SOCKET& tcp_sock, netIP& cli_ip, netPort& cli_port )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];
	struct sockaddr_in sin;
	int addr_size = sizeof ( sin );
	tcp_sock = accept ( s.socket, (sockaddr*) &sin, (socklen_t *) (&addr_size) );

	if ( SOCK_INVALID ( tcp_sock ) ) {
		netPrintError ( "TCP Accept error" );
		TRACE_EXIT ( (__func__) );
		return -1;
	}
	
	cli_ip = sin.sin_addr.s_addr; // IP address of connecting client
	cli_port = sin.sin_port; // Accepting TCP does not know/care what the client port is
	TRACE_EXIT ( (__func__) );
	return 1;
}

int NetworkSystem::netSocketRecv ( int sock_i, char* buf, int buflen, int& recvlen )
{
	TRACE_ENTER ( (__func__) ); // Return value: success = 0, or an error number; on success recvlen = bytes recieved
	socklen_t addr_size;
	int result;
	NetSock& s = m_socks [ sock_i ];
	if ( s.src.type != NTYPE_CONNECT ) {
		TRACE_EXIT ( (__func__) );
		return 0; // Only recv on connection sockets
	}
	
	addr_size = sizeof ( s.src.addr );
	if ( s.mode == NET_TCP ) {
		if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) { 
			result = recv ( s.socket, buf, buflen, 0 );	// TCP/IP
		} else {
			#ifdef BUILD_OPENSSL
				result = SSL_read( s.ssl, buf, buflen );
				if ( result <= 0 ) {	
					int ssl_error = SSL_get_error ( s.ssl, result );
					ERR_print_errors_fp ( stdout );
					if ( ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE ) {
						TRACE_EXIT ( (__func__) );
						return SSL_ERROR_WANT_READ;
					}
				}
			#endif
		}
	} else {
		result = recvfrom ( s.socket, buf, buflen, 0, (sockaddr*) &s.src.addr, &addr_size ); // UDP
	}
	if ( result == 0 ) {
		netTerminateSocket ( sock_i ); // Peer has unexpected shutdown
		netPrintError ( "Unexpected shutdown", result );
		TRACE_EXIT ( (__func__) );
		return ECONNREFUSED;
	}	
	netCheckError ( result, sock_i ); // Check connection
	recvlen = result;
	TRACE_EXIT ( (__func__) );
	return 0;
}

bool NetworkSystem::netSocketIsConnected ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
    fd_set sockSet;
    FD_ZERO ( &sockSet );
    FD_SET ( s.socket, &sockSet );
    struct timeval tv = { 0, 0 };
    int so_error = -1;
    if ( select ( s.socket + 1, NULL, &sockSet, NULL, &tv ) > 0 ) { 
        socklen_t len = sizeof ( so_error );
        getsockopt ( s.socket, SOL_SOCKET, SO_ERROR, &so_error, &len );
    } 
    TRACE_EXIT ( (__func__) );
    return so_error == 0; // Use select and result from getsockopt to check if connection is done
}

bool NetworkSystem::netSocketSetForRead ( fd_set* sockSet, int sock_i )
{
	NetSock& s = m_socks[ sock_i ];
	if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) { 
		return FD_ISSET ( s.socket, sockSet );
	} 
	#ifdef BUILD_OPENSSL
		return FD_ISSET ( SSL_get_fd ( s.ssl ), sockSet );
	#else
		return false;
	#endif
}

int NetworkSystem::netSocketSelectRead ( fd_set* sockSet ) 
{
	TRACE_ENTER ( (__func__) );
	if ( m_socks.size ( ) == 0 ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}

	int result, maxfd =- 1;
	NET_PERF_PUSH ( "socklist" );
	FD_ZERO ( sockSet );
	for ( int n = 0; n < (int) m_socks.size ( ); n++ ) { // Get all sockets that are Enabled or Connected
		NetSock& s = m_socks[ n ];
		if ( s.state != STATE_NONE && s.state != STATE_TERMINATED ) { // look for STATE_START or NTYPE_CONNECT
			if ( s.state < STATE_SSL_HANDSHAKE || s.security == NET_SECURITY_PLAIN_TCP ) { 
				FD_SET ( s.socket, sockSet );
				if ( (int) s.socket > maxfd ) maxfd = s.socket;
			} else { 
				#ifdef BUILD_OPENSSL
					int fd = SSL_get_fd ( s.ssl );
					FD_SET ( fd, sockSet );	
					if ( (int) fd > maxfd ) maxfd = fd;
				#endif
			}
		}
	}
	NET_PERF_POP ( );
	
	if ( ++maxfd == 0 ) {
		TRACE_EXIT ( (__func__) );
		return 0; // No sockets
	}

	NET_PERF_PUSH ( "select" );
	timeval tv;
    tv.tv_sec = m_rcvSelectTimout.tv_sec;
	tv.tv_usec = m_rcvSelectTimout.tv_usec;
	result = select ( maxfd, sockSet, NULL, NULL, &tv ); // Select all sockets that have changed
	NET_PERF_POP ( );
	TRACE_EXIT ( (__func__) );
	return result;
}

int NetworkSystem::netPrintError ( str msg, int error_id )
{
	TRACE_ENTER ( (__func__) );
	str error_str = GET_ERROR_MSH ( error_id );
	verbose_print ( "  netSys ERROR: %s\n  %s (%d)\n", msg.c_str ( ), error_str.c_str ( ), error_id );
	TRACE_EXIT ( (__func__) );
	return error_id;
}

bool NetworkSystem::netIsError ( int result )
{
	TRACE_ENTER ( (__func__) );
	if ( SOCK_ERROR ( result ) ) { 
		TRACE_EXIT ( (__func__) );
		return true; 
	}
	TRACE_EXIT ( (__func__) );
	return false;
}

str NetworkSystem::getIPStr ( netIP ip )
{
	TRACE_ENTER ( (__func__) );
	str ipstr = GET_IP_STR ( ip );
	TRACE_EXIT ( (__func__) );
	return ipstr;
}

netIP NetworkSystem::getStrToIP ( str name )
{
	TRACE_ENTER ( (__func__) );
	char ipname [ 1024 ];
	strcpy ( ipname, name.c_str ( ) );
	TRACE_EXIT ( (__func__) );
	return inet_addr ( ipname );
}

//----------------------------------------------------------------------------------------------------------------------
//
// -> PUBLIC CONFIG API <-
//
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// -> MISCELLANEOUS CONFIG API <-
//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netSetSelectInterval ( int time_ms ) 
{
	m_rcvSelectTimout.tv_sec = time_ms / 1000;
	m_rcvSelectTimout.tv_usec = ( time_ms % 1000 ) * 1000; 
}

//----------------------------------------------------------------------------------------------------------------------
// -> SECURITY CONFIG API <-
//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netSetReconnectInterval ( int time_ms )
{
	if ( m_hostType == 's' ) {
		return false;
	}
	m_reconnectInterval = time_ms;
	return true;
}

bool NetworkSystem::netSetReconnectLimit ( int limit )
{
	m_reconnectLimit = limit;
	return true;
}

bool NetworkSystem::netSetReconnectLimit ( int limit, int sock_i )
{
	if ( invalid_socket_index ( sock_i ) ) {
		return false;
	}
	m_socks[ sock_i ].reconnectLimit = limit;
	m_socks[ sock_i ].reconnectBudget = limit;
	return true;
}

//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netSetSecurityLevel ( int level )
{
	if ( level == NET_SECURITY_PLAIN_TCP ) {
		return netSetSecurityToPlainTCP ( );
	}
	if ( level == NET_SECURITY_OPENSSL ) {
		return netSetSecurityToOpenSSL ( );
	}
	return false;
}

bool NetworkSystem::netSetSecurityLevel ( int level, int sock_i )
{
	if ( level == NET_SECURITY_PLAIN_TCP ) {
		return netSetSecurityToPlainTCP ( sock_i );
	}
	if ( level == NET_SECURITY_OPENSSL ) {
		return netSetSecurityToOpenSSL ( sock_i );
	}
	return false;
}

//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netSetSecurityToPlainTCP ( )
{
	m_security = NET_SECURITY_PLAIN_TCP;
	return true;
}

bool NetworkSystem::netSetSecurityToPlainTCP ( int sock_i )
{
	if ( invalid_socket_index ( sock_i ) ) {
		return false;
	}
	m_socks[ sock_i ].security = NET_SECURITY_PLAIN_TCP;
	return true;
}

//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netSetSecurityToOpenSSL ( )
{
	#ifdef BUILD_OPENSSL
		m_security = NET_SECURITY_OPENSSL;
		return true;
	#else
		return false;
	#endif
}

bool NetworkSystem::netSetSecurityToOpenSSL ( int sock_i )
{
	if ( invalid_socket_index ( sock_i ) ) {
		return false;
	}
	#ifdef BUILD_OPENSSL
		m_socks[ sock_i ].security = NET_SECURITY_PLAIN_TCP;
		return true;
	#else
		return false;
	#endif
}

//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netAllowFallbackToPlainTCP ( bool allow )
{
	m_tcpFallbackAllowed = allow;
	return true;
}

bool NetworkSystem::netAllowFallbackToPlainTCP ( bool allow, int sock_i )
{
	if ( invalid_socket_index ( sock_i ) ) {
		return false;
	}
	m_socks[ sock_i ].tcpFallback = allow;
	return true;
}

//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netSetPathToPublicKey ( str path )
{
	if ( ! std::filesystem::is_regular_file ( path ) ) {
		debug_print ( "File path to public key is invalid: %s", path );
		return false;
	}
	m_pathPublicKey = path;
	return true;
}

bool NetworkSystem::netSetPathToPrivateKey ( str path )
{
	if ( ! std::filesystem::is_regular_file ( path ) ) {
		debug_print ( "File path to private key is invalid: %s", path );
		return false;
	}
	m_pathPrivateKey = path;
	return true;
}

bool NetworkSystem::netSetPathToCertDir ( str path )
{
	if ( ! std::filesystem::is_directory ( path ) ) {
		debug_print ( "Path to certificate folder is invalid: %s", path );
		return false;
	}
	m_pathCertDir = path;
	return true;
}

bool NetworkSystem::netSetPathToCertFile ( str path )
{
	if ( ! std::filesystem::is_regular_file ( path ) ) {
		debug_print ( "File path to certificate is invalid: %s", path );
		return false;
	}
	m_pathCertFile = path;
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
// -> END <-
//----------------------------------------------------------------------------------------------------------------------
