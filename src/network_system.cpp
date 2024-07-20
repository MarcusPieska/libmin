//----------------------------------------------------------------------------------------------------------------------
//
// Network System
// Quanta Sciences, Rama Hoetzlein (c) 2007-2020
//
//----------------------------------------------------------------------------------------------------------------------

#include <assert.h>


#include "network_system.h"

#ifdef __linux__
	#include <net/if.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h> 
	#include <sys/stat.h>
	#include <errno.h>    
#elif _WIN32
	#include <winsock2.h>
#elif __ANDROID__
	#include <net/if.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h> 
#endif

//#undef BUILD_OPENSSL

#ifdef BUILD_OPENSSL
	#include <openssl/opensslv.h>
	#include <openssl/crypto.h>
	#include <openssl/pem.h>
	#include <openssl/err.h>
	#include <openssl/md5.h>
	#include <openssl/ssl.h>	
	#include <openssl/x509v3.h>
#endif

//#define DEBUG_STREAM				// enable this to read/write network stream to disk file

//----------------------------------------------------------------------------------------------------------------------
// TRACING FUNCTIONS
//----------------------------------------------------------------------------------------------------------------------

#define TRACE_FUNCTION_CALLS
//#define TRACE_FUNCTION_FLUSH

double NetworkSystem::get_time ( ) 
{
	TimeX current_time;
	current_time.SetTimeNSec ( );
	return current_time.GetElapsedSec ( m_refTime );
}

void NetworkSystem::trace_setup ( const char* trace_file_path )
{
	m_trace = fopen ( trace_file_path, "w" );
	if ( m_trace == 0 ) {
		netPrintf ( PRINT_ERROR, "Could not open trace file: Errno: %d", errno );
		return;
	}
	m_refTime.SetTimeNSec ( );
	#ifdef __linux__
		chmod ( trace_file_path, S_IRWXO ); 
	#endif
}

void NetworkSystem::trace_enter ( const char* function_name ) 
{
	if ( m_trace == 0 ) {
		return;
	}
	str pad ( m_indentCount * 2, ' ' );
	fprintf ( m_trace, "%.9f:i:%s:%s\n", get_time ( ),  pad.c_str ( ), function_name );
	#ifdef TRACE_FUNCTION_FLUSH
		fflush ( m_trace );
	#endif
	m_indentCount++;
}

void NetworkSystem::trace_exit ( const char* function_name )
{
	if ( m_trace == 0 ) {
		return;
	}
	m_indentCount--;
	if ( m_indentCount < 0 ) {
		netPrintf ( PRINT_ERROR, "Bad indent: Call from: %s", function_name );
		m_indentCount = 0;
	}
	str pad ( m_indentCount * 2, ' ' );
	fprintf ( m_trace, "%.9f:o:%s:%s\n", get_time ( ), pad.c_str ( ), function_name );
	#ifdef TRACE_FUNCTION_FLUSH
		fflush ( m_trace );
	#endif
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

#ifdef TRACE_FUNCTION_CALLS
	#define TRACE_SETUP(msg) this->trace_setup(msg)
	#define TRACE_ENTER(msg) this->trace_enter(msg)
	#define TRACE_EXIT(msg) this->trace_exit(msg)
	#define NET_PERF_PUSH(msg) this->net_perf_push(msg)
	#define NET_PERF_POP(msg) this->net_perf_pop()
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

inline void NetworkSystem::CXSetHostname ( )
{
	TRACE_ENTER ( (__func__) );
	// NOTE: Host may have multiple interfaces, this is just to get one valid local IP address (-Marty)
	struct in_addr addr;
	int ret;
	char name [ 512 ];
	if ( ( ret = gethostname ( name, sizeof ( name ) ) ) != 0 ) {
		netPrintf ( PRINT_ERROR, "Cannot get local host name: Return %d", ret );
	}
	
	#ifdef _WIN32
		struct hostent* phe = gethostbyname ( name );
		if ( phe == 0 ) {
			netPrintf ( PRINT_ERROR, "Bad host lookup in gethostbyname" );
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

inline void NetworkSystem::CXSocketApiInit ( )
{
	TRACE_ENTER ( (__func__) );
	#if defined(_MSC_VER) || defined(_WIN32) // Winsock startup
		WSADATA WSAData;
		int status;
		if ( ( status = WSAStartup ( MAKEWORD ( 1,1 ), &WSAData ) ) == 0 ) {
			netPrintf ( PRINT_VERBOSE, "Started Winsock" );
		} else {
			netPrintf ( PRINT_ERROR, "Unable to start Winsock: Return: %d", status );
		}
	#endif
	TRACE_EXIT ( (__func__) );
}

inline void NetworkSystem::CXSocketMakeBlock ( SOCKET sock_h, bool block )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32 // windows
		unsigned long block_mode = block ? 1 : 0; 
		ioctlsocket ( sock_h, FIONBIO, &block_mode ); // FIONBIO = non-blocking mode	
	#else // linux
		int flags = fcntl ( sock_h, F_GETFL, 0 ), ret;
		if ( flags == -1 ) {
			netPrintf ( PRINT_ERROR, "Failed at fcntl F_GETFL: Return: %d", flags );
			TRACE_EXIT ( (__func__) );
			return;
		} else {
			netPrintf ( PRINT_VERBOSE, "Call to get flags succeded" );
		}
		
		if ( block ) {
			flags &= ~O_NONBLOCK;
		} else {
			flags |= O_NONBLOCK;
		}

		if ( ( ret = fcntl ( sock_h, F_SETFL, flags ) ) == -1 ) {
			netPrintf ( PRINT_ERROR, "Failed at fcntl F_SETFL: Return: %d", ret );
		} else {
			netPrintf ( PRINT_VERBOSE, "Call to set blocking succeded" );
		}
	#endif
	TRACE_EXIT ( (__func__) );
}

unsigned long NetworkSystem::CXSocketReadBytes ( SOCKET sock_h ) 
{   
	TRACE_ENTER ( (__func__) );
	unsigned long bytes_avail;
	int ret;
	#ifdef _WIN32 // windows
		if ( ( ret = ioctlsocket ( sock_h, FIONREAD, &bytes_avail ) ) == -1 ) {
			netPrintf ( PRINT_ERROR, "Failed at ioctlsocket FIONREAD: Return: %d", ret );
			bytes_avail = -1;
		} 
	#else		
	    int bytes_avail_int;
		if ( ( ret = ioctl ( sock_h, FIONREAD, &bytes_avail_int ) ) == -1 ) {
			netPrintf ( PRINT_ERROR, "Failed at ioctl FIONREAD: Return: %d", ret );
			bytes_avail = -1;
		} else {
			bytes_avail = (unsigned long) bytes_avail_int;
		}
	#endif    
	TRACE_EXIT ( (__func__) );
	return bytes_avail;
}

inline int NetworkSystem::CXSocketIvalid ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32
		TRACE_EXIT ( (__func__) );
		return sock_h == INVALID_SOCKET;
	#else
		TRACE_EXIT ( (__func__) );
		return sock_h < 0;
	#endif
}

inline int NetworkSystem::CXSocketError ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	#if defined(_MSC_VER) || defined(_WIN32)
		TRACE_EXIT ( (__func__) );
		return sock_h == SOCKET_ERROR;
	#else
		TRACE_EXIT ( (__func__) );
		return sock_h < 0;
	#endif
}

inline bool NetworkSystem::CXSocketBlockError ( )
{
	#ifdef __linux__
		return errno == EAGAIN || errno == EWOULDBLOCK;
    #elif _WIN32
		return WSAGetLastError ( ) == WSAEWOULDBLOCK;
	#else
		return false;
	#endif
}

inline str NetworkSystem::CXGetErrorMsg ( int& error_id )
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

inline void NetworkSystem::CXSocketUpdateAddr ( int sock_i, bool src )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];	   
	int optval = 0, ret;
	unsigned long ioval = ( s.blocking ? 0 : 1 ); // 0 = blocking, 1 = non-blocking
	#ifdef _WIN32 // Windows
		int case_key = ( src ) ? s.src.type : s.dest.type;
		switch ( case_key ) {
			case NTYPE_BROADCAST:	s.src.ip.S_un.S_addr = htonl( INADDR_BROADCAST ); 	optval = 1;	break;
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
			//if ( ret < 0 ) netPrintf ( PRINT_ERROR, "Cannot set socket opt" );
			ret = ioctl ( s.socket, FIONBIO, &ioval );
			//if ( ret < 0 ) netPrintf ( PRINT_ERROR, "Cannot set socket ctrl" );
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

inline void NetworkSystem::CXSocketClose ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	#ifdef _WIN32
		shutdown ( sock_h, SD_BOTH );					
		closesocket ( sock_h );
	#else
		int ret, err = 1;
		socklen_t len = sizeof ( err );
		if ( ( ret = getsockopt ( sock_h, SOL_SOCKET, SO_ERROR, (char*)&err, &len ) ) == -1 ) {
			netPrintf ( PRINT_ERROR , "Failed at getsockopt SO_ERROR: Return: %d", ret );
		}
		if ( err ) {
			errno = err;  
		}
		shutdown ( sock_h, SHUT_RDWR );				
		close ( sock_h );
	#endif
	TRACE_EXIT ( (__func__) );
}

inline str NetworkSystem::CXGetIpStr ( netIP ip )
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
// -> MAIN CODE <-
//----------------------------------------------------------------------------------------------------------------------

NetworkSystem::NetworkSystem ( const char* trace_file_name )
{
	m_hostType = ' ';
	m_hostIp = 0;
	m_readyServices = 0;
	m_userEventCallback = 0;
	m_rcvSelectTimout.tv_sec = 0;
	m_rcvSelectTimout.tv_usec = 1e3;
	m_lastClientConnectCheck.SetTimeNSec ( );

	m_security = NET_SECURITY_PLAIN_TCP;
	m_pathPublicKey = str("");
	m_pathPrivateKey = str("");
	m_pathCertDir = str("");
	m_pathCertFile = str("");
	
	m_printVerbose = true;
	m_printFlow = false;
	m_trace = 0;
	m_check = 0;
	m_indentCount = 0;
	
	// internal buffers
	m_packetPtr = &m_packetBuf[0];
	m_packetLen = 0;
	m_packetCounter = 0;
	m_recvMax = 65535;
	m_recvBuf = (char*) malloc( m_recvMax );	
	m_recvPtr = m_recvBuf;
	m_recvLen = 0;	

	netPrintf(PRINT_VERBOSE, "SERIALIZED HEADER SIZE: %d\n", Event::staticSerializedHeaderSize());
	
	if ( trace_file_name != NULL ) {
		TRACE_SETUP (( trace_file_name ));
	} 
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
	unsigned long bytes_avail = CXSocketReadBytes ( sock_h );
	TRACE_EXIT ( (__func__) );
	return bytes_avail;
}

void NetworkSystem::make_sock_no_delay ( SOCKET sock_h ) 
{
	TRACE_ENTER ( (__func__) );
	int no_delay = 1, ret;
	if ( ( ret = setsockopt ( sock_h, IPPROTO_TCP, TCP_NODELAY, (char *) &no_delay, sizeof ( no_delay ) ) ) < 0 ) {
		netPrintf ( PRINT_ERROR, "Failed at set no delay: Return: %d", ret );
	}  
	else {
		netPrintf ( PRINT_VERBOSE, "Call to no delay succeded" );
	} 
	TRACE_EXIT ( (__func__) );
} 

void NetworkSystem::make_sock_block ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	CXSocketMakeBlock ( sock_h, true );
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::make_sock_non_block ( SOCKET sock_h )
{
	TRACE_ENTER ( (__func__) );
	CXSocketMakeBlock ( sock_h, false );
	TRACE_EXIT ( (__func__) );
}

bool NetworkSystem::invalid_socket_index ( int sock_i ) 
{
	return sock_i < 0 || sock_i >= m_socks.size ( );
}

//----------------------------------------------------------------------------------------------------------------------
//
// -> CLIENT & SERVER SPECIFIC <-
//
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// -> OPENSSL SERVER <-
//----------------------------------------------------------------------------------------------------------------------

#ifdef BUILD_OPENSSL
	
str NetworkSystem::netGetErrorStringSSL ( int ret, SSL* ssl ) 
{		 
	TRACE_ENTER ( (__func__) );
	str msg = str ( );
	switch ( SSL_get_error ( ssl, ret ) )
	{
		case SSL_ERROR_NONE:
			msg += "TLS/SSL I/O operation completed. "; 
			break;
		case SSL_ERROR_ZERO_RETURN:  
			msg += "TLS/SSL connection has been closed. "; 
			break;
		case SSL_ERROR_WANT_READ: 
			msg += "Read incomplete; call again later. ";
			break;
		case SSL_ERROR_WANT_WRITE: 
			msg += "Write incomplete; call again later. ";
			break;
		case SSL_ERROR_WANT_CONNECT: 
			msg += "Connect incomplete; call again later. ";
			break;
		case SSL_ERROR_WANT_ACCEPT: 
			msg += "Accept incomplete; call again later. "; 
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:  
			msg += "Operation incomplete; SSL_CTX_set_client_cert_cb() callback asked to be called again later. ";
			break;
		case SSL_ERROR_SYSCALL: 
			msg += "Some I/O error occurred. The OpenSSL error queue is here: "; 
			break;
		case SSL_ERROR_SSL: 
			msg += "An SSL library failure occurred, usually a protocol error. The OpenSSL error queue is here: "; 
			break;
		default: 
			msg += "Unknown error"; 
			break;
	};		 
	char buf[ 2048 ]; // append, SSL error queue 
	unsigned long err;
	while ( ( err = ERR_get_error ( ) ) != 0 ) {
		ERR_error_string ( err, buf );
		msg += str ( buf ) + ". ";
	}	 
	ERR_clear_error ( ); 
	TRACE_EXIT ( (__func__) );
	return msg;
}
	
void NetworkSystem::netFreeSSL ( int sock_i ) 
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
	char msg[ 2048 ];
	NetSock& s = m_socks [ sock_i ];
	make_sock_no_delay ( s.socket );
	int ret = 0, exp;
	make_sock_non_block ( s.socket ); 
	s.security |= NET_SECURITY_FAIL; 
	s.state = STATE_FAILED; 
	s.lastStateChange.SetTimeNSec ( );

	if ( ( s.ctx = SSL_CTX_new ( TLS_server_method ( ) ) ) == 0 ) {
		netPrintf ( PRINT_ERROR_HS, "Failed at new ssl ctx" );
		netFreeSSL ( s.socket );
		TRACE_EXIT ( (__func__) );
		return;
	}

	dbgprintf ( "HANDSHAKE OpenSSL: %s\n", OPENSSL_VERSION_TEXT ); // Openssl version 

	exp = SSL_OP_SINGLE_DH_USE;
	if ( ( ( ret = SSL_CTX_set_options ( s.ctx, exp ) ) & exp ) != exp ) {
		netPrintf ( PRINT_ERROR_HS, "Failed at: set ssl option: Return: %d", ret );
		netFreeSSL ( sock_i );
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to set ssl option succeded" );
	}

	if ( ( ret = SSL_CTX_set_default_verify_paths ( s.ctx ) ) <= 0 ) { // Set CA veryify locations for trusted certs
		netPrintf ( PRINT_ERROR_HS, "Default verify paths failed: Return: %d", ret );
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to default verify paths succeded" );
	}
	const char* fmt = "Trusted cert paths. CA file = %s, CA dir = %s";
	netPrintf ( PRINT_VERBOSE_HS, fmt, m_pathCertFile.c_str ( ), m_pathCertDir.c_str ( ) );

	if ( ! m_pathCertFile.empty ( ) || ! m_pathCertDir.empty ( ) ) {
		ret = ret = SSL_CTX_load_verify_locations ( s.ctx, m_pathCertFile.c_str ( ) , m_pathCertDir.c_str ( ) );
		if ( ret <= 0 ) {
			netPrintf ( PRINT_ERROR_HS, "Load verify locations failed on cert file: %s", m_pathCertFile.c_str ( ) );
		} else {
			netPrintf ( PRINT_VERBOSE_HS, "Call to load verify locations succeded" );
		}
	}


	SSL_CTX_set_verify ( s.ctx, SSL_VERIFY_PEER, NULL );

	if ( ( ret = SSL_CTX_use_certificate_file ( s.ctx, m_pathPublicKey.c_str ( ), SSL_FILETYPE_PEM ) ) <= 0 ) {
		netPrintf ( PRINT_ERROR_HS, "Use certificate failed on public key: %s", m_pathPublicKey.c_str ( ) );	
		netFreeSSL ( sock_i ); 
		s.lastStateChange.SetTimeNSec ( );
		TRACE_EXIT ( (__func__) );	
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to use certificate succeded" );
	}

	if ( ( ret = SSL_CTX_use_PrivateKey_file ( s.ctx, m_pathPrivateKey.c_str ( ), SSL_FILETYPE_PEM ) ) <= 0 ) {			
		netPrintf ( PRINT_ERROR_HS, "Use private key failed on %s", m_pathPrivateKey.c_str ( ) );	
		netFreeSSL ( sock_i ); 
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to use private key succeded" );
	}

	s.ssl = SSL_new ( s.ctx );
	long lret = SSL_set_mode ( s.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE );
	if ( lret & SSL_MODE_ENABLE_PARTIAL_WRITE == 0 ) {
		std::cout << "SSL_MODE_ENABLE_PARTIAL_WRITE = 0" << std::endl;
		exit (0);
	}
	
	if ( ( ret = SSL_set_fd ( s.ssl, s.socket ) ) <= 0 ) {
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf ( PRINT_ERROR_HS, "Failed at set ssl fd: Return: %d: %s", ret, msg.c_str ( ) );
		netFreeSSL ( sock_i ); 
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to set ssl fd succeded" );
	}
	
	s.security &= ~NET_SECURITY_FAIL;
	s.state = STATE_SSL_HANDSHAKE;
	s.lastStateChange.SetTimeNSec ( );
	TRACE_EXIT ( (__func__) );
}
	      
void NetworkSystem::netServerAcceptSSL ( int sock_i ) 
{ 
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];	   
	int ret = SSL_accept ( s.ssl ); // SSL accept 
	if ( ret < 0 ) { 
		ret = netNonFatalErrorSSL ( sock_i, ret ); // ret = 2, if want read/write
	}
	
	if ( ret <= 0 ) { // SSL fatal error		
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf ( PRINT_ERROR_HS, "SSL_accept failed (1): Return: %d: %s", ret, msg.c_str ( ) );
		netFreeSSL ( sock_i );
		s.security |= NET_SECURITY_FAIL; // Handshake failed
		netManageHandshakeError ( sock_i );
	} else if (ret == 2) { // SSL non-fatal. Want_read or Want_write
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf(PRINT_VERBOSE_HS, "Non-blocking to ssl accept returned: %d: %s", ret, msg.c_str ( ) );
		netPrintf(PRINT_VERBOSE_HS, "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
	} else if (ret == 1) { // SSL connection complete.
		netPrintf ( PRINT_VERBOSE_HS, "Call to ssl accept succeded" );
		netPrintf ( PRINT_VERBOSE_HS, "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
		netServerCompleteConnection ( sock_i ); // Handshake succeeded. Complete connection.
	}
	
	TRACE_EXIT ( (__func__) );
}
	
#endif

//----------------------------------------------------------------------------------------------------------------------
// -> GENERAL SERVER <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netServerStart ( netPort srv_port, int security )
{
	TRACE_ENTER ( (__func__) );
	netPrintf ( PRINT_VERBOSE, "Start Server:" );
	m_hostType = 's';
	netIP srv_anyip = inet_addr ( "0.0.0.0" );
	
	NetAddr addr1 ( NTYPE_ANY, m_hostName, srv_anyip, srv_port );
	NetAddr addr2 ( NTYPE_BROADCAST, "", 0, srv_port );
	int srv_sock_i = netAddSocket ( NET_SRV, NET_TCP, STATE_START, false, addr1, addr2 ), ret;
	const char reuse = 1;
	NetSock& s = m_socks[ srv_sock_i ];
	if ( ( ret = setsockopt ( s.socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof ( int ) ) ) < 0 ) {	
		netPrintf ( PRINT_ERROR, "Failed at SO_REUSEADDR; Return: %d", ret );
	}
	if ( security != NET_SECURITY_UNDEF ) {
		m_socks[ srv_sock_i ].security = security;
	}
	
	netSocketBind ( srv_sock_i );
	netSocketListen ( srv_sock_i );	
	if ( security == NET_SECURITY_UNDEF ) {
		if ( ( m_security > NET_SECURITY_PLAIN_TCP ) && ( m_security & NET_SECURITY_PLAIN_TCP ) ) {
			netServerStart ( --srv_port, NET_SECURITY_PLAIN_TCP );
		}
	}
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netServerAcceptClient ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	/* int srv_sock_svc = netFindSocket ( NET_SRV, NET_TCP, NTYPE_ANY ); // MP: Check that this is OK
	if ( srv_sock_svc == -1 ) {
		netPrintf ( PRINT_ERROR, "Unable to find server listen socket" );
	} */

	str srv_name = m_socks[ sock_i ].src.name;
	netPort srv_port = m_socks[ sock_i ].src.port;
	netIP cli_ip = 0;
	netPort cli_port = 0;

	SOCKET sock_h;	// New literal socket
	int result = netSocketAccept ( sock_i, sock_h, cli_ip, cli_port );
	if ( result < 0 ) {
		// This should result in netManageHandshakeError (-RAMA)
		netPrintf ( PRINT_VERBOSE_HS, "Connection not accepted" );
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
	s.lastStateChange.SetTimeNSec ( );

	if ( s.security & NET_SECURITY_OPENSSL ) {
		netServerSetupHandshakeSSL ( cli_sock_i );
		if ( s.security & NET_SECURITY_FAIL ) {
			netManageHandshakeError ( sock_i );
		}
	}
	else if ( s.security & NET_SECURITY_PLAIN_TCP ) { // Complete TCP or SSL connection
		netServerCompleteConnection ( cli_sock_i );
	}
	TRACE_EXIT ( (__func__) ); 	
} 
	
void NetworkSystem::netServerCompleteConnection ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	int srv_sock_svc = netFindSocket ( NET_SRV, NET_TCP, NTYPE_ANY );
	if ( srv_sock_svc == -1 ) {
	   netPrintf ( PRINT_ERROR_HS, "Unable to find server listen socket" );
	}
	netPort srv_port = m_socks[ srv_sock_svc ].src.port;
	NetSock& s = m_socks [ sock_i ];	

	assert(s.side != NET_CLI);

	// Accept succeeded
	bool ssl = (s.security & NET_SECURITY_OPENSSL) == NET_SECURITY_OPENSSL;
	netPrintf(PRINT_VERBOSE, "SUCCESS %s: Server %s:%d, Accepted %s:%d", ssl ? "OpenSLL" : "TCP", getIPStr(m_hostIp).c_str(), s.src.port, getIPStr(s.dest.ipL).c_str(), s.dest.port);
	netList();

	// Send first event to client
	Event e; 
	e = netMakeEvent ( 'sOkT', 0 );
	e.attachInt64 ( s.dest.ipL );	// Client IP
	e.attachInt64 ( s.dest.port );	// Client port assigned by server!
	e.attachInt64 ( m_hostIp );		// Server IP
	e.attachInt64 ( srv_port );		// Server port
	e.attachInt ( sock_i );			// Connection ID (goes back to the client)
	netSend ( e, sock_i );			// Send TCP connected event to client

	// Send verify event to server
	Event ue = new_event ( 120, 'app ', 'sOkT', 0, m_eventPool ); // Inform the user-app (server) of the event	
	ue.attachInt ( sock_i );
	ue.attachInt ( -1 ); // cli_sock not known
	ue.startRead ( );
	(*m_userEventCallback) ( ue, this ); // Send to application

	// Last step. Set socket as CONNECTED.
	// (we assume the netSend of 'sOkT' succeeded)
	s.state = STATE_CONNECTED;
	s.lastStateChange.SetTimeNSec();
	
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netServerCheckConnectionHandshakes ( ) 
{
	for ( int sock_i = 0; sock_i < (int) m_socks.size ( ); sock_i++ ) { 
		NetSock& s = m_socks[ sock_i ];
		if ( s.state == STATE_SSL_HANDSHAKE ) {
			TimeX current_time;
			current_time.SetTimeNSec ( );
			if (  current_time.GetElapsedSec ( s.lastStateChange ) > 5.0 ) {
				netManageHandshakeError ( sock_i );
			}
		}
	}
}

void NetworkSystem::netServerProcessIO ( )
{
	TRACE_ENTER ( (__func__) );
	fd_set sockReadSet;
	fd_set sockWriteSet;
	int rcv_events = netSocketSelect ( &sockReadSet, &sockWriteSet );
	NET_PERF_PUSH ( "findsocks" );
	for ( int sock_i = 0; sock_i < (int) m_socks.size ( ); sock_i++ ) { 
		NetSock& s = m_socks[ sock_i ];
		if ( netSocketIsSelected ( &sockReadSet, sock_i ) ) {
			if ( s.src.type == NTYPE_ANY ) { // Listen for TCP connections on socket
				netServerAcceptClient ( sock_i );
			} else {
				if ( ( s.security & NET_SECURITY_OPENSSL ) && s.state == STATE_SSL_HANDSHAKE ) {
					netServerAcceptSSL ( sock_i );
				}
				netReceiveData ( sock_i );
			}
		}
		if ( netSocketIsSelected ( &sockWriteSet, sock_i ) ) {
			netSendResidualEvent ( sock_i );
		}
	}
	NET_PERF_POP ( );
	TRACE_EXIT ( (__func__) );
}

//----------------------------------------------------------------------------------------------------------------------
// -> OPENSSL CLIENT <-
//----------------------------------------------------------------------------------------------------------------------

#ifdef BUILD_OPENSSL
	
void NetworkSystem::netClientSetupHandshakeSSL ( int sock_i ) 
{ 
	char msg[2048];

	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	if ( s.ctx != 0 ) {
		netFreeSSL ( sock_i ); 
		netPrintf ( PRINT_VERBOSE_HS, "Call to free old context made (1)" );
	}
	
	int ret = 0, exp;
	make_sock_no_delay ( s.socket );
	make_sock_non_block ( s.socket ); 
	s.security |= NET_SECURITY_FAIL; // Assume failure until end of this function
	s.state = STATE_FAILED; 
	s.lastStateChange.SetTimeNSec ( );
	
	#if OPENSSL_VERSION_NUMBER < 0x10100000L // Version 1.1
		SSL_load_error_strings ( );	 
		SSL_library_init ( );
	#else // version 3.0+
		OPENSSL_init_ssl ( OPENSSL_INIT_LOAD_SSL_STRINGS, NULL );
	#endif

	dbgprintf ( "HANDSHAKE OpenSSL: %s\n", OPENSSL_VERSION_TEXT ); // Openssl version 

	//s.bio = BIO_new_socket ( s.socket, BIO_NOCLOSE );

	s.ctx = SSL_CTX_new ( TLS_client_method ( ) );
	if ( ! s.ctx ) {
		netPrintf ( PRINT_ERROR_HS, "Failed at: new ctx" );
		netFreeSSL ( sock_i );
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to ctx succeded" );
	}

	// Use TLS 1.2+ only, since we have custom client-server protocols
	SSL_CTX_set_min_proto_version ( s.ctx, TLS1_2_VERSION );
	SSL_CTX_set_max_proto_version ( s.ctx, TLS1_3_VERSION );
	SSL_CTX_set_verify ( s.ctx, SSL_VERIFY_PEER, NULL );

	if ( !SSL_CTX_load_verify_locations( s.ctx, m_pathPublicKey.c_str ( ), NULL ) ) {
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf ( PRINT_ERROR_HS, "Load verify failed on public key: %s", msg.c_str ( ) );
		netFreeSSL ( sock_i );
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to load verify locations succeded" );
	}		

	s.ssl = SSL_new ( s.ctx );
	long lret = SSL_set_mode ( s.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE );
	if ( lret & SSL_MODE_ENABLE_PARTIAL_WRITE == 0 ) {
		std::cout << "SSL_MODE_ENABLE_PARTIAL_WRITE = 0" << std::endl;
		exit (0);
	}
	
	if ( ! s.ssl ) {
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf ( PRINT_ERROR_HS, "Failed at new ssl: %s", msg.c_str ( ) );
		netFreeSSL ( sock_i ); 
		TRACE_EXIT ( (__func__) );
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to ssl succeded" );
	}	

	if ( ( ret = SSL_set_fd ( s.ssl, s.socket ) ) != 1 ) {
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf ( PRINT_ERROR_HS, "Failed at set fd failed: Return: %d: %s", ret, msg.c_str ( ) );
		netFreeSSL ( sock_i );
		TRACE_EXIT ( (__func__) ); 	
		return;
	} else {
		netPrintf ( PRINT_VERBOSE_HS, "Call to ssl set fd succeded" );
	}	

	s.security &= ~NET_SECURITY_FAIL;
	s.state = STATE_SSL_HANDSHAKE;
	s.lastStateChange.SetTimeNSec ( );
	TRACE_EXIT ( (__func__) );
}	

void NetworkSystem::netClientConnectSSL ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	int exp;
	NetSock& s = m_socks[ sock_i ];
	int ret = SSL_connect ( s.ssl );
	if ( ret < 0 ) {
		ret = netNonFatalErrorSSL ( sock_i, ret ); // ret = 2, want read/write
	}

	if ( ret <= 0 ) { // SSL connect error.
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf(PRINT_ERROR_HS, "Call to ssl connect failed: Return: %d: %s", ret, msg.c_str ( ) );
		netFreeSSL ( sock_i );
		s.security |= NET_SECURITY_FAIL; // Handshake error
		netManageHandshakeError ( sock_i );

	} else if ( ret == 2 ) { // SSL connect non-fatal. Want_read/write.
		str msg = netGetErrorStringSSL ( ret, s.ssl );
		netPrintf ( PRINT_VERBOSE_HS, "Non-blocking ssl connect returned: %d: %s", ret, msg.c_str ( ) );
		netPrintf ( PRINT_VERBOSE_HS, "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
	
	} else if ( ret == 1 ) { // SSL connect succeeded.
		netPrintf ( PRINT_VERBOSE_HS, "Call to ssl connect succeded" );
		netPrintf ( PRINT_VERBOSE_HS, "Ready for safe transfer: %d", SSL_is_init_finished ( s.ssl ) );
		
		// Note: We DO NOT set state=CONNECTED here yet.
		// Must wait for sOkT event which contains the server srv_sock ID.
	}
		
	TRACE_EXIT ( (__func__) );
}

#endif

//----------------------------------------------------------------------------------------------------------------------
// -> GENERAL CLIENT <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netClientStart ( netPort cli_port, str srv_addr )
{
	TRACE_ENTER ( (__func__) );
	
	netPrintf ( PRINT_ERROR, "Just testing: REMOVE THIS" ); // TODO
	
	eventStr_t sys = 'net '; 
	m_hostType = 'c'; // Network System is running in client mode
	netPrintf ( PRINT_VERBOSE, "Start Client:" );

	struct HELPAPI NetAddr netAddr = NetAddr ( ); // Start a TCP listen socket on Client
	netAddr.convertIP ( ntohl ( inet_addr ( srv_addr.c_str ( ) ) ) );
	netAddr.ipL = inet_addr ( srv_addr.c_str ( ) );
	netAddSocket ( NET_CLI, NET_TCP, STATE_NONE, false, NetAddr ( NTYPE_ANY, m_hostName, m_hostIp, cli_port ), netAddr );
	TRACE_EXIT ( (__func__) );
}

int NetworkSystem::netClientConnectToServer ( str srv_name, netPort srv_port, bool block, int cli_sock_i )
{
	TRACE_ENTER ( (__func__) );
	str cli_name;
	netIP cli_ip, srv_ip;
	int cli_port, connect_result, ret;

	if ( ! VALID_INDEX ( cli_sock_i ) ) { // If a socket index is not given, find a socket index
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
				netPrintf ( PRINT_ERROR_HS, "Unable to resolve server: %s: Return: %d", srv_name.c_str ( ), result );
				TRACE_EXIT ( (__func__) );
				return -1;
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
		
		int cli_sock_svc_i = netFindSocket ( NET_CLI, NET_TCP, NTYPE_ANY ); // Find a local TCP socket service
		cli_name = m_socks[ cli_sock_svc_i ].src.name;
		cli_port = m_socks[ cli_sock_svc_i ].src.port;
		cli_ip = m_hostIp;
		NetAddr srv_addr = NetAddr ( NTYPE_CONNECT, srv_name, srv_ip, srv_port ); // Find or create socket
		cli_sock_i = netFindSocket ( NET_CLI, NET_TCP, srv_addr );
		if ( cli_sock_i == NET_ERR ) { 
			NetAddr cli_addr = NetAddr ( NTYPE_CONNECT, cli_name, cli_ip, cli_port );
			cli_sock_i = netAddSocket ( NET_CLI, NET_TCP, STATE_START, block, cli_addr, srv_addr );
			if ( cli_sock_i == NET_ERR ) {	
				netPrintf ( PRINT_ERROR_HS, "Unable to add socket" );
				TRACE_EXIT ( (__func__) );		
				return -1;
			}
		}
	} 

	const char reuse = 1;
	NetSock& s = m_socks[ cli_sock_i ];
	s.srvAddr = srv_name;
	s.srvPort = srv_port; 
	if ( ( ret = setsockopt ( s.socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof ( int ) ) ) < 0 ) {
		netPrintf ( PRINT_ERROR_HS, "Failed at SO_REUSEADDR: Return: %d", ret );
	}
	if ( s.state != STATE_CONNECTED ) { // Try to connect if needed
		connect_result = netSocketConnect ( cli_sock_i );
		if ( connect_result != 0 ) {
			netReportError ( connect_result );
		} 
	} else {
		s.reconnectBudget = s.reconnectLimit;
	}
	if ( s.security & NET_SECURITY_OPENSSL ) { // SSL handshake
		netClientSetupHandshakeSSL ( cli_sock_i );
		if ( s.security & NET_SECURITY_FAIL ) {	
			netManageHandshakeError ( cli_sock_i );
		}
	}
	TRACE_EXIT ( (__func__) );
	return cli_sock_i; // Return socket for this connection
}

void NetworkSystem::netClientCheckConnectionHandshakes ( )
{
	TRACE_ENTER ( (__func__) );
	TimeX current_time;
	current_time.SetTimeNSec ( );	
	if ( current_time.GetElapsedMSec ( m_lastClientConnectCheck ) > m_reconnectInterval ) {
		m_lastClientConnectCheck.SetTimeNSec ( );
		for ( int sock_i = 1; sock_i < (int) m_socks.size ( ); sock_i++ ) {
			NetSock& s = m_socks[ sock_i ];
			if ( s.state == STATE_SSL_HANDSHAKE ) {
				TimeX current_time;
				current_time.SetTimeNSec ( );
				if ( current_time.GetElapsedSec ( s.lastStateChange ) > 5.0 ) {
					netManageHandshakeError ( sock_i );
				}
			}
			if ( s.security & NET_SECURITY_OPENSSL && s.state == STATE_SSL_HANDSHAKE ) {
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
	fd_set sockReadSet;
	fd_set sockWriteSet;
	int rcv_events = netSocketSelect ( &sockReadSet, &sockWriteSet );
	NET_PERF_PUSH ( "findsocks" );
	for ( int sock_i = 0; sock_i < (int) m_socks.size ( ); sock_i++ ) { 
		if ( netSocketIsSelected ( &sockReadSet, sock_i ) ) {
			NetSock& s = m_socks[ sock_i ];
			if ( s.security & NET_SECURITY_OPENSSL && s.state == STATE_SSL_HANDSHAKE ) {
				netClientConnectSSL ( sock_i ); // This call is LESS important than the other
			}
			netReceiveData(sock_i);
		}
		if ( netSocketIsSelected ( &sockWriteSet, sock_i ) ) {
			netSendResidualEvent( sock_i );
		}
	}
	NET_PERF_POP ( );
	TRACE_EXIT ( (__func__) );
}

//----------------------------------------------------------------------------------------------------------------------
//
// -> CLIENT & SERVER COMMON FUNCTIONS <-
//
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// -> CLIENT & SERVER <-
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
	netList ( );
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
	netManageFatalError ( sock_i ); // Terminate local socket	 
	TRACE_EXIT ( (__func__) );
	return 1;
}

#ifdef BUILD_OPENSSL

int NetworkSystem::netNonFatalErrorSSL ( int sock, int ret ) 
{
	TRACE_ENTER ( (__func__) );
	int err = SSL_get_error ( m_socks [ sock ].ssl, ret ), code;
	if ( err == SSL_ERROR_WANT_READ ) {
		TRACE_EXIT ( (__func__) );
		return 2;	// ret value to use for non-fatal want read/write
	} else if ( err == SSL_ERROR_WANT_WRITE ) {
		TRACE_EXIT ( (__func__) );
		return 2;	// ret value to use for non-fatal want read/write
	}
	TRACE_EXIT ( (__func__) );
	return ret;		// pass-thru other ret error values
}

#endif

//----------------------------------------------------------------------------------------------------------------------
// -> CORE CODE <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netProcessEvents ( Event& e )
{
	TRACE_ENTER ( (__func__) );
	switch ( e.getName ( ) ) {
		case 'sOkT': {
			// Received OK from server. connection complete.			
			netIP cli_ip = e.getInt64 ( );		// Client IP completed
			netPort cli_port = e.getInt64 ( );  // Client port
			netIP srv_ip = e.getInt64 ( );		// Server IP
			int srv_port = e.getInt64 ( );		// Server port
			int srv_sock = e.getInt ( );		// Server sock which maintains this client

			int cli_sock = e.getSrcSock();		// Client sock which received accept (srcsock, not in payload)
	
			// Verify client and server IPs
			netIP srv_ip_chk = e.getSrcIP ( ); // source IP from the socket event came on
			netIP cli_ip_chk = m_socks[ cli_sock ].src.ipL; // original client IP

			// Mark the client socket as CONNECTED.
			// Update with server socket & client port.
			m_socks[cli_sock].state = STATE_CONNECTED; // mark connected
			m_socks[cli_sock].lastStateChange.SetTimeNSec();
			m_socks[cli_sock].dest.sock = srv_sock; // assign server socket
			m_socks[cli_sock].src.port = cli_port; // assign client port from server			

			// Connection complete
			bool ssl = m_socks[cli_sock].security & NET_SECURITY_OPENSSL;
			netPrintf(PRINT_VERBOSE, "SUCCESS %s. Client %s:%d (sock %d), To Server: %s:%d (sock %d)", ssl ? "OpenSSL" : "TCP", getIPStr(cli_ip).c_str(), cli_port, cli_sock, getIPStr(srv_ip).c_str(), srv_port, srv_sock);
			netList();

			Event e = new_event ( 120, 'app ', 'sOkT', 0, m_eventPool ); // Inform the user-app (client) of the event
			e.attachInt ( srv_sock );
			e.attachInt ( cli_sock );		
			e.startRead ( );
			(*m_userEventCallback) ( e, this ); // Send to application			
			break;
		} 
		case 'sExT': { // Server recv, exit TCP from client. sEnT
			int local_sock_i = e.getUInt ( ); // Socket to close
			int remote_sock = e.getUInt ( ); // Remote socket
			netIP cli_ip = m_socks[ local_sock_i ].dest.ipL;
			netPrintf ( PRINT_VERBOSE_HS, "Server: Client %s closed OK", getIPStr ( cli_ip ).c_str ( ) );
			netManageFatalError ( local_sock_i );
			netList ( );
			break;
		}
	}
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netInitialize ( )
{
	TRACE_ENTER ( (__func__) );
	m_check = 0;
	netPrintf ( PRINT_VERBOSE, "Network Initialize" );
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
	s.lastStateChange.SetTimeNSec ( );
	s.src = src;
	s.dest = dest;
	s.socket = 0;
	s.timeout.tv_sec = 0; 
	s.timeout.tv_usec = 0;
	s.blocking = block;
	s.broadcast = 1;
	s.security = m_security; 
	s.reconnectBudget = s.reconnectLimit = m_reconnectLimit;  

	s.ctx = 0;
	s.ssl = 0;
	s.bio = 0;

	s.txBuf = (char*) malloc( m_recvMax ); // TODO: This is too big for a default value; use resize	
	s.txBufLimit = m_recvMax;
	s.txPktSize = 0;
	s.txSoFar = 0;

	int n = m_socks.size ( );
	m_socks.push_back ( s );
	netSocketAdd ( n );
	
	TRACE_EXIT ( (__func__) );
	return n;
}

int NetworkSystem::netManageHandshakeError ( int sock_i ) 
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	int security_fail = s.security;		// record the security levels at failure
	int outcome = 0;
	bool fallback_allowed = ( s.security & NET_SECURITY_OPENSSL ) && ( s.security & NET_SECURITY_PLAIN_TCP );
	if ( fallback_allowed && s.side == NET_CLI ) {
		// client try fallback to plain TCP
		s.security = NET_SECURITY_PLAIN_TCP;
		s.srvPort -= 1;
		s.dest.port -= 1;
		s.state = STATE_START;
		s.lastStateChange.SetTimeNSec ( );
		if ( s.ctx != 0 ) {
			netFreeSSL ( sock_i ); 
			netPrintf ( PRINT_VERBOSE, "Call to free old context made (2)" );
		}
		CXSocketClose ( s.socket );
		s.socket = 0;
		netSocketAdd ( sock_i );
		netClientConnectToServer ( s.srvAddr, s.srvPort, false, sock_i );
		
	} else {
		outcome = netDeleteSocket ( sock_i, 0 );
	}
	// Handshake failed
	bool ssl = (security_fail & NET_SECURITY_OPENSSL);
	netPrintf(PRINT_VERBOSE, "FAILED %s.", ssl ? "OpenSSL" : "TCP" );

	TRACE_EXIT ( (__func__) );
	return outcome;
}

int NetworkSystem::netManageFatalError ( int sock_i, int force ) 
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	int outcome = 0;
	if ( m_hostType == 'c' && s.reconnectBudget > 0 ) {
		s.state = STATE_START;
		s.lastStateChange.SetTimeNSec ( );
		if ( s.ctx != 0 ) {
			netFreeSSL ( sock_i ); 
			netPrintf ( PRINT_VERBOSE, "Call to free old context made (3)" );
		}
		CXSocketClose ( s.socket );
		s.socket = 0;
		netSocketAdd ( sock_i );
	} else {
		outcome = netDeleteSocket ( sock_i, 1 );
	}
	TRACE_EXIT ( (__func__) );
	return outcome;
}

// Terminate Socket
// Note: This does not erase the socket from std::vector because we don't want to
// shift around the other socket IDs. Instead it disables the socket ID, making it available
// to another client later. Only the very last socket could be actually removed from list.

int NetworkSystem::netDeleteSocket ( int sock_i, int force )
{
	TRACE_ENTER ( (__func__) );
	if ( sock_i < 0 || sock_i >= m_socks.size ( ) ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}
	NetSock& s = m_socks[ sock_i ];
	netPrintf ( PRINT_VERBOSE_HS, "Terminating socket: %d", sock_i );
	if ( s.state != NTYPE_CONNECT && s.state != STATE_CONNECTED && force == 0 ) {
		 TRACE_EXIT ( (__func__) );
		 return 0;
	}
	CXSocketClose ( s.socket );
	s.state = STATE_TERMINATED;
	s.lastStateChange.SetTimeNSec ( );
	
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
			netServerCheckConnectionHandshakes ( );
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

void NetworkSystem::netResizeRecvBuf(int len)
{
	if (len > m_recvMax) {
		int new_max = len;
		char* new_recv = (char*) malloc( new_max );
		memcpy(new_recv, m_recvBuf, m_recvLen);		
		free(m_recvBuf);
		m_recvBuf = new_recv;
		m_recvPtr = m_recvBuf + m_recvLen;
		m_recvMax = new_max;
	}
}

void NetworkSystem::netResetRecvBuf()
{
	m_recvLen = 0;
	m_recvPtr = m_recvBuf;
}

void NetworkSystem::netDeserializeEvents(int sock_i)
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	int header_sz = Event::staticSerializedHeaderSize();

	// Consumer pattern:
	// - retrieve entire event from stream directly if possible (for performance)
	// - if not, consume input stream into temp buffer	
	// - build complete event and clear temp when complete	
	// Notes:
	//  bufferLen = length of data remaining on this call (decreases as consumed)
	//  eventLen  = total length of expected event (including header) 
	//  recvLen   = partial length currently received (over multiple calls to this func), when 0 = start new event
	//  recvMax   = maximum length of temp buffer, may dynamic resize for large events	

	netPrintf ( PRINT_FLOW, "PKT #%d, %d bytes.", m_packetCounter, m_packetLen );	
	
	if ( m_packetCounter == 6 ) {
		bool stop = true;
	}
	m_packetCounter++;
	m_packetPtr = &m_packetBuf[0];

	while ( m_packetLen > 0 ) {
		if ( m_recvLen == 0 && m_packetLen > header_sz ) { // Check for new or partial event
			// Start of new event, retrieve total event length from encoded header
			m_eventLen = *((int*)(m_packetPtr + Event::staticOffsetLenInfo())) + Event::staticSerializedHeaderSize ( );

			if ( m_packetLen >= m_eventLen ) {
				// Create event; no name/target. will be set during deserialize		
				m_event = new_event ( m_eventLen - Event::staticSerializedHeaderSize ( ), 0, 0, 0, m_eventPool );				
				m_event.rescope ( "nets" );									// belongs to network now
				m_event.setSrcSock ( sock_i );								// tag event /w socket
				m_event.setSrcIP( m_socks[ sock_i ].src.ipL );				// recover sender address from socket

				// Deserialize directly from input buffer (for performance)
				m_event.deserialize ( m_packetPtr, m_eventLen );		// deserialize					
				netQueueEvent ( m_event );								// queue & delete				
				netPrintf ( PRINT_FLOW, "RX %d bytes, %s", m_eventLen, m_event.getNameStr ( ).c_str ( ) );
				delete_event ( m_event );				

				m_packetLen -= m_eventLen;								// consume event size in bytes
				m_packetPtr += m_eventLen;
				m_eventLen = 0;											// reset event size (recvLen remains 0)

			}
			else { // Store partial event in recv buffer	
				netResizeRecvBuf ( m_recvLen + m_packetLen );
				memcpy ( m_recvPtr, m_packetPtr, m_packetLen );			// transfer into recv buffer
				m_recvPtr += m_packetLen;								// advance recv buffer
				m_recvLen += m_packetLen;
				m_packetPtr += m_packetLen;								// consume remaining buffer len bytes
				m_packetLen = 0;
			}

		} else { // Continuation of event. Store additional data in recv buffer
			if ( m_recvLen + m_packetLen == 65984 ) {
				bool stop = true;
			}
			netResizeRecvBuf ( m_recvLen + m_packetLen );
			memcpy ( m_recvPtr, m_packetPtr, m_packetLen );			// transfer into recv buffer
			m_recvPtr += m_packetLen;								// advance recv buffer
			m_recvLen += m_packetLen;
			m_packetPtr += m_packetLen;								// consume remaining buffer len bytes
			m_packetLen = 0;

			if ( m_recvLen > header_sz && m_eventLen == 0 )  {
				m_eventLen = *((int*)(m_recvBuf + Event::staticOffsetLenInfo())) + Event::staticSerializedHeaderSize();				
			}
		}

		// Check for possibly multiple complete events on recv buffer
		while ( m_recvLen >= m_eventLen && m_eventLen > 0 ) {
			// Create event; no name/target. will be set during deserialize	
			m_event = new_event ( m_eventLen - Event::staticSerializedHeaderSize ( ), 0, 0, 0, m_eventPool );					
			m_event.rescope ( "nets" );								// belongs to network now
			m_event.setSrcSock ( sock_i );							// tag event /w socket
			m_event.setSrcIP ( m_socks[ sock_i ].src.ipL );			// recover sender address from socket
			
			// Deserialize event from recv buf			
			m_event.deserialize ( m_recvBuf, m_eventLen );			// deserialize			
			netQueueEvent ( m_event );								// queue & delete				
			netPrintf ( PRINT_FLOW, "RX %d bytes, %s", m_eventLen, m_event.getNameStr ( ).c_str ( ) );
			delete_event ( m_event );			
			
			// Reduce recv buffer
			m_recvLen -= m_eventLen;								// consume event bytes in recv buffer
			memcpy(m_recvBuf, m_recvBuf + m_eventLen, m_recvLen);	// transfer remaining bytes to beginning (memcpy ok since data always moving backwards in mem)
			m_recvPtr = m_recvBuf + m_recvLen;						// reset to beginning of recv			
			m_eventLen = 0;											// reset event len

			// Check for additional event(s)
			if (m_recvLen > header_sz) {
				m_eventLen = *((int*)(m_recvBuf + Event::staticOffsetLenInfo())) + Event::staticSerializedHeaderSize();				
			}
		}
	}
	TRACE_EXIT ( (__func__) );
} 

// -- Original deserialize func (NOT CORRECT)
//
/* void NetworkSystem::netDeserializeEvents(int sock_i)
{
	m_packetPtr = &m_packetBuf[0];
	bool bDeserial;

	while (m_packetLen > 0) {
		if (m_event.isEmpty()) { // Check the type of incoming socket
			if (m_socks[sock_i].blocking) {
				// Blocking socket. NOT an Event socket. Attach arbitrary data onto a new event.
				m_eventLen = m_packetLen;
				m_event = new_event(m_eventLen + 128, 'app ', 'HTTP', 0, m_eventPool);
				m_event.rescope("nets");
				m_event.attachInt(m_packetLen); // attachInt+Buf = attachStr
				m_event.attachBuf(m_packetPtr, m_packetLen);
				m_dataLen = m_event.mDataLen;
			}
			else {
				// Non-blocking socket. Receive a complete Event.
				// directly read length-of-event info from incoming data (m_dataLen value)
				m_dataLen = *((int*)(m_packetPtr + Event::staticOffsetLenInfo()));

				// compute total event length, including header
				m_eventLen = m_dataLen + Event::staticSerializedHeaderSize();

				// Event is allocated with no name/target as this will be set during deserialize
				m_event = new_event(m_dataLen, 0, 0, 0, m_eventPool);
				m_event.rescope("nets"); // Belongs to network now

				// check for serialize issue
				if (m_packeten < Event::staticSerializedHeaderSize()) {
					netPrintf(PRINT_ERROR, "Serialize issue. Buffer len %d less than event header %d. CORRUPT AFTER THIS POINT!", m_packetLen, Event::staticSerializedHeaderSize() );
				}

				// Deserialize of actual buffer length (EventLen or packetLen)
				m_event.deserialize(m_packetPtr, imin(m_eventLen, m_packetLen)); // Deserialize header				
			}
			m_event.setSrcSock(sock_i);		// <--- tag event /w socket
			m_event.setSrcIP(m_socks[sock_i].src.ipL); // recover sender address from socket
			bDeserial = true;

		}
		else { // More data for existing Event..
			bDeserial = false;
		}

		// BufferLen = actual bytes received at this time (may be partial)
		// EventLen = size of event in *network*, serialized event including data payload
		//    packetLen > eventLen      multiple events
		//    packetLen = eventLen      one event, or end of event
		//    packetLen < eventLen 			part of large event

		if (m_packetLen >= m_eventLen) { // One event, multiple, or end of large event..
			if (!bDeserial) { // Not start of event, attach more data				
				m_event.attachBuf(m_packetPtr, m_packetLen);
			}
			// End of event
			m_packetLen -= m_eventLen; // Advance buffer
			m_packetPtr += m_eventLen;
			
			// debugging
			int hsz = Event::staticSerializedHeaderSize();
			netPrintf(PRINT_VERBOSE, "RX %d bytes, %s", m_event.mDataLen + hsz, m_event.getNameStr().c_str());
			if ( m_event.mDataLen + hsz != m_eventLen ) {
				netPrintf(PRINT_ERROR, "Serialize issue. Event length %d != expected %d.", m_event.mDataLen + hsz, m_eventLen);
			}

			// Reset event length
			m_eventLen = 0;
		
			netQueueEvent(m_event);						
			delete_event(m_event);
		}
		else { // Partial event..
			if (!bDeserial) { // Not start of event, attach more data				
				m_event.attachBuf(m_packetPtr, m_packetLen);
			}
			m_eventLen -= m_packetLen;
			m_packetPtr += m_packetLen;
			m_packetLen = 0;
		}
	}	
} */


void NetworkSystem::netReceiveByInjectedBuf(int sock_i, char* buf, int buflen)
{
	TRACE_ENTER((__func__));

	// This function receives an input stream from a specified buffer,
	// INSTEAD of the TCP/IP network. Used primarily for testing, it 
	// allows for the injection of a custom event stream to test deserialization.
	// Events will be pushed to the network queue for app processing as if they came from a network.
	// See also: netReceiveData
	
	// inject buffer
	memcpy(m_packetBuf, buf, buflen);
	m_packetLen = buflen;

	// Deserialize events from input stream
	netDeserializeEvents(sock_i);

	TRACE_EXIT((__func__));	
}

//----------------------------------------------------------------------------------------------------------------------
// -> RECIEVE CODE <-
//----------------------------------------------------------------------------------------------------------------------

void NetworkSystem::netReceiveData ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	int outcome = 1;
	while ( outcome ) {
		NET_PERF_PUSH ( "recv" ); // Receive input stream from TCP/IP network
		int result = netSocketRecv ( sock_i, m_packetBuf, NET_BUFSIZE-1, m_packetLen );
		outcome = m_packetLen > 0;
		if ( result != 0 ) {
			netReportError ( result ); // Recv failed. Report net error
			TRACE_EXIT ( (__func__) );
			return;
		}
		NET_PERF_POP ( );

		#ifdef DEBUG_STREAM
			if ( m_packetLen > 0 ) { // Write TCP/IP stream to disk, with packet sizes
				FILE* fp1 = fopen ( "packet_stream.raw", "ab" );
				fwrite ( m_packetBuf, m_packetLen, 1, fp1 );
				fclose ( fp1 );
				FILE* fp2 = fopen ( "packet_sizes.txt", "at" );
				fprintf ( fp2, "%d\n", m_packetLen );
				fclose ( fp2 );
			}
		#endif		

		if ( m_packetLen > 0 ) { // Deserialize events from input stream
			netDeserializeEvents ( sock_i );
		}
	}
	TRACE_EXIT ( (__func__) );	
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

Event NetworkSystem::netMakeEvent ( eventStr_t name, eventStr_t sys )
{
	TRACE_ENTER ( (__func__) );
	Event e = new_event ( 120, sys, name, 0, m_eventPool  );
	e.setSrcIP ( m_hostIp );	// default to local IP if protocol doesn't transmit sender
	e.setTarget ( 'net ' );		// all network configure events have a 'net ' target name
	e.setName ( name );
	e.startWrite ();
	e.bOwn = false;				// dont kill on destructor
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

void NetworkSystem::netList ( bool verbose )
{
	TRACE_ENTER ( (__func__) );
	if ( m_printVerbose || verbose ) { // Print the network
		str side, mode, stat, src, dst, msg, secur;
		dbgprintf ( "\n------ NETWORK SOCKETS. MyIP: %s, %s\n", m_hostName.c_str ( ), getIPStr ( m_hostIp ).c_str ( ) );
		for ( int n = 0; n < m_socks.size ( ); n++ ) {
			side = ( m_socks[ n ].side == NET_CLI ) ? "cli" : "srv";
			secur = (m_socks[ n ].security & NET_SECURITY_OPENSSL) ? "ssl" : "tcp";			// future: udp should made a security level, remove s.mode variable.
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

			dbgprintf ( "%d: %s %s %s src[%s] dst[%s] %s\n", n, side.c_str(), secur.c_str(), stat.c_str(), src.c_str(), dst.c_str(), msg.c_str() );
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
	CXSocketApiInit ( );
	TRACE_EXIT ( (__func__) );
}

void NetworkSystem::netSetHostname ()
{
	TRACE_ENTER ( (__func__) );
	CXSetHostname ( );
	netPrintf ( PRINT_VERBOSE, "  Local Host: %s, %s", m_hostName.c_str ( ), getIPStr ( m_hostIp ).c_str ( ) );
	TRACE_EXIT ( (__func__) );
}

bool NetworkSystem::netSendLiteral ( str str_lit, int sock_i )
{
	TRACE_ENTER ( (__func__) );
	int len = str_lit.length ( ), result;
	char* buf = (char*) malloc ( str_lit.length ( ) + 1 );
	strcpy ( buf, str_lit.c_str ( ) );	
	
	NetSock& s = m_socks[ sock_i ]; // Send over socket
	if ( s.mode == NET_TCP ) {
		if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) {
			result = send ( s.socket, buf, len, 0 ); // TCP/IP
		} else {
			#ifdef BUILD_OPENSSL
				if ( ( result = SSL_write ( s.ssl, buf, len ) ) <= 0 ) {	
					if ( netNonFatalErrorSSL ( sock_i, result ) ) { 
						TRACE_EXIT ( (__func__) );
						return SSL_ERROR_WANT_WRITE;
					} else {
						str msg = netGetErrorStringSSL ( result, s.ssl );
						netPrintf ( PRINT_ERROR, "Failed at ssl write (1): Returned: %d: %s", result, msg.c_str ( ) );
					}
				}
			#endif
		} 
	}
	else {
		int addr_size = sizeof ( s.dest.addr );
		result = sendto ( s.socket, buf, len, 0, (sockaddr*)&s.dest.addr, addr_size ); // UDP
	}
	free( buf );
	TRACE_EXIT ( (__func__) );
	return CXSocketBlockError ( ) || netCheckError ( result, sock_i );		
}

bool NetworkSystem::netCheckError ( int result, int sock_i )
{
	TRACE_ENTER ( (__func__) );
	if ( CXSocketError ( m_socks[ sock_i ].socket ) ) {
		netManageFatalError ( sock_i ); // Peer has shutdown (unexpected shutdown)
		netPrintf ( PRINT_ERROR, "Unexpected shutdown" );
		TRACE_EXIT ( (__func__) );
		return false;
	}
	TRACE_EXIT ( (__func__) );
	return true; // TODO: Check this; treat as benign error if there is a tail to send
}

void NetworkSystem::netSendResidualEvent ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks[ sock_i ];
	int remaining = s.txPktSize - s.txSoFar, result;
	if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) {
		result = send ( s.socket, s.txBuf + s.txSoFar, remaining, 0 ); // TCP/IP
	} else {
		s.txSoFar = 0;
		TRACE_EXIT ( (__func__) );
		return;
		//result = SSL_write ( s.ssl, s.txBuf + s.txSoFar, remaining );
	}
	
	netPrintf ( PRINT_ERROR, "2 Tail TX: %d %d", result, remaining );
	if ( result > 0 ) {
		s.txSoFar += result;
		if ( result != remaining ) {
			netPrintf ( PRINT_ERROR, "2 Tail TX: %d ?= %d (%d)", result, remaining, s.txSoFar );
		} else {
			netPrintf ( PRINT_ERROR, "2 Partial TX done!" );
			s.txSoFar = s.txPktSize = 0;
		} 
	} 
	TRACE_EXIT ( (__func__) );
}

bool NetworkSystem::netSend ( Event& e, int sock_i )
{
	TRACE_ENTER ( (__func__) );
	if ( sock_i == -1 ) { // Caller wishes to send on any outgoing socket
		sock_i = netFindOutgoingSocket ( true );
		if ( sock_i == -1 ) { 
			TRACE_EXIT ( (__func__) );
			return false;
		}
	}
	if ( m_socks[ sock_i ].txSoFar > 0 ) {
		TRACE_EXIT ( (__func__) );
		return false;
	}
	
	int result;
	e.rescope ( "nets" );
	if ( e.mData == 0x0 ) { 
		TRACE_EXIT ( (__func__) );
		return false;
	}

	e.serialize ( ); // Prepare serialized buffer
	char* buf = e.getSerializedData ( );
	int len = e.getSerializedLength ( );
	netPrintf ( PRINT_FLOW, "TX %d bytes, %s", e.getSerializedLength ( ), e.getNameStr ( ).c_str ( ) );

	NetSock& s = m_socks[ sock_i ];
	if ( m_socks[ sock_i ].mode == NET_TCP ) { // Send over socket
		if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) {
			result = send ( s.socket, buf, len, 0 ); // TCP/IP
			if ( result > 0 && result != len ) {
				s.txSoFar = result;
				s.txPktSize = len;
				memcpy ( s.txBuf, buf, len );
				s.txBuf[ len ] = '\0';
				netPrintf ( PRINT_FLOW, "1 Partial TX: %d < %d (%d)", result, len, s.txSoFar );
				TRACE_EXIT ( (__func__) );
				return true;
			} 
			if ( result == len ) {
				TRACE_EXIT ( (__func__) );
				return true;
			}
		} else {
			#ifdef BUILD_OPENSSL

				fd_set sockSet;
				int fd = SSL_get_fd ( s.ssl );
				FD_ZERO ( &sockSet );
				FD_SET ( fd, &sockSet );	
				if ( select ( fd + 1, NULL, &sockSet, NULL, NULL ) < 0 ) {
					TRACE_EXIT ( (__func__) );
					return false;
				}
				
				result = SSL_write ( s.ssl, buf, len );
				if ( result <= 0 ) {	
					if ( netNonFatalErrorSSL ( sock_i, result ) ) { 
						str msg = netGetErrorStringSSL ( result, s.ssl );
						s.txSoFar = 1;
						netPrintf ( PRINT_ERROR, "Non fatal SSL error: Return: %d: %s", result, msg.c_str ( ) );
						TRACE_EXIT ( (__func__) );
						return false;
						return SSL_ERROR_WANT_WRITE;
					} else {
						str msg = netGetErrorStringSSL ( result, s.ssl );
						netPrintf ( PRINT_ERROR, "1 Failed ssl write (2): Return: %d: %s", result, msg.c_str ( ) );
					}
				} else if ( result < len ) {
					s.txSoFar = result;
					s.txPktSize = len;
					memcpy ( s.txBuf, buf, len );
					s.txBuf[ len ] = '\0';
					netPrintf ( PRINT_ERROR, "1 Partial TX: %d < %d (%d)", result, len, s.txSoFar );
					std::cin.get();
					TRACE_EXIT ( (__func__) );
					return true;
				}
			#endif
		}  
	} else {
		int addr_size = sizeof( m_socks[ sock_i ].dest.addr );
		result = sendto ( s.socket, buf, len, 0, (sockaddr*) &s.dest.addr, addr_size ); // UDP
	}
	if ( result <= 0 ) {
		TRACE_EXIT ( (__func__) );
		return false;
	}
	TRACE_EXIT ( (__func__) );
	return CXSocketBlockError ( ) || netCheckError ( result, sock_i ); // Check connection
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
	CXSocketUpdateAddr ( sock_i, true );
	CXSocketUpdateAddr ( sock_i, false );
	TRACE_EXIT ( (__func__) );
	return 1;
}

int NetworkSystem::netSocketBind ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock* s = &m_socks [ sock_i ];
	int addr_size = sizeof ( s->src.addr );
	netPrintf ( PRINT_VERBOSE, "Bind: %s, port %i", ( s->side == NET_CLI ) ? "cli" : "srv", s->src.port );
	int ret = bind ( s->socket, (sockaddr*) &s->src.addr, addr_size );
	if ( netIsError ( ret ) ) {
		netPrintf ( PRINT_ERROR, "Cannot bind to source: Return: %d", ret );
	}
	TRACE_EXIT ( (__func__) );
	return ret;
}

int NetworkSystem::netSocketConnect ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock* s = &m_socks[ sock_i ];
	int addr_size = sizeof ( s->dest.addr ), ret;
	netPrintf ( PRINT_VERBOSE_HS, "%s connect: ip %s, port %i", (s->side == NET_CLI) ? "cli" : "srv", getIPStr (s ->dest.ipL ).c_str ( ), s->dest.port );
	if ( ( ret = connect ( s->socket, (sockaddr*) &s->dest.addr, addr_size ) ) < 0 ) {
		netPrintf ( PRINT_ERROR_HS, "Socket connect error: Return: %d", ret );
		TRACE_EXIT ( (__func__) );
		return -1;
	}	
	TRACE_EXIT ( (__func__) );
	return 0;
}

int NetworkSystem::netSocketListen ( int sock_i )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];
	netPrintf ( PRINT_VERBOSE, "Listen: port %i", s.src.port );
	int ret = listen ( s.socket, SOMAXCONN );
	if ( CXSocketError ( ret ) ) {
		netPrintf ( PRINT_ERROR, "TCP listen error: Return: %d", ret );
	}
	TRACE_EXIT ( (__func__) );
	return ret;
}

int NetworkSystem::netSocketAccept ( int sock_i, SOCKET& tcp_sock, netIP& cli_ip, netPort& cli_port )
{
	TRACE_ENTER ( (__func__) );
	NetSock& s = m_socks [ sock_i ];
	struct sockaddr_in sin;
	int addr_size = sizeof ( sin );
	tcp_sock = accept ( s.socket, (sockaddr*) &sin, (socklen_t *) (&addr_size) );

	if ( CXSocketIvalid ( tcp_sock ) ) {
		netPrintf ( PRINT_ERROR_HS, "TCP accept error: Return: %d", tcp_sock );
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
				if ( ( result = SSL_read( s.ssl, buf, buflen ) ) <= 0 ) {	
					if ( netNonFatalErrorSSL ( sock_i, result ) ) { 
						TRACE_EXIT ( (__func__) );
						return SSL_ERROR_WANT_READ;
					} else {
						str msg = netGetErrorStringSSL ( result, s.ssl );
						netPrintf ( PRINT_ERROR, "Failed at ssl read: Returned: %d: %s", result, msg.c_str ( ) );
					}
				}
			#endif
		}
	} else {
		result = recvfrom ( s.socket, buf, buflen, 0, (sockaddr*) &s.src.addr, &addr_size ); // UDP
	}
	if ( result == 0 ) {
		netManageFatalError ( sock_i ); // Peer has unexpected shutdown
		netPrintf ( PRINT_ERROR, "Unexpected shutdown: Result: %d", result );
		TRACE_EXIT ( (__func__) );
		return ECONNREFUSED;
	}	
	bool outcome = CXSocketBlockError ( ) || netCheckError ( result, sock_i ); // Check connection
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
    /* if ( select ( s.socket + 1, NULL, &sockSet, NULL, &tv ) > 0 ) { 
        socklen_t len = sizeof ( so_error );
        getsockopt ( s.socket, SOL_SOCKET, SO_ERROR, &so_error, &len );
    } */
    TRACE_EXIT ( (__func__) );
    return so_error == 0; // Use select and result from getsockopt to check if connection is done
}

bool NetworkSystem::netSocketIsSelected ( fd_set* sockSet, int sock_i )
{
	NetSock& s = m_socks[ sock_i ];
	if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) { 
		return FD_ISSET ( s.socket, sockSet );
	} 
	#ifdef BUILD_OPENSSL
		if ( s.ssl ) {
			return FD_ISSET ( SSL_get_fd ( s.ssl ), sockSet );
		}
	#else
		return false;
	#endif
	return false;
}

int NetworkSystem::netSocketSelect ( fd_set* sockReadSet, fd_set* sockWriteSet ) 
{
	TRACE_ENTER ( (__func__) );
	if ( m_socks.size ( ) == 0 ) {
		TRACE_EXIT ( (__func__) );
		return 0;
	}

	int result, maxfd =- 1;
	NET_PERF_PUSH ( "socklist" );
	FD_ZERO ( sockReadSet );
	FD_ZERO ( sockWriteSet );
	for ( int n = 0; n < (int) m_socks.size ( ); n++ ) { // Get all sockets that are Enabled or Connected
		NetSock& s = m_socks[ n ];
		if ( s.state != STATE_NONE && s.state != STATE_TERMINATED && s.state != STATE_FAILED ) {
			if ( s.security == NET_SECURITY_PLAIN_TCP || s.state < STATE_SSL_HANDSHAKE ) { 
				FD_SET ( s.socket, sockReadSet );
				if ( s.txPktSize > 0 ) {
					FD_SET ( s.socket, sockWriteSet );
				}
				if ( (int) s.socket > maxfd ) maxfd = s.socket;
			} else { 
				#ifdef BUILD_OPENSSL
					int fd = SSL_get_fd ( s.ssl );
					FD_SET ( fd, sockReadSet );	
					if ( s.txPktSize > 0 ) {
						FD_SET ( fd, sockWriteSet );	
					}
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
	result = select ( maxfd, sockReadSet, sockWriteSet, NULL, &tv ); // Select all sockets that have changed
	NET_PERF_POP ( );
	TRACE_EXIT ( (__func__) );
	return result;
}

str NetworkSystem::netPrintf ( int flag, const char* fmt_raw, ... )
{	
	if ( ( flag == PRINT_VERBOSE || flag == PRINT_VERBOSE_HS ) && ! m_printVerbose ) {
		return str("");
	}
	if ( flag == PRINT_FLOW && ! m_printFlow ) {
		return str("");
	}

	str tag;
    char buffer[ 2048 ];
    if ( flag == PRINT_ERROR_HS ) {
		tag = "    ";
		flag = PRINT_ERROR;
	} else if ( flag == PRINT_VERBOSE_HS ) {
		tag = "    ";
		flag = PRINT_VERBOSE;
	} else {
		tag = "";
	}
	
    va_list args;
    va_start ( args, fmt_raw );
    vsnprintf ( buffer, sizeof ( buffer ), fmt_raw, args );
    va_end ( args );
    str msg = str ( buffer ) + "\n";
	switch ( flag ) {
		case PRINT_VERBOSE:
			if ( m_printVerbose ) {
				msg = tag + msg;
				dbgprintf ( msg.c_str ( ) );
			}
			break;
		case PRINT_FLOW:
			if ( m_printFlow ) {
				msg = tag + msg;
				dbgprintf ( msg.c_str ( ) );
			}
			break;
		case PRINT_ERROR:
			//str error_str = CXGetErrorMsg ( error_id ); // Used to be: return error_id; 
			str delim = tag +  "=================================================\n";
			msg = delim + tag + str("ERROR: ") + msg + delim;
			dbgprintf ( msg.c_str ( ) );
			break;
	}
	return msg;
}

bool NetworkSystem::netIsError ( int result )
{
	TRACE_ENTER ( (__func__) );
	if ( CXSocketError ( result ) ) { 
		TRACE_EXIT ( (__func__) );
		return true; 
	}
	TRACE_EXIT ( (__func__) );
	return false;
}

str NetworkSystem::getIPStr ( netIP ip )
{
	TRACE_ENTER ( (__func__) );
	str ipstr = CXGetIpStr ( ip );
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

void NetworkSystem::netSetSelectInterval ( int time_ms ) 
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

bool NetworkSystem::netSetSecurityLevel ( int levels )
{
	m_security = 0;
	if ( levels & NET_SECURITY_PLAIN_TCP ) {
		m_security |= NET_SECURITY_PLAIN_TCP;
	}
	if ( levels & NET_SECURITY_OPENSSL ) {
		m_security |= NET_SECURITY_OPENSSL;
	}
	return ( m_security | levels ) == m_security;
}

bool NetworkSystem::netSetSecurityLevel ( int levels, int sock_i )
{
	m_security = 0;
	if ( levels & NET_SECURITY_PLAIN_TCP ) {
		m_socks[ sock_i ].security |= NET_SECURITY_PLAIN_TCP;
	}
	if ( levels & NET_SECURITY_OPENSSL == NET_SECURITY_OPENSSL ) {
		m_socks[ sock_i ].security |= NET_SECURITY_OPENSSL; 
	}
	return ( m_socks[ sock_i ].security | levels ) == m_security;
}

//----------------------------------------------------------------------------------------------------------------------

bool NetworkSystem::netSetPathToPublicKey ( str path )
{	
	char msg[ 2048 ];
	str found_path;
	if ( ! getFileLocation ( path, found_path ) ) {
		sprintf ( msg, "Public key not found: %s", path.c_str ( ) );
		netPrintf ( PRINT_ERROR, msg );
		return false;
	}
	m_pathPublicKey = found_path;	
	return true;
}

bool NetworkSystem::netSetPathToPrivateKey ( str path )
{
	char msg[ 2048 ];
	str found_path;
	if ( ! getFileLocation ( path, found_path ) ) {
		sprintf ( msg, "Private key not found: %s", path.c_str ( ) );
		netPrintf ( PRINT_ERROR, msg );
		return false;	
	}
	m_pathPrivateKey = found_path;	
	return true;
}

bool NetworkSystem::netSetPathToCertDir ( str path )
{
	char buf[ 2048 ];
	strncpy ( buf, path.c_str ( ), 2048 );
	addSearchPath ( buf );
	m_pathCertDir = path;
	return true;
}

bool NetworkSystem::netSetPathToCertFile ( str path )
{
	char msg[ 2048 ];
	str found_path;
	if ( ! getFileLocation ( path, found_path ) ) {
		sprintf ( msg, "Cert file not found: %s\n", path.c_str ( ) );
		netPrintf ( PRINT_ERROR, msg );
		return false;	
	}
	m_pathCertFile = found_path;		
	return true;
}

//----------------------------------------------------------------------------------------------------------------------
// -> END <-
//----------------------------------------------------------------------------------------------------------------------
