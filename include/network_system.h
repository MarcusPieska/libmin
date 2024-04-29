//----------------------------------------------------------------------------------------------------------------------
// -> COMMENTS <-
//----------------------------------------------------------------------------------------------------------------------
//
// Network System
// Quanta Sciences, Rama Hoetzlein (c) 2007-2020
// Updated: R.Hoetzlein, 2024
//
// Features:
// - Client & Server model
// - Server maintains many client connections (socket list)
// - Buffered event queue
// - User-level callbacks to process event queue
// - Events hold packet payloads
// - Events have 4-byte names for efficient custom protocols
// - Events have attach/get methods to help serialize data
// - Event memory pools to handle many, small events
// - Arbitrary event size, regardless of TCP/IP buffer size
// - Graceful disconnect for unexpected shutdown of client or server
// - Reconnect for clients
// - Verbose error handling
// - C++ class model allows for multiple client/server objects
// - C++ class model with no inheritence (for simplicity)
// - Cross-platform and tested on Windows, Linux and Android
// 
//----------------------------------------------------------------------------------------------------------------------
// -> HEADER <-
//----------------------------------------------------------------------------------------------------------------------

#ifndef DEF_NETWORK_H
#define DEF_NETWORK_H

#include "common_defs.h"
#include "network_socket.h"
#include "event_system.h"
#include "time.h"

#ifdef __ANDROID__
	#include <sys/socket.h>
	#include <arpa/inet.h>
#endif

#include <cstdio>
#include <map>

#define NET_NOT_CONNECTED		11002
#define NET_DISCONNECTED		107

#define SRV_PORT			8000
#define SRV_SOCK			0
#define CLI_PORT			8001
#define CLI_SOCK			1

#define SRV_UDP			0
#define SRV_TCP			1
#define CLI_UDP			2
#define CLI_TCP			3

#define CONN_CLI		0
#define CONN_SRV		1
#define CONN_UDP		0
#define CONN_TCP		1

#define NET_BUFSIZE			65535		// Typical UDP max packet size

// -- NOTES --
// IP               = 20 bytes
// UDP = IP + 8     = 28 bytes
// TCP = IP + 28    = 48 bytes
// Event            = 24 bytes (header)
// TCP + Event      = 72 bytes (over TCP)

typedef int (*funcEventHandler) ( Event& e, void* this_ptr  );
typedef std::string str;

class EventPool;

class HELPAPI NetworkSystem {
	
public:
	NetworkSystem ();

	// Network System
	void netInitialize ( );
	void netCreate ( );
	void netDestroy ( );
	void netDebug ( bool v )	{ mPrintDebugNet = v; mPrintVerbose = v;  }
	void netVerbose ( bool v )	{ mPrintVerbose = v; }
	void netPrint ( bool verbose = false );
	str netPrintAddr ( NetAddr adr );
	bool setPathToPublicKey ( str path );
	bool setPathToPrivateKey ( str path );
	bool setPathToCertDir ( str path );
	bool setPathToCertFile ( str path );
	

	// Server - Network API
	void netStartServer ( netPort srv_port );
	void netServerListen ( int sock );

	// Client - Network API
	void netStartClient ( netPort srv_port, str srv_addr="127.0.0.1" );
	int netClientConnectToServer ( str srv_name, netPort srv_port, bool blocking = false );
	int netCloseConnection ( int localsock );
	int netCloseAll ( );

	// Event processing
	void netProcessEvents ( Event& e );
	int netProcessQueue ( void );
	int netRecieveSelect ( );
	int netRecieveAllData ( );
	int netRecieveData ( int sock_i );
	Event netMakeEvent ( eventStr_t name, eventStr_t sys );
	bool netSend ( Event& e );
	bool netSend ( Event& e, int mode, int sock );
	bool netSendLiteral ( str str, int sock );
	void netQueueEvent ( Event& e ); // Place incoming event on recv queue
	int netEventCallback ( Event& e ); // Processes network events (dispatch)
	void netSetUserCallback ( funcEventHandler userfunc )	{ mUserEventCallback = userfunc; }
	bool netIsConnectComplete ( int sock );
	bool netCheckError ( int result, int sock );
	int netError ( str msg, int error_id = 0 );

	// Sockets - abtract functions
	int netAddSocket ( int side, int mode, int status, bool block, NetAddr src, NetAddr dest );
	int netFindSocket ( int side, int mode, int type );
	int netFindSocket ( int side, int mode, NetAddr dest );
	int netFindOutgoingSocket ( bool bTcp );
	int netTerminateSocket ( int sock_i, int force=0 );
	NetSock& getSock ( int sock_i )			{ return mSockets[ sock_i ]; }
	str getSocketIP ( int sock_i )	{ return getIPStr( mSockets[ sock_i ].dest.ipL ); }

	// Sockets - socket-specific low-level functions
	void netStartSocketAPI ( );
	void netSetHostname ( );
	int netUpdateSocket ( int sock_i );
	int netSocketBind ( int sock_i );	
	int netSocketConnect ( int sock_i );
	int netSocketListen ( int sock_i );
	int netSocketAccept ( int sock_i,  SOCKET& tcp_sock, netIP& cli_ip, netPort& cli_port  );	
	int netSocketRecv ( int sock_i, char* buf, int buflen, int& recvlen); 
	
	bool netIsError ( int result );	// socket-specific error check
	void netReportError ( int result );
	str netPrintError ( int ret, str msg, SSL* sslsock=0x0 );
	int	netGetServerSocket ( int sock )	{ return ( sock >= mSockets.size ( ) ) ? -1 : mSockets[ sock ].dest.sock; }

	bool netIsQueueEmpty() { return ( mEventQueue.size ( ) == 0 ); }

	// Accessors
	TimeX				getSysTime ( )		{ return TimeX::GetSystemNSec ( ); }
	str					getHostName ( )		{ return mHostName; }
	bool				isServer ( )		{ return mHostType == 's'; }
	bool				isClient ( )		{ return mHostType == 'c'; }
	netIP				getHostIP ( )		{ return mHostIP; }
	str 				getIPStr ( netIP ip ); // return IP as a string
	netIP				getStrToIP ( str name );
	int					getMaxPacketLen ( )	{ return mMaxPacketLen; }
	EventPool*  getPool()					{ return mEventPool; }

public:
	#ifdef BUILD_OPENSSL
		void free_openssl ( int sock_i ); 
		int checkOpensslError ( int sock_i, int ret ); 
		
		int setupServerOpenssl ( int sock_i ); 
		int acceptServerOpenssl ( int sock_i );
		void checkServerOpensslHandshake ( int sock_i );
		
		int setupClientOpenssl ( int sock_i ); 
		int connectClientOpenssl ( int sock_i );	
		void checkClientOpensslHandshake ( int sock_i );	
    #endif
	
	void netServerListenReturnSig ( int sock_i );	

	EventPool*					mEventPool;	// Event Memory Pool
	EventQueue					mEventQueue; // Network Event queue

	uchar						mHostType;
	str							mHostName; // Host info
	netIP						mHostIP;
	int							mReadyServices;
	timeval						mRcvSelectTimout;

	std::vector< NetSock >		mSockets; // Socket list

	funcEventHandler			mUserEventCallback;	// User event handler

	// Incoming event data
	int							mDataLen;
	int							mEventLen;
	Event						mEvent;	// Incoming event

	// Network buffers
	int							mBufferLen;
	char*						mBufferPtr;
	char						mBuffer[ NET_BUFSIZE ];
	int							mMaxPacketLen;

	// Debugging
	int							mCheck;
	bool						mPrintDebugNet;
	bool						mPrintVerbose;
	bool						mPrintHandshake;

	#ifdef _WIN32
		struct fd_set			mSockSet;
	#elif __ANDROID__
		fd_set				    mSockSet;
	#elif __linux__
		fd_set				    mSockSet;
	#endif

private: 
	void sleep_ms ( int time_ms );
	unsigned long get_read_ready_bytes ( int sock_h );
	void make_sock_no_delay ( int sock_h );
	void make_sock_block ( int sock_h );
	void make_sock_non_block ( int sock_h );
	
	// Tracing and logging
	template<typename... Args> void verbose_print ( const char* fmt, Args... args );
	template<typename... Args> void debug_print ( const char* fmt, Args... args );
	template<typename... Args> void handshake_print ( const char* fmt, Args... args );
	template<typename... Args> void verbose_debug_print ( const char* fmt, Args... args );
	double get_time ( );
	void trace_setup ( const char* function_name );
	void trace_enter ( const char* function_name );
	void trace_exit ( const char* function_name );
	void net_perf_push ( const char* msg );
	void net_perf_pop ( );
	
	// Cross-platform socket interactions
	void SET_HOSTNAME ( );
	void SOCK_API_INIT ( );
	void SOCK_MAKE_BLOCK ( int sock_h, bool block = false );
	unsigned long SOCK_READ_BYTES ( int sock_h );
	int SOCK_INVALID ( int sock );
	int SOCK_ERROR ( int sock );
	str GET_ERROR_MSH ( int& error_id );
	void SOCK_UPDATE_ADDR ( int sock_i, bool src = true );
	void SOCK_CLOSE ( int sock_h );
	str GET_IP_STR ( netIP ip );
	
	struct timespec mRefTime;
	FILE* mTrace;
	int mIndentCount;
	str mPathPublicKey;
	str mPathPrivateKey;
	str mPathCertDir;
	str mPathCertFile;
};

extern NetworkSystem* net;

#endif 

//----------------------------------------------------------------------------------------------------------------------
// -> END <-
//----------------------------------------------------------------------------------------------------------------------
