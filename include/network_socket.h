//---------------------------------------------------------------------
//
// Network System
// Quanta Sciences, Rama Hoetzlein (c) 2007-2020
// 
//---------------------------------------------------------------------

#ifndef DEF_NET_SOCK
	#define DEF_NET_SOCK

	#include <vector>	

    #ifdef _WIN32
        #include <winsock2.h>			// Winsock Ver 2.0
		#include <ws2tcpip.h>
		#pragma comment( lib, "ws2_32.lib")

		typedef int		socklen_t;

	#elif __ANDROID__
		#include <sys/socket.h>			// Non-windows Platforms (Linux, Cygwin)
		#include <netinet/in.h>
		#include <arpa/inet.h>
		#include <sys/time.h>
		#include <sys/types.h>
		#include <netdb.h>
		#include <unistd.h>
		#include <fcntl.h>
		#include <errno.h>
		#include <sys/ioctl.h>
		typedef int SOCKET;
        #elif __linux__
                #include <sys/socket.h>			// Non-windows Platforms (Linux, Cygwin)
		#include <netinet/in.h>
		#include <arpa/inet.h>
		#include <sys/time.h>
		#include <sys/types.h>
		#include <netdb.h>
		#include <unistd.h>
		#include <fcntl.h>
		#include <errno.h>
		#include <sys/ioctl.h>
		typedef int SOCKET;
    #endif

	#include <openssl/bio.h>					// MP: Same cross-platform ? Tentative: Yes
	#include <openssl/ssl.h>
	#include <openssl/err.h>

	#include "event_system.h"

	#define NET_ERR						-1
	
	#define NET_CLI						0 // sides
	#define	NET_SRV						1	
	
	#define NET_TCP						0 // modes
	#define NET_UDP						1	
	
	#define NET_SECURITY_UNDEF			-2 // security types
	#define NET_SECURITY_FAIL			-1 
	#define NET_SECURITY_PLAIN_TCP		0
	#define NET_SECURITY_OPENSSL		1
	#define NET_SECURITY_DTLS			2
	
	#define NET_ANY						0 // types
	#define NET_BROADCAST				1		
	#define NET_SEARCH					2	
	#define NET_CONNECT					3	

	#define NET_OFF						0 // stats
	#define NET_ENABLE					1
	#define STATE_SSL_HANDSHAKE			2
	#define STATE_CONNECTED				3
	#define STATE_FAILED				4
	#define STATE_TERMINATED			5
	

	// Network Address Abstraction
	struct HELPAPI NetAddr {
	public:
        NetAddr ( int t, std::string n, netIP i, int p ) { type = t; name = n; ipL = i; convertIP(i); port = p;}
		NetAddr ()  { type = NET_OFF; name = ""; ipL = 0; convertIP(0); port = 0; }

		void convertIP ( netIP i ) {
#ifdef _WIN32
			ip.S_un.S_addr = i;
#elif __ANDROID__
			ip.s_addr = i;
#elif __linux__
			ip.s_addr = i;
#endif
		}

		std::string		name;
		char			type;			// type (any, broadcast, search, connect)
		int				sock;
		int				port;
		netIP			ipL;

#ifdef _WIN32
		in_addr			ip;
#elif __ANDROID__
                struct in_addr	        ip;
#elif __linux__
	        struct in_addr          ip;
#endif
		sockaddr_in		addr;
	};

	// Network Socket Abstraction
	struct HELPAPI NetSock {
		eventStr_t			sys;				// system
		char				side;				// side (client, server)
		char				mode;				// mode (TCP, UDP)		
		char				state;				// stat (off, connected)
		timeval				timeout;		
		NetAddr				src;				// source socket (ip, port, name, sockID)		
		NetAddr				dest;				// dest socket (ip, port, name, sockID)	
		SOCKET				socket;				// hard socket
		bool				blocking;			// is blocking
		bool				broadcast;			// is broadcast
		bool				tcpFallback;		// allow plain TCP if OpenSSL fails
		int 				security; 			// indicates the security level; e.g., OpenSSL
		int 				reconnectLimit; 	// limits the number of reconnection attempts 
		int 				reconnectBudget; 	// remaining allowed reconnect attempts
		
		std::string srvAddr;
		int srvPort;
		
		SSL_CTX 				*ctx; 			// MP: Need to read up on these before commenting; Same cross-platform ? Tentative: Yes
		SSL 					*ssl;			// MP:
		BIO 					*bio;			// MP:
	};


#endif
