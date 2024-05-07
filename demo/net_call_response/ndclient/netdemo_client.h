
#ifndef NETDEMO_CLIENT
	#define NETDEMO_CLIENT

	#include "network_system.h"

	class NDClient : public NetworkSystem {
	public:		
		// networking 
		void Start ( std::string srv_addr );
		void Reconnect ();
		void Close ();		
		int Run ();				
		int Process (Event& e);
		static int NetEventCallback ( Event& e, void* this_ptr );	

		// demo app protocol
		void RequestWords ( int num );		

		int			mHasConnected;

	private:
		int			mSock;					// this is my socket (local) to access the server
		int			mSeq;
		std::string mSrvAddr;
		
		TimeX		m_currtime;
		TimeX		m_lasttime;

	};

#endif
