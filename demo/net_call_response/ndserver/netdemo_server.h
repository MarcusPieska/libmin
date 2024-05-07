
#ifndef NETDEMO_SERVER
	#define NETDEMO_SERVER

	#include "network_system.h"

	class NDServer : public NetworkSystem {
	public:		
		// networking funcs
		void Start ();
		int Run ();		
		void Close ();
		int Process (Event& e);
		static int NetEventCallback ( Event& e, void* this_ptr );	

		// demo app
		void InitWords ();
		std::string ConvertToWords ( int num );
		void SendWordsToClient ( std::string msg, int sock );

	private:

		std::vector<std::string>		wordlist;

	};

#endif