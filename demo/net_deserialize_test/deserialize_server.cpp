

#include "deserialize_server.h"

#include "network_system.h"
#include <assert.h>

int Server::NetEventCallback (Event& e, void* this_pointer) {
    Server* self = static_cast<Server*>(this_pointer);
    return self->Process ( e );
}


void Server::Start (int inject)
{
	bool bDebug = true;
	bool bVerbose = true;

	m_inject = inject;

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

	BuildTestBuffer( m_inject );
}

void Server::Close ()
{
	
}


int Server::BuildTestBuffer( int test_id )
{
	if (test_id < 0) return 0;

	// Test deserialization
	// OLD code - netRecieveData,      before 6/25/2024 - will   PASS easy test, FAIL hard test.
	// NEW code - netDeserializeEvents, after 6/25/2024 - should PASS easy test, PASS hard test.

	int test_start_sz, test_inc_sz, test_cnt;
	
	switch (test_id) {
	case 0:										// easy test - assumes event size /w header matches packet size
		test_start_sz = TEST_TCP_PACKET_SIZE;	// all events are size of TCP window
		test_inc_sz = 0;
		test_cnt = 10;
		break;
	case 1:										// hard test - large packets, may be partial, headers may cross packet boundary		
		test_start_sz = TEST_TCP_PACKET_SIZE - 4;
		test_inc_sz = 8;
		test_cnt = 20;
		break;
	case 2:										// hard test 2 - small packets, many fill a single packet
		test_start_sz = 64;
		test_inc_sz = 8;
		test_cnt = 20;
		break;
	};

	int event_sz = test_start_sz;
	int header_sz = Event::staticSerializedHeaderSize();
	int payload_sz;
	std::string str;

	// compute test size
	m_testlen = 0;
	for (int i = 0; i < test_cnt; i++) {
		m_testlen += event_sz;
		event_sz += test_inc_sz;
	}
	// allocate test buf	
	if (m_testbuf != 0) free(m_testbuf);
	m_testbuf = (char*) malloc(m_testlen);
	m_testptr = m_testbuf;
	
	char buf[65535];

	event_sz = test_start_sz;
	printf("-------------------\n");
	printf("TEST INPUT - Network should deserialize the following events:\n");
	for (int i = 0; i < test_cnt; i++) {

		// make event
		Event e = new_event(event_sz - header_sz, 'app ', 'cTst', 0, getNetPool());
		payload_sz = event_sz - header_sz - sizeof(int);		// event = header + payload + verify_int
		str = std::string(payload_sz, i + 65);					// make test str of identical chars
		memcpy(buf, str.c_str(), payload_sz);
		e.attachBuf( buf, payload_sz);
		e.attachInt(event_sz);								// put verification length at end of event
		printf("  #%d, %d bytes, %s, %.5s\n", i, event_sz, e.getNameStr().c_str(), str.c_str() );

		// copy entire event, including header, into test buf
		int sz = e.getSerializedLength();
		assert(sz == event_sz);
		memcpy( m_testptr, e.serialize(), sz );
		
		m_testptr += event_sz;
		event_sz += test_inc_sz;								// continually increase event_sz
	}
	printf("TEST READY..\n");
	printf("-------------------\n");
	
	return m_testlen;
}


int Server::Run ()
{
	// Injection test

	if (m_inject >= 0 ) {		

		// build test buffer with multiple events of various sizes
		int PKSZ = TEST_TCP_PACKET_SIZE;
		dbgprintf("RUNNING INJECTION TEST..\n");		
		dbgprintf("  TEST TCP PACKET WINDOW: %d\n", PKSZ);

		// inject test buffer in chunks of TCP_PACKET_SIZE		
		int len = m_testlen;
		m_testptr = m_testbuf;
		int cnt = ceil( float(m_testlen) / PKSZ);
		dbgprintf("  netReceiveByInjectedBuf.. %d total bytes, %d packet sz, %d packets\n", m_testlen, PKSZ, cnt );

		cnt = 0;
		while (len > 0) {						  
			
			netReceiveByInjectedBuf ( 1, m_testptr, imin( PKSZ, len ) );		// inject next packet

			m_testptr += PKSZ;
			len -= PKSZ;
			cnt++;
		}
	}

	// process event queue
	return netProcessQueue ();
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

	char buf[65535];

	// Process Network events
	e.startRead ();
	switch (e.getName()) {
	case 'sOkT':				// Connection to client complete. (telling myself)		
		sock = e.getInt();		// server sock		
		dbgprintf ( "  Connected to client: #%d\n", sock );		
		break;
	case 'cFIN':				// Client closed connection		
		sock = e.getInt();
		dbgprintf ( "  Disconnected client: #%d\n", sock );		
		break;	
	case 'cTst': {
		// recv test event
		int payload_sz = e.getDataLength() - sizeof(int);
		e.getBuf( buf, payload_sz );
		int verify_len = e.getInt();

		int event_len = e.getDataLength() + Event::staticSerializedHeaderSize();

		if (event_len == verify_len) {
			dbgprintf("  App. Got event: %d, cTst, %.5s\n", event_len, buf );
		}
		else {
			dbgprintf("  App. **ERROR** Got event: %d, should be %d bytes.\n", event_len, verify_len );
		}
		} break;
	default:
		dbgprintf("  App. **ERROR** Unhandled message: %s\n", e.getNameStr().c_str());
		return 0;
		break;
	};
	
	return 1;
}

