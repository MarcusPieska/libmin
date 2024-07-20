
#ifdef _WIN32
	#include <conio.h>
#endif

#ifdef __linux__
	#include <stdio.h>
	#include <sys/ioctl.h>
	#include <termios.h>

	int _kbhit ( ) 
	{
		static const int STDIN = 0;
		static bool kbinit = false;
		if ( !kbinit ) {
			termios term;
			tcgetattr(STDIN, &term);
			term.c_lflag &= ~ICANON;
			tcsetattr ( STDIN, TCSANOW, &term );
			setbuf ( stdin, NULL );
			kbinit = true;
		}
		int bytes;
		ioctl ( STDIN, FIONREAD, &bytes );
		return bytes;
	}
#endif   

#include "bulk_client.h"
#include "bulk_server.h"

std::string get_addr ( int argc, char** argv )
{
    std::string addr = "127.0.0.1";
    for ( int i = 1; i < argc - 1; ++i ) {
        std::string arg = argv[i];
        if ( arg == "--addr" || arg == "-a" ) {
            addr = argv[++i];
        }
    }
    return addr;
}

bool str_exists_in_args ( int argc, char** argv, const char* to_find )
{
    for ( int i = 1; i < argc - 1; ++i ) {;
        if ( strcmp( argv[i], to_find ) == 0 ) {
            return true;
        }
    }
    return false;
}

int main ( int argc, char* argv [] )
{
	addSearchPath ( ASSET_PATH );

    //----- network performance profiling	
    // - libmin must be built with PROFILE_NET and USE_NVTX
    // - for CPU netRecv will show >1/ms due to perf printfs, use nvtx markers for better analysis
    // - for NVTX the nvToolsExt64_1.dll must be present
    // - enable this line to see profiling:
    // PERF_INIT ( 64, true, true, true, 0, "" );	

    if ( str_exists_in_args ( argc, argv, "-s" ) || str_exists_in_args ( argc, argv, "--server" ) ) { 
        Server srv ( "../trace-func-call-server" ); 
        srv.Start ( str_exists_in_args ( argc, argv, "--tcp" ) );
        while ( !_kbhit ( ) ) {
            srv.Run ( );
        }
        srv.Close ( );
    } else {
        Client cli ( "../trace-func-call-client" );
        cli.Start( get_addr ( argc, argv ), str_exists_in_args ( argc, argv, "--tcp" ) );
        while ( !_kbhit ( ) ) {

            cli.Run ( );
        }
        cli.Close ( );
    }
	return 1;
}
