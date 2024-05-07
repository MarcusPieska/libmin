
cmake ndserver/CMakeLists.txt -B../../../build/net_call_response/ndserver 
make -C../../../build/net_call_response/ndserver

cmake ndclient/CMakeLists.txt -B../../../build/net_call_response/ndclient 
make -C../../../build/net_call_response/ndclient
