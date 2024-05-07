
cmake ndserver/CMakeLists.txt -B../../../build/net_bulk_transfer/ndserver 
make -C../../../build/net_bulk_transfer/ndserver

cmake ndclient/CMakeLists.txt -B../../../build/net_bulk_transfer/ndclient 
make -C../../../build/net_bulk_transfer/ndclient
