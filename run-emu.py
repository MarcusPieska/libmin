import os
import time
import sys

duration = 5

paths = ["../build/ndserver/nd_server", "../build/ndclient/nd_client"]
addr = ["10.0.20.2", "10.0.10.1"]
intfs = ["h2-dev-r1", "h1-dev-r1"]
contexts = ["ip netns exec emu-h2", "ip netns exec emu-h1"]

for c, i in zip(contexts, intfs):
  timeout = "timeout -k %s %s" %(str(duration), str(duration)) 
  cmd = "tcpdump -i %s -w %s.pcap" %(i, i)
  run_command = "%s %s xterm -hold -e '%s' &" %(c, timeout, cmd)
  print("Running TCP dump on host interface ..." )
  print("Command: '%s'" %(run_command))
  os.system(run_command)
  

for p, a, c in zip(paths, addr, contexts): 
  #run_command = "xterm -hold -e '%s' &" %(p)
  if "server" in p:
    run_command = "%s xterm -hold -e '%s' &" %(c, p)
  #else:
  #  run_command = "%s xterm -hold -e '%s --addr %s' &" %(c, p, a)
  print("Running server executable in a new xterm window...\n")
  print("Command: '%s'" %(run_command))
  os.system(run_command)
  time.sleep(2)
  break
