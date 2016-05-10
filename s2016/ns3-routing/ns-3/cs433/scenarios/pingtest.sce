* LS VERBOSE ALL OFF
* DV VERBOSE ALL ON
* APP VERBOSE ALL OFF
* LS VERBOSE STATUS ON
* LS VERBOSE ERROR ON
* DV VERBOSE STATUS ON
* DV VERBOSE ERROR ON
* APP VERBOSE STATUS ON
* APP VERBOSE ERROR ON
* LS VERBOSE TRAFFIC ON
* APP VERBOSE TRAFFIC ON

# Advance Time pointer by 45 seconds. Allow the routing protocol to stabilize.
TIME 45000

1 DV DUMP NEIGHBORS

# Ping from node 1 to node 3.  NOTE: shortest path is 1->2->3
1 DV PING 3 ping!

# Bring down all links of node 2
NODELINKS DOWN 2

# Advance Time pointer by 60 seconds.  Allow the routing protocol to stabilize.
TIME 60000

# Ping from node 1 to node 3.  NOTE: only available path now 1->0->4->3
1 DV PING 3 second_ping!

# Demo complete
QUIT
