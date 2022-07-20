README.txt

# RoutingAssignment.hpp

`
class RoutingAssignment{
   …
   UUID global_timer;
   map < uint32_t, uint32_t > routing_td; 
   vector < uint32_t > neighbors;
   vector< uint32_t > links;
   map< uint32_t, uint32_t > my_links;
   virtual void printLinkCost();
   virtual void connection_state ();
   …
}
`

This is the newly added instances in class RoutingAssignment. ‘global_timer’ is used for adding/canceling timers during initializing + regularly responding. 
‘routing_td’ is the routing table implemented as a map. The key is the IP address, and the value is the metric value. 
‘links’ is a vector for the ip addresses that the current router has for other connections. 
‘my_links’ is a connection table for the current router. It is also a map, where the key is the ip of the peer, and the value is the ip of the current router. Thus, if we collect all the values (not key) of my_links, it should be the same with the values inside ‘links’.
printLinkCost() is an additional function for printing all the metrics of the links connected with IP address in ‘links’
connection_state() is a function that prints all the pairs inside ‘my_links’

# RoutingAssignment.cpp

*initialize(…)
Initialize for each router. The main funtionality is sending request to immediate neighbor using broadcasting. At this point, command and version in RIP header are set to 1. Address family and ip address in RIP entry are set to 0. And metric is set to 301(unreachable). Becuase router can have multiple ports, every ports send request packest using while loop. 
The IP address corresponding to the port is obtained through the getIPAddr(port_num) method. Use the corresponding IP as the source ip of the packet, and use 255.255.255.255, which is the broadcast ip, for the destination ip. Also, port uses 520 for both source and destination. The RIP header and entry are added to the data part of the UDP packet, and calculate the checksum. Then the packet is sended.
If there is no corresponding IP address, break the while loop. 
We implemented to use one timer per router. Therefore, after the while loop is breaked, in other words packet sending is finished, addTimer(-1, 30*1000*1000*1000) is used to periodically update the routing table. According to RFC1058, set the timer interval to 30 second(30*1000*1000*1000 nanosecond). After that, free the memory, which is allocated at the first of initialize, for rip_entry and rip_header.

*ripQuery(…)
Look up the given IP address in the argument in the routing table. The routing table is a form of a map, so just find the value in match with the key as the given IP address, and return the value. If the IP address is not inside the routing table, return 400.

*packetArrived(…)

There are two kinds of packets that arrive. First is the packets that arrives as a request from the peer, and the second is the packet that arrives as response from the peer.

In the case of packet arrived as request, this is the request that arrived from the initial broadcast. In this case, we should send our routing tables to the peer. I implemented a code that sends each of the routing table pair as an entry and included this information in the packet. For each pair in the routing table, if the IP address was owned by ‘me’ that is, if the IP address was included in the values of ‘my_links’, the metric value is 0. Otherwise, it is the value in the routing table. 
Also, all of the ip addresses arrived as request is saved in the ‘my_links’ table, because this means that the peer address is a neighbor to the current router.

In the case of packet arrived as response, first, we figure out how many entries are included in the arrived packet. Then, iterate through the entries. We check if the IP address in the entry is included in the routing table. If it is not, add this IP address to our ip table, and if it is already included in the rouging table, we compare the value of the ‘cost with the peer that sent the request + value of the metric’ and the original value in the routing table.

*timercallback(…)

Initially, we should add the timer when we initially broadcast to our neighbors in initialize(…). Then, we constantly send our routing table to our neighbors (broadcast) for every thirty seconds. The structure of the packet that we broadcast inside timercallback(…) is the same with the packet that we send in response to the request in packetArrived(…).