# Socket structure

we made Socket structure in the TCPAssignment.hpp. To handle sockets efficiently, we save all sockets in vector<Socket *> Socketfd.

struct Socket {
    int pid;				// process id
    int fd;					// file descriptor
    int domain;				// must be AF_INET in KENS
    int type;				
    int protocol;				// IPPROTO_TCP
    int backlog;				// backlog (saved in listen(..., backlog))
    int seq_num;				// for 3-way handshake
    int ack_num;				// for 3-way handshake
    bool bound;				// T: this socket is bound / F: this socket is not bound
    bool passive;				// if the socket is listening, passive is true
    UUID syscalluuid;			// for saving syscallUUID
    sockaddr_in *accept_addr;			// save accept_addr for late accept
    struct my_sockaddr_in *my_addr;		// address of itself
    struct my_sockaddr_in *peer_addr;		// address of peer
    vector<Socket *> acceptQueue;		// established connection is pushed in this acceptQueue
    vector<Socket *> listenQueue;		// connection request is pushed in this listenQueue
};

- syscall_socket(...)
Create new file descriptor for new socket using createFileDescriptor(...) function. Then, create new Socket object and initialize its elements. Finally return file descriptor we made before.

- syscall_bind(...)
Find the corresponding socket using find_socket(...) function with pid and socket_fd. If value of bound of socket is true, then return -1 because it means double bind. If not, copy the address from parameter "address" to "socket->my_addr". Before returning, check is the pair of port and ip address overlaped or not. 

- syscall_listen(...)
Find the corresponding socket using find_socket(...) function with pid and sock_fd. "passive" of the Socket structure is setting to true. And "backlog" of the Socket structure is setting to "backlog" which is parameter of syscall_listen().

- syscall_getsockname(...)
Find the corresponding socket using find_socket(...) function with pid and sock_fd. Copy the address from socket->my_addr(socket is the Socket object that we found before) to empty address pointer "address".

- syscall_getpeername()
Find the corresponding socket using find_socket(...) function with pid and sock_fd. Copy the address from socket->peer_addr(socket is the Socket object that we found before) to empty address pointer "address".

- syscall_close(...)
Using arguments pid and fd, find socket which will be closed. Remove the file descriptor of socket with removeFileDescriptor(...) function. Finally, socket object is removed in the remove_socket(...) function.

# 3 way handshake

3way handshake is connection between client and server. First, the client and the server both creates sockets using socket() function. The server binds the socket with the IP address and pro number using bind() function. 

- syscall_connect(…)
The client sends a packet with flag SYN using connect() function. If the socket in connect() is not bound, client binds the socket inside connect(). The way we bind the socket Is using “my_addr” and “peer_addr” which is pointer of “my_sockaddr_in”  structure. “my_addr” saves the IP address, port number of the current environment it is created from(source). “peer_addr” includes the IP address and port number of the side that the socket should send the packet to(destination). The destination ip address and port number is received from the arguments of connect(). Also, we find the source IP address and port number through interface given in KENS. client port (source port) is a random number smaller than 65536, which is the maximum port number in TCP connection. After checking if the pair of IP address and port number is not used in other sockets (if it is used, identify another random number), use the random port number as client port number. After that, send the packet with flag SYN to server. We did not returnsystemcall yet, because we needed to block the system call of connect() until SYN | ACK flag arrived from server. This part is checked in packetArrived(…) function, and returnSystemcall is called in packetArrived function once the response is checked.

- syscall_accept(…)
First, we check accepted queue. This a queue for connections that should be accepted and not yet accepted. We should create a  new client socket for the connection for the client. This is done in packetArrived(…) when the server receives packet with flag SYN from client. Here, we fill out the peer_addr information in client socket with the source  IP address and source port number in the packet. We also make new file descriptor for the client socket. We filled the missing parts of the connection (which is actually a socket pointer) and pushed the client socket into the list of sockets (Socketfd). And then, we fill the address pointer that was given as argument in accept(…) with the information of peer_addr inside client socket.  Then, we returnsystemcall with the fd of the created client socket.
If the length of the accepted queue is 0, we do not call returnsystemcall. Instead, we save the address pointer we should fill out inside the socket. Then, accept(…) will be waiting for packet from client and when the packet arrives, packetArrived will handle the packet same as what was done in accept at the first paragraph and call returnsystemcall of client socket fd.

- packetArrived(…)
1) Flag SYN
This is a packet arrived from client to server in the first step of 3 way handshake. Inside this function, client socket is created including the information including source IP address and port number and destination IP address and port number. And then, if the listening queue has space, the created client socket is pushed to the listen queue. And than packet including flag of SYN and ACK is sent back to the client. 

2) Flag SYN & ACK
the packet is send from server to client and it's the 2nd step of 3-way handshake. So flag is changed to 16(only ACK is 1) and swap dst and src of TCP header in packet. Then, send this packet to server.

3) Flag ACK
Pull out one connection from the listen queue and put It inside accept queue.
Check if there is a pending accept(…) using the accept_addr in socket structure. If accept_addr is not null pointer, it means that there is a pointer that is needed to be filled. Then, do the same things that supposed to be done inside accept(…) function.

