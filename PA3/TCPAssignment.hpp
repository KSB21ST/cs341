/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

#define MSS 1460
#define DATA_TIMEOUT 10 * 1000 * 1000
#define W_SIZE 10

namespace E {

struct my_sockaddr_in {
  sa_family_t sin_family; 
  in_port_t sin_port;
  in_addr sin_addr;
};

struct read_meta {
  UUID syscallUUID;
  int count;
  void *buf;
  bool waiting;
};

struct write_meta {
  UUID syscallUUID;
  int count;
  void *buf;
  bool waiting;
};

struct Payload{
  // char payload[1024];
  void *payload;
  size_t offset;
  size_t size;
};

struct sPacket {
  uint32_t next_seq_num;
  Time send_time;
  UUID key;
};

struct Socket{
  int pid;
  int fd;
  int domain;
  int type;
  int protocol;
  int backlog;
  int seq_num;
  int ack_num;
  bool bound;
  bool passive;
  bool accepted;
  bool connected;
  UUID syscalluuid;
  sockaddr_in *accept_addr;
  struct my_sockaddr_in *my_addr;
  struct my_sockaddr_in *peer_addr;
  vector<Socket *> acceptQueue;
  vector<Socket *>listenQueue;

  //for read, write
  struct read_meta *read_wait;
  struct Payload *read_buf;
  Socket *cli_sock;

  vector<sPacket *> sendPackets;
  uint32_t last_ack_num;
  uint64_t EstimatedRTT;
  uint64_t DevRTT;
  uint64_t TimeoutInterval;

  vector<Packet>pktq;
  int start;
  int end;
  struct write_meta *write_wait;
  int received;
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

  Socket * find_socket(int pid, int socket_fd);
  Socket * FindMySocket(uint32_t ip, uint16_t port);
  sPacket * find_packet(Socket *socket, uint32_t ack_num);
  int remove_packet(Socket *socket, uint32_t ack_num);
  int remove_socket(int pid, int socket_fd);
  int check_overlap(int pid, int socket_fd, in_addr addr, in_port_t port);
  int check_overlap2(int pid, int socket_fd, in_addr_t addr, in_port_t port);
  bool check_port(int pid, int socket_fd, in_port_t port);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

  //my implementations
  virtual void syscall_socket (UUID syscallUUID, int pid,
                        int domain, int type, int protocol);
  virtual  void syscall_bind (UUID syscallUUID, int pid,
                              int socket_fd, struct sockaddr *address,
                              socklen_t address_len);
  virtual void syscall_getsockname (UUID syscallUUID, int pid,
                                   int sock_fd, struct sockaddr *address,
                                   socklen_t *address_len);
  virtual void syscall_close(UUID syscallUUID, int pid, int fd);
  virtual void syscall_getpeername (UUID syscallUUID, int pid,
                                        int sock_fd, struct sockaddr *address,
                                        socklen_t *address_len);
  virtual void syscall_connect (UUID syscallUUID, int pid,
                                    int sock_fd, struct sockaddr *address,
                                    socklen_t address_len);
  virtual void syscall_listen(UUID syscallUUID, int pid, 
                                   int sock_fd, int backlog);
  virtual void syscall_accept(UUID syscallUUID, int pid, 
                                   int socket_fd, struct sockaddr *address, socklen_t *address_len);
  virtual void syscall_read (UUID syscallUUID, int pid,
                                  int sockfd, void *buf, size_t count);
  virtual void syscall_write (UUID syscallUUID, int pid,
                                   int fd, void *buf, size_t count);
  vector<Socket *> Socketfd;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */