/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

using namespace std;

namespace E {
bool is_first = true;
TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  Socketfd = vector<Socket *>();
}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  (void)syscallUUID;
  (void)pid;

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int,
    param.param2_int, param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    // param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int,
         static_cast<struct sockaddr*>(param.param2_ptr),
    (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int,
    param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
         static_cast<struct sockaddr*>(param.param2_ptr),
         static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int,
          static_cast<struct sockaddr *>(param.param2_ptr),
          (socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
          static_cast<struct sockaddr *>(param.param2_ptr),
          static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
         static_cast<struct sockaddr *>(param.param2_ptr),
         static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t head_len;
  uint8_t flag;
  uint16_t window_size;
  uint16_t checksum;
  packet.readData(26, &(src_ip), 4); //ip header: src_ip
  packet.readData(30, &(dst_ip), 4); //ip header: dst_ip
  packet.readData(34, &(src_port), 2); //tcp header: src_port
  packet.readData(36, &(dst_port), 2); //tcp header: dst_port
  packet.readData(38, &(seq_num), 4); //tcp header: sequence number
  packet.readData(42, &(ack_num), 4); //tcp header: ack number
  packet.readData(46, &(head_len), 1); //tcp header: head length 4bit + recv 6bit (4bit)
  packet.readData(47, &(flag), 1); //tcp header: recv(2bit) + flag (6bit)
  packet.readData(48, &(window_size), 2); //tcp header: window_size
  packet.readData(50, &checksum, 2); //tcp header: checksum
  checksum = ntohs(checksum);

  if(flag == 2){/*received this packet from server side from client connect: SYN */
    /*send packet with SYN + ACK to client*/
    // Socket *my_socket = FindMySocket(ntohs(dst_ip), ntohs(dst_port));
    Socket *my_socket = FindMySocket(dst_ip, dst_port);
    if(my_socket == nullptr){
      return;
    }

    Socket *cli_sock = new Socket;
    cli_sock->my_addr = new my_sockaddr_in;
    cli_sock->peer_addr = new my_sockaddr_in;
    cli_sock->pid = 0;
    cli_sock->fd = 0;
    cli_sock->domain = my_socket->domain;
    cli_sock->type = my_socket->type;
    cli_sock->protocol = my_socket->protocol;
    cli_sock->backlog = 0;
    cli_sock->seq_num = ack_num;
    cli_sock->ack_num = seq_num+1;
    cli_sock->bound = true;
    cli_sock->passive = false;
    cli_sock->accept_addr = nullptr;
    cli_sock->my_addr->sin_family = AF_INET;
    cli_sock->my_addr->sin_port = dst_port;
    (cli_sock->my_addr->sin_addr).s_addr = dst_ip;
    cli_sock->peer_addr->sin_family = AF_INET;
    cli_sock->peer_addr->sin_port = src_ip;
    (cli_sock->peer_addr->sin_addr).s_addr = src_ip;
    cli_sock->acceptQueue = vector<Socket *>();
    cli_sock->listenQueue = vector<Socket *>();
    if((int)(my_socket->listenQueue).size() < my_socket->backlog){
      (my_socket->listenQueue).push_back(cli_sock);
      size_t packet_size = 54;
      Packet pkt (packet_size);
      uint8_t h_len = 0x50;
      uint16_t window_size = 0xffff;
      uint8_t flag = 18;
      uint32_t _sequence_num = htonl(ack_num);
      uint32_t _ack_num = htonl(htonl(seq_num)+1);
      
      pkt.writeData(26, &dst_ip, 4); //ip header: source ip
      pkt.writeData(30, &src_ip, 4); //ip header: dst ip
      pkt.writeData(34, &dst_port,2); //tcp header: source port
      pkt.writeData(36, &src_port, 2); //tcp header: dst port
      pkt.writeData(46, &h_len, 1); //header length + reserve
      pkt.writeData(47, &flag, 1);
      pkt.writeData(48, &window_size, 2);
      pkt.writeData(38, &_sequence_num, 4); //tcp header: sequence num
      pkt.writeData(42, &_ack_num, 4); //tcp header: ack
      /*for checksum*/
      uint8_t temp[20];
      pkt.readData(34, temp, sizeof(temp));
      uint16_t _checksum = NetworkUtil::tcp_sum(dst_ip, src_ip, temp, 20);
      _checksum = htons(~_checksum);
      pkt.writeData(50, &_checksum, 2);
      sendPacket("IPv4", move(pkt));
    }
  }
  else if(flag == 18){/*received this packet from client side after connect: SYN + ACK*/
    Socket *my_socket = FindMySocket(dst_ip, dst_port);
    if(my_socket == nullptr){
      return;
    }
    size_t packet_size = 54;
    Packet pkt (packet_size);
    uint8_t h_len = 0x50;
    uint16_t window_size = 0xffff;
    uint8_t flag = 16;
    uint32_t sequence_num = htonl(ack_num);
    uint32_t ack_num = htonl(htonl(seq_num) + 1);

    pkt.writeData(26, &(my_socket->my_addr->sin_addr).s_addr, 4); //ip header: source ip
    pkt.writeData(30, &(my_socket->peer_addr->sin_addr).s_addr, 4); //ip header: dst ip
    pkt.writeData(34, &(my_socket->my_addr->sin_port),2); //tcp header: source port
    pkt.writeData(36, &(my_socket->peer_addr->sin_port), 2); //tcp header: dst port
    pkt.writeData(38, &sequence_num, 4); //tcp header: sequence num
    pkt.writeData(42, &ack_num, 4); //tcp header: ack
    pkt.writeData(46, &h_len, 1); //header length + reserve
    pkt.writeData(47, &flag, 1);
    pkt.writeData(48, &window_size, 2);
    /*for checksum*/
    uint8_t temp[20];
    pkt.readData(34, temp, sizeof(temp));
    uint16_t checksum = NetworkUtil::tcp_sum((my_socket->my_addr->sin_addr).s_addr, (my_socket->peer_addr->sin_addr).s_addr, temp, 20);
    checksum = htons(~checksum);
    pkt.writeData(50, &checksum, 2);
    sendPacket("IPv4", move(pkt));
    my_socket->passive = false;
    returnSystemCall (my_socket->syscalluuid, 0);
  }else if(flag == 16){
    Socket *my_socket = FindMySocket(dst_ip, dst_port);
    if(my_socket == nullptr){
      returnSystemCall (my_socket->syscalluuid, -1);
    }

    if((my_socket->listenQueue).size() >=0){
      Socket *cli_sock = my_socket->listenQueue.front();
      my_socket->listenQueue.erase (my_socket->listenQueue.begin());
      (my_socket->acceptQueue).push_back(cli_sock);
    }

    if(my_socket->accept_addr != nullptr){
      int fd;
      if ((fd = createFileDescriptor (my_socket->pid)) == -1)
      {
        returnSystemCall (my_socket->syscalluuid, -1);
        return;
      }
      Socket *cli_sock = my_socket->acceptQueue.front();
      my_socket->acceptQueue.erase (my_socket->acceptQueue.begin());
      cli_sock->fd = fd;
      cli_sock->pid = my_socket->pid; //my create same fd in different pid
      cli_sock->syscalluuid = my_socket->syscalluuid;
      Socketfd.push_back(cli_sock);

      sockaddr_in *addr = my_socket->accept_addr;
      addr->sin_family = cli_sock->peer_addr->sin_family;
      addr->sin_port = htons(cli_sock->peer_addr->sin_port);
      addr->sin_addr = cli_sock->peer_addr->sin_addr;
      my_socket->accept_addr = nullptr;
      returnSystemCall (my_socket->syscalluuid, fd);
      return;
    }
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  (void)payload;
}

//my impelementation
Socket * TCPAssignment::find_socket(int pid, int socket_fd)
{
  std::vector <Socket *>::iterator i;
  for (i = Socketfd.begin(); i != Socketfd.end(); i++)
  {
    Socket *s = (*i);
    if (s->pid == pid && s->fd == socket_fd){
      return s;
    }
  }
  return nullptr;
}

Socket * TCPAssignment::FindMySocket(uint32_t ip, uint16_t port)
{
  std::vector <Socket *>::iterator i;
  for (i = Socketfd.begin(); i != Socketfd.end(); i++)
  {
    Socket *s = (*i);
    if (((s->my_addr->sin_addr).s_addr == ip || (s->my_addr->sin_addr).s_addr == INADDR_ANY || ip == INADDR_ANY)
      && s->my_addr->sin_port == port){
      return s;
    }
  }
  return nullptr;
}


void TCPAssignment::syscall_socket (UUID syscallUUID, int pid,
                                   int domain, int type, int protocol)
{
  int fd;
  if ((fd = createFileDescriptor (pid)) == -1)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  Socket *socket = new Socket;
  socket->fd = fd;
  socket->pid = pid; //my create same fd in different pid
  socket->domain = domain;
  socket->type = type;
  socket->protocol = protocol;
  socket->backlog = 0;
  socket->seq_num = 0;
  socket->ack_num = 0;
  socket->bound = false;
  socket->passive = false;
  socket->accept_addr = nullptr;
  socket->syscalluuid = syscallUUID;
  socket->my_addr = new my_sockaddr_in;
  socket->my_addr->sin_family = AF_INET;
  socket->my_addr->sin_port = -1;
  socket->peer_addr = new my_sockaddr_in;
  socket->peer_addr->sin_family = AF_INET;
  socket->peer_addr->sin_port = -1;
  socket->acceptQueue = vector<Socket *>();
  socket->listenQueue = vector<Socket *>();
  Socketfd.push_back(socket);

  returnSystemCall (syscallUUID, fd);
  return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, 
                                   int sock_fd, int backlog) 
{
  Socket *socket = find_socket(pid, sock_fd);
  if (socket == nullptr || !socket->bound){
    returnSystemCall (syscallUUID, -1);
    return;
  }
  socket->passive = true;
  socket->backlog = backlog;
  returnSystemCall (syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_connect (UUID syscallUUID, int pid,
                                    int sock_fd, struct sockaddr *address,
                                    socklen_t address_len)
{
  Socket *socket = find_socket(pid, sock_fd);
  if (socket == nullptr){
      returnSystemCall (syscallUUID, -1);
      return;
  }
  sockaddr_in *addr = (sockaddr_in *)address;

  if(!socket->passive){
    /*find avaliable port*/
    socket->peer_addr->sin_family = AF_INET;
    socket->peer_addr->sin_port = addr->sin_port;
    (socket->peer_addr->sin_addr).s_addr = (addr->sin_addr).s_addr;

    ipv4_t dst_ip = NetworkUtil::UINT64ToArray<4>((socket->peer_addr->sin_addr).s_addr);
    in_port_t dst_port = getRoutingTable(dst_ip);
    optional<ipv4_t> cli_ip = getIPAddr(dst_port);
    in_addr_t client_ip = NetworkUtil::arrayToUINT64<4>(cli_ip.value());


    in_port_t client_port;
    
      if(!socket->bound){
        while(true){
          client_port = rand() % 65536;
          if(check_overlap2(pid, sock_fd, client_ip, client_port) < 0){
            continue;
          }else{
            break;
          }
        }

      socket->my_addr->sin_family = AF_INET;
      socket->my_addr->sin_port = client_port;
      (socket->my_addr->sin_addr).s_addr = client_ip;
      socket->bound = true;
    }

    // cout << "my_addr: " << "ip: " << (socket->my_addr->sin_addr).s_addr << " port: " << socket->my_addr->sin_port << endl;
    // cout << "peer_addr: " << "ip: " << (socket->peer_addr->sin_addr).s_addr << " port: " << socket->peer_addr->sin_port << endl;

    /*send packet to server SYN*/
    size_t packet_size = 54;
    Packet pkt (packet_size);
    uint8_t h_len = 0x50;
    uint16_t window_size = 0xffff;
    uint8_t flag = 2;
    uint32_t sequence_num = htonl(rand());
    uint32_t ack_num = htonl(0);
    socket->seq_num = ntohl(sequence_num);
    socket->ack_num = ntohl(ack_num);
    socket->syscalluuid = syscallUUID;

    pkt.writeData(26, &(socket->my_addr->sin_addr).s_addr, 4); //ip header: source ip
    pkt.writeData(30, &(socket->peer_addr->sin_addr).s_addr, 4); //ip header: dst ip
    pkt.writeData(34, &(socket->my_addr->sin_port),2); //tcp header: source port
    pkt.writeData(36, &(socket->peer_addr->sin_port), 2); //tcp header: dst port
    pkt.writeData(38, &sequence_num, 4); //tcp header: sequence num
    pkt.writeData(42, &ack_num, 4); //tcp header: ack
    pkt.writeData(46, &h_len, 1); //header length + reserve
    pkt.writeData(47, &flag, 1);
    pkt.writeData(48, &window_size, 2);
    /*for checksum*/
    uint8_t temp[20];
    pkt.readData(34, temp, sizeof(temp));
    uint16_t checksum = NetworkUtil::tcp_sum((socket->my_addr->sin_addr).s_addr, (socket->peer_addr->sin_addr).s_addr, temp, 20);
    checksum = htons(~checksum);
    pkt.writeData(50, &checksum, 2);
    sendPacket("IPv4", move(pkt));
  }
    return;
}

void TCPAssignment::syscall_bind (UUID syscallUUID, int pid,
                  int socket_fd, struct sockaddr *address,
                  socklen_t address_len)
{
  // cout << "inside bind" << endl;
  Socket *socket = find_socket(pid, socket_fd);
  if (socket == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }

  if (socket->bound){
    returnSystemCall (syscallUUID, -1);
    return;
  }
  sockaddr_in *_addr = (sockaddr_in*)address;
  if (_addr->sin_family != AF_INET){
    returnSystemCall (syscallUUID, -1);
  }

  socket->my_addr->sin_family = AF_INET;
  socket->my_addr->sin_port = _addr->sin_port;
  (socket->my_addr->sin_addr).s_addr = (_addr->sin_addr).s_addr;
  socket->bound = true;

  returnSystemCall (syscallUUID, check_overlap(pid, socket->fd, _addr->sin_addr, _addr->sin_port));
  return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, 
                                   int socket_fd, struct sockaddr *address, socklen_t *address_len) 
{
  Socket *socket = find_socket(pid, socket_fd);
  if(socket==nullptr || !socket->bound){
    returnSystemCall (syscallUUID, -1);
    return;
  }
    /*create client socket*/
    int fd;
    if ((fd = createFileDescriptor (pid)) == -1)
    {
      returnSystemCall (syscallUUID, -1);
      return;
    }

    
  if((socket->acceptQueue).size() != 0){
    Socket *cli_sock = socket->acceptQueue.front();
    socket->acceptQueue.erase (socket->acceptQueue.begin());
    cli_sock->fd = fd;
    cli_sock->pid = pid; //my create same fd in different pid
    cli_sock->syscalluuid = syscallUUID;
    Socketfd.push_back(cli_sock);

    sockaddr_in *addr = (sockaddr_in *)address;
    addr->sin_family = cli_sock->peer_addr->sin_family;
    addr->sin_port = htons(cli_sock->peer_addr->sin_port);
    addr->sin_addr = cli_sock->peer_addr->sin_addr;
    *address_len = sizeof(sockaddr_in);
    cli_sock->bound = true;
    returnSystemCall (syscallUUID, fd);
    return;
  }else{
    socket->accept_addr = (sockaddr_in *)address;
    socket->syscalluuid = syscallUUID;
    *address_len = sizeof(sockaddr_in);
    return;
  }
}

void TCPAssignment::syscall_getsockname (UUID syscallUUID, int pid,
                                   int sock_fd, struct sockaddr *address,
                                   socklen_t *address_len)
{
  Socket *socket = find_socket(pid, sock_fd);
  if(socket == nullptr){
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if(socket->my_addr == nullptr){
    returnSystemCall (syscallUUID, -1);
  }

  struct my_sockaddr_in *server_addr = socket->my_addr;
  sockaddr_in *addr = (sockaddr_in *)address;
  addr->sin_family = server_addr->sin_family;
  addr->sin_port = server_addr->sin_port;
  addr->sin_addr = server_addr->sin_addr;
  *address_len = sizeof(sockaddr_in);
  returnSystemCall (syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
  Socket * socket = find_socket(pid, fd);
  if(socket != nullptr){
    removeFileDescriptor(pid, fd);
    returnSystemCall(syscallUUID, remove_socket(pid, fd));
  }
}

void TCPAssignment::syscall_getpeername (UUID syscallUUID, int pid,
                                        int socket_fd, struct sockaddr *address,
                                        socklen_t *address_len)
{
  Socket *socket = find_socket(pid, socket_fd);
  if(socket == nullptr ){
    returnSystemCall (syscallUUID, -1);
    return;
  }
  sockaddr_in *addr = (sockaddr_in *)address;
  addr->sin_family = AF_INET;
  addr->sin_port = socket->peer_addr->sin_port;
  addr->sin_addr = socket->peer_addr->sin_addr;
  *address_len = sizeof (sockaddr_in);
  returnSystemCall (syscallUUID, 0);
  return;
}

int TCPAssignment::remove_socket(int pid, int socket_fd)
{
  std::vector <Socket *>::iterator i;
  for (i = Socketfd.begin(); i != Socketfd.end(); i++)
  {
    Socket *s = (*i);
    if (s->pid == pid && s->fd == socket_fd){
      Socketfd.erase(i);
      s->acceptQueue = vector<Socket *>();
      s->listenQueue = vector<Socket *>();
      delete s->my_addr;
      delete s->peer_addr;
      delete s;
      return 0;
    }
  }
  return -1;
}

int TCPAssignment::check_overlap(int pid, int socket_fd, in_addr addr, in_port_t port){
  std::vector <Socket *>::iterator i;
  for (i = Socketfd.begin(); i != Socketfd.end(); i++)
  {
    Socket *s = (*i);
    if(s->my_addr == nullptr){
      return -1;
    }
    if (s->my_addr->sin_port == port 
          && ((s->my_addr->sin_addr).s_addr == addr.s_addr 
            || (s->my_addr->sin_addr).s_addr == INADDR_ANY))
    {
      if (s->fd != socket_fd || s->pid != pid){
        return -1;
      }
    }
  }
  return 0;
}

int TCPAssignment::check_overlap2(int pid, int socket_fd, in_addr_t addr, in_port_t port){
  std::vector <Socket *>::iterator i;
  for (i = Socketfd.begin(); i != Socketfd.end(); i++)
  {
    Socket *s = (*i);
    if(s->my_addr == nullptr){
      return -1;
    }
    if (s->my_addr->sin_port == port 
          && ((s->my_addr->sin_addr).s_addr == addr
            || (s->my_addr->sin_addr).s_addr == INADDR_ANY ))
    {
        return -1;
    }
  }
  return 0;
}

bool TCPAssignment::check_port(int pid, int socket_fd, in_port_t port)
{
  vector <Socket *>::iterator i;
  for (i = Socketfd.begin(); i != Socketfd.end(); i++)
  {
    Socket *s = (*i);
    if (s->my_addr->sin_port == port){ // overlap port and addr
      if (s->fd != socket_fd || s->pid != pid){
        return false;
      }
    }
  }
  return true;
}


} // namespace E