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
    this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
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
  uint8_t ip_hlen;
  uint16_t total_len;
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
  uint32_t tseq;
  packet.readData(14, &(ip_hlen), 1); //ip header: version + hlen
  packet.readData(16, &(total_len), 2); // ip header: total length
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
  
  total_len = ntohs(total_len);

  if(total_len <= 40){
    uint8_t checksum_temp[20];
    packet.readData(34, checksum_temp, sizeof(checksum_temp));
    uint16_t checksum_now = NetworkUtil::tcp_sum(src_ip, dst_ip, checksum_temp, 20);
    checksum_now = htons(~checksum_now);
    if (~(checksum & checksum_now) == 0) {
    // if (checksum_now != 0xffff) {
      return;
    }
  }else{
    uint8_t checksum_temp[total_len];
    packet.readData(34, checksum_temp, total_len - 20);
    uint16_t checksum_now = NetworkUtil::tcp_sum(src_ip, dst_ip, checksum_temp, total_len - 20);
    if (htons(~checksum_now)!= 0) {
      return;
    }
  }

  checksum = ntohs(checksum);

  Socket *my_socket = FindMySocket(dst_ip, dst_port);
  if(my_socket == nullptr){ 
    return;
  }

  // cout << "(ACK any) received ack: " << ntohl(ack_num) << endl;

  if ((flag & 16) == 16) { // ACK flag is on
    if(my_socket->connected == false){ //for three way handshake
      if(flag == 17){
        sPacket *my_packet = find_packet(my_socket, ntohl(ack_num));
        delete my_packet;
      }else if (flag == 16){
        sPacket *my_packet = find_packet(my_socket, ntohl(ack_num));
        if (my_packet == nullptr){
          // cout << "(pkt arrived)(flag 16) my_packet nullptr" << endl;
          // return;
          if(total_len > 40){
            // data packet is arrived to receiver
            // printf("cannot find packet with flag 16, seq_num: %d, ack_num: %d\n", ntohl(seq_num), ntohl(ack_num));
          }else{
            // something's wrong
            return;
          }
        }else{
          cancelTimer(my_packet->key);
          

          uint64_t SampleRTT = getCurrentTime() * 1000000 - my_packet->send_time;
          // uint64_t SampleRTT = getCurrentTime() - my_packet->send_time;

          my_socket->EstimatedRTT = (1-0.125) * my_socket->EstimatedRTT + 0.125 * SampleRTT; // have to calculate SampleRTT
          my_socket->DevRTT = (1-0.25) * my_socket->DevRTT + 0.25*fabs(SampleRTT - my_socket->EstimatedRTT);
          my_socket->TimeoutInterval = my_socket->EstimatedRTT + 4*my_socket->DevRTT;
          delete my_packet;
          if(total_len > 40){
            returnSystemCall (my_socket->syscalluuid, total_len - 40);
          }
        }
      }else{
        sPacket *my_packet = find_packet(my_socket, ntohl(ack_num));
        if (my_packet == nullptr){
          // cout << "(pkt arrived)(not flag 16) my_packet nullptr" << endl;
          // return;
        }else{
          cancelTimer(my_packet->key);

          uint64_t SampleRTT = getCurrentTime() * 1000000 - my_packet->send_time;
          // uint64_t SampleRTT = getCurrentTime() - my_packet->send_time;

          my_socket->EstimatedRTT = (1-0.125) * my_socket->EstimatedRTT + 0.125 * SampleRTT; // have to calculate SampleRTT
          my_socket->DevRTT = (1-0.25) * my_socket->DevRTT + 0.25*fabs(SampleRTT - my_socket->EstimatedRTT);
          my_socket->TimeoutInterval = my_socket->EstimatedRTT + 4*my_socket->DevRTT;
          delete my_packet;
          if(total_len > 40){
            returnSystemCall (my_socket->syscalluuid, total_len - 40);
          }
        }
      }
    }else{ // for DATA connections
      // cout << "connected" << endl;
      if(total_len <= 40 && flag == 16){
        // cout << "inside connected,flag 16" << endl;
        int i;
        for (i = my_socket->start; i < my_socket->end; i++)
        { 
          my_socket->pktq[i].readData (38, &tseq, 4);
          tseq = ntohl (tseq);
          if (tseq == ntohl(ack_num))
          {
            break;
          }
        }
        // if(i < my_socket->end) {
        //   remove_packet(my_socket, ntohl(ack_num));
        // }

        // cout << "(received) : " << i << " ack: " << ntohl(ack_num) << endl;
        if (i == my_socket->start|| i == my_socket->end + 1)
        {
          cout << i << " dup packet" << endl;
          sPacket *dup_packet = find_packet(my_socket, ntohl(ack_num));
          if(dup_packet != nullptr){
            cancelTimer(dup_packet->key);
            delete dup_packet;
          }
          return;
        }
        my_socket->received++;
        // cout << "1-1" << endl;
        // Timer restart
        my_socket->start = i;
        sPacket *my_packet = find_packet(my_socket, ntohl(ack_num));
        if(my_packet != nullptr){
          cancelTimer (my_packet->key);
          uint64_t SampleRTT = getCurrentTime() * 1000000 - my_packet->send_time;
          my_socket->EstimatedRTT = (1-0.125) * my_socket->EstimatedRTT + 0.125 * SampleRTT; // have to calculate SampleRTT
          my_socket->DevRTT = (1-0.25) * my_socket->DevRTT + 0.25*fabs(SampleRTT - my_socket->EstimatedRTT);
          my_socket->TimeoutInterval = my_socket->EstimatedRTT + 4*my_socket->DevRTT;
          delete my_packet;
        }
        if(my_socket->write_wait->waiting != false){
            my_socket->write_wait->waiting = false;
            returnSystemCall(my_socket->write_wait->syscallUUID, my_socket->write_wait->count);
        }
      }
    }
  }

  // void *payload = nullptr;
  if(total_len > 40){ //DATA EXISTS
    Socket *con_sock = nullptr;
    if(my_socket->read_wait->waiting){
      // cout << "my socket connected" << endl;
      con_sock = my_socket;
    }else if(my_socket->cli_sock->read_wait->waiting){
      // cout << "client socket connected" << endl;
      con_sock = my_socket->cli_sock;
    }
    if (my_socket->last_ack_num == -1 || my_socket->last_ack_num == ntohl(seq_num)) { // first arrived data packet or no packet loss

      size_t count_save = 0;
      count_save = con_sock->read_wait->count;
      int read_bytes = 0;
      if (con_sock->read_wait->count > total_len - 40){
          read_bytes = total_len - 40;
          packet.readData(54, con_sock->read_wait->buf, total_len - 40);
          con_sock->read_wait->count -= read_bytes;
      }else{
        size_t remaining = total_len - 40;
        read_bytes = con_sock->read_wait->count;
        packet.readData(54, con_sock->read_wait->buf, read_bytes);
        con_sock->read_wait->waiting = false;
        con_sock->read_wait->buf = nullptr;
        con_sock->read_wait->count = 0;
        remaining -= read_bytes;

        //push remaining bytes into new payload -> recv_buffer
        size_t copy_byte = 0;
        if(remaining > 0){
          con_sock->read_buf = new Payload;
          con_sock->read_buf->payload = malloc(remaining);
          // memcpy(con_sock->read_buf->payload, (char *)payload + read_bytes, remaining);
          packet.readData(54 + read_bytes, con_sock->read_buf->payload, remaining);
          con_sock->read_buf->size = remaining;
          con_sock->read_buf->offset = 0;
        }
      }
      // free(payload);

      //send ACK packet to client
      size_t packet_size = 54;
      Packet pkt (packet_size);
      uint8_t h_len = 0x50;
      uint16_t window_size = 0xffff;
      uint8_t flag = 16;
      uint32_t _sequence_num = ack_num;
      uint32_t _ack_num = htonl(ntohl(seq_num) + total_len - 40);

      my_socket->last_ack_num = ntohl(_ack_num);
      
      uint16_t ip_length = htons(40);
      pkt.writeData(16, &ip_length, 2);
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
      returnSystemCall (con_sock->syscalluuid, read_bytes);
      return;
    }else{
      //send duplicated ACK packet to sender
      size_t packet_size = 54;
      Packet pkt (packet_size);
      uint8_t h_len = 0x50;
      uint16_t window_size = 0xffff;
      uint8_t flag = 16;
      uint32_t _sequence_num = htonl(con_sock->seq_num);
      uint32_t _ack_num = htonl(my_socket->last_ack_num);
      
      uint16_t ip_length = htons(40);
      pkt.writeData(16, &ip_length, 2);
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
      return;
    }
  }
  
  if(flag == 2){/*received this packet from server side from client connect: SYN */
    /*send packet with SYN + ACK to client*/
    // Socket *my_socket = FindMySocket(ntohs(dst_ip), ntohs(dst_port));
    // Socket *my_socket = FindMySocket(dst_ip, dst_port);
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
    cli_sock->seq_num = ntohl(ack_num);
    cli_sock->ack_num = ntohl(seq_num)+1;
    cli_sock->bound = true;
    cli_sock->passive = false;
    cli_sock->accept_addr = nullptr;
    cli_sock->my_addr->sin_family = AF_INET;
    cli_sock->my_addr->sin_port = ntohs(dst_port);
    (cli_sock->my_addr->sin_addr).s_addr = ntohl(dst_ip);
    cli_sock->peer_addr->sin_family = AF_INET;
    cli_sock->peer_addr->sin_port = ntohs(src_port);
    (cli_sock->peer_addr->sin_addr).s_addr = ntohl(src_ip);
    cli_sock->acceptQueue = vector<Socket *>();
    cli_sock->listenQueue = vector<Socket *>();
    cli_sock->read_wait = new read_meta;
    cli_sock->read_wait->buf = nullptr;
    cli_sock->read_wait->count = 0;
    cli_sock->read_wait->waiting = false;
    cli_sock->write_wait = new write_meta;
    cli_sock->write_wait->buf = nullptr;
    cli_sock->write_wait->count = 0;
    cli_sock->write_wait->waiting = false;
    cli_sock->read_buf = nullptr;
    cli_sock->accepted = false;
    cli_sock->connected = false;
    cli_sock->sendPackets = vector<sPacket *>();
    cli_sock->EstimatedRTT = 100000000;
    cli_sock->DevRTT = 0;
    cli_sock->TimeoutInterval = cli_sock->EstimatedRTT + 4*cli_sock->DevRTT;
    cli_sock->last_ack_num = -1;
    cli_sock->received = 0;
    cli_sock->pktq = vector<Packet>();
    cli_sock->start = 0;
    cli_sock->end = 0;
    cli_sock->received = 0;
    if((int)(my_socket->listenQueue).size() < my_socket->backlog){
      (my_socket->listenQueue).push_back(cli_sock);
      size_t packet_size = 54;
      Packet pkt (packet_size);
      uint8_t h_len = 0x50;
      uint16_t window_size = 1024;
      uint8_t flag = 18;
      uint32_t _sequence_num = htonl(ack_num);
      uint32_t _ack_num = htonl(ntohl(seq_num)+1);
      
      uint16_t ip_length = htons(40);
      pkt.writeData(16, &ip_length, 2);
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

      tuple<Packet, Socket *> pld = make_tuple(pkt, my_socket);
      UUID key = addTimer(pld, my_socket->TimeoutInterval);

      sPacket *send_packet = new sPacket;
      send_packet->next_seq_num = ntohl(_sequence_num) + 1;
      send_packet->send_time = getCurrentTime() * 1000000;
      send_packet->key = key;
      my_socket->sendPackets.push_back(send_packet);
    }
  }
  else if(flag == 18){/*received this packet from client side after connect: SYN + ACK*/
    // Socket *my_socket = FindMySocket(dst_ip, dst_port);
    if(my_socket == nullptr){
      return;
    }
    my_socket->ack_num = ntohl(seq_num) + 1;
    my_socket->seq_num = ntohl(ack_num);
    my_socket->connected = true;
    size_t packet_size = 54;
    Packet pkt (packet_size);
    uint8_t h_len = 0x50;
    uint16_t window_size = 1024;
    uint8_t flag = 16;
    uint32_t sequence_num = htonl(ack_num);
    uint32_t ack_num = htonl(htonl(seq_num) + 1);

    uint32_t src_ip = htonl((my_socket->my_addr->sin_addr).s_addr); 
    uint32_t dst_ip = htonl((my_socket->peer_addr->sin_addr).s_addr);
    uint16_t src_port = htons(my_socket->my_addr->sin_port);
    uint16_t dst_port = htons(my_socket->peer_addr->sin_port);

    uint16_t ip_length = htons(40);
    pkt.writeData(16, &ip_length, 2);
    pkt.writeData(26, &(src_ip), 4); //ip header: source ip
    pkt.writeData(30, &(dst_ip), 4); //ip header: dst ip
    pkt.writeData(34, &(src_port),2); //tcp header: source port
    pkt.writeData(36, &(dst_port), 2); //tcp header: dst port
    pkt.writeData(38, &sequence_num, 4); //tcp header: sequence num
    pkt.writeData(42, &ack_num, 4); //tcp header: ack
    pkt.writeData(46, &h_len, 1); //header length + reserve
    pkt.writeData(47, &flag, 1);
    pkt.writeData(48, &window_size, 2);
    /*for checksum*/
    uint8_t temp[20];
    pkt.readData(34, temp, sizeof(temp));
    uint16_t checksum = NetworkUtil::tcp_sum(src_ip, dst_ip, temp, 20);
    checksum = htons(~checksum);
    pkt.writeData(50, &checksum, 2);
    sendPacket("IPv4", move(pkt));

    // tuple<Packet, Socket *> pld = make_tuple(pkt, my_socket);
    // UUID key = addTimer(pld, my_socket->TimeoutInterval);

    // sPacket *send_packet = new sPacket;
    // send_packet->next_seq_num = ntohl(sequence_num) + 1;
    // send_packet->send_time = getCurrentTime() * 1000000;
    // send_packet->key = key;
    // my_socket->sendPackets.push_back(send_packet);

    my_socket->passive = false;
    returnSystemCall (my_socket->syscalluuid, 0);
  }else if(flag == 16){
    if((my_socket->listenQueue).size() > 0){
      Socket *cli_sock = my_socket->listenQueue.front();
      my_socket->listenQueue.erase (my_socket->listenQueue.begin());
      (my_socket->acceptQueue).push_back(cli_sock);
    }

    if(my_socket->accept_addr != nullptr && my_socket->acceptQueue.size() > 0){
      int fd;
      if ((fd = createFileDescriptor (my_socket->pid)) == -1)
      {
        returnSystemCall (my_socket->syscalluuid, -1);
        return;
      }
      Socket *cli_sock = nullptr;
      std::vector <Socket *>::iterator i;
      for (i = (my_socket->acceptQueue).begin(); i != (my_socket->acceptQueue).end(); i++)
      {
        Socket *s = (*i);
        if (((s->my_addr->sin_addr).s_addr == ntohl(dst_ip) || (s->my_addr->sin_addr).s_addr == INADDR_ANY || dst_ip == INADDR_ANY)
          && s->my_addr->sin_port == ntohs(dst_port)){
          cli_sock = s;
          break;
        }
      }

      if(i == my_socket->acceptQueue.end()){
        return;
      }
      // Socket *cli_sock = my_socket->acceptQueue.front();
      // my_socket->acceptQueue.erase (my_socket->acceptQueue.begin());
      my_socket->acceptQueue.erase(i);
      cli_sock->fd = fd;
      cli_sock->pid = my_socket->pid; //my create same fd in different pid
      cli_sock->syscalluuid = my_socket->syscalluuid;
      cli_sock->seq_num = ntohl(ack_num);
      cli_sock->ack_num = ntohl(seq_num)+1;
      cli_sock->accepted = true;
      cli_sock->connected = true;
      Socketfd.push_back(cli_sock);

      sockaddr_in *addr = my_socket->accept_addr;
      addr->sin_family = AF_INET;
      addr->sin_port = cli_sock->peer_addr->sin_port;
      (addr->sin_addr).s_addr = (cli_sock->peer_addr->sin_addr).s_addr;
      my_socket->accept_addr = nullptr;
      my_socket->cli_sock = cli_sock;
      returnSystemCall (my_socket->syscalluuid, fd);
      return;
    }
    // returnSystemCall (my_socket->syscalluuid, total_len-40);
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // (void)payload;

  tuple<Packet, Socket *> m = any_cast<tuple<Packet, Socket *>>(payload);
  Packet pkt = get<0>(m);
  Socket *socket = get<1>(m);

  uint8_t ip_hlen;
  uint16_t total_len;
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
  pkt.readData(14, &(ip_hlen), 1); //ip header: version + hlen
  pkt.readData(16, &(total_len), 2); // ip header: total length
  pkt.readData(26, &(src_ip), 4); //ip header: src_ip
  pkt.readData(30, &(dst_ip), 4); //ip header: dst_ip
  pkt.readData(34, &(src_port), 2); //tcp header: src_port
  pkt.readData(36, &(dst_port), 2); //tcp header: dst_port
  pkt.readData(38, &(seq_num), 4); //tcp header: sequence number
  pkt.readData(42, &(ack_num), 4); //tcp header: ack number
  pkt.readData(46, &(head_len), 1); //tcp header: head length 4bit + recv 6bit (4bit)
  pkt.readData(47, &(flag), 1); //tcp header: recv(2bit) + flag (6bit)
  pkt.readData(48, &(window_size), 2); //tcp header: window_size
  pkt.readData(50, &checksum, 2); //tcp header: checksum

  Packet cloned_pkt = pkt.clone();
  auto m2 = make_tuple(cloned_pkt, socket);
  // auto m2 = make_tuple(pkt, socket);

  uint8_t c_ip_hlen;
  uint16_t c_total_len;
  uint32_t c_src_ip;
  uint32_t c_dst_ip;
  uint16_t c_src_port;
  uint16_t c_dst_port;
  uint32_t c_seq_num;
  uint32_t c_ack_num;
  uint8_t c_head_len;
  uint8_t c_flag;
  uint16_t c_window_size;
  uint16_t c_checksum;
  cloned_pkt.readData(14, &(c_ip_hlen), 1); //ip header: version + hlen
  cloned_pkt.readData(16, &(c_total_len), 2); // ip header: total length
  cloned_pkt.readData(26, &(c_src_ip), 4); //ip header: src_ip
  cloned_pkt.readData(30, &(c_dst_ip), 4); //ip header: dst_ip
  cloned_pkt.readData(34, &(c_src_port), 2); //tcp header: src_port
  cloned_pkt.readData(36, &(c_dst_port), 2); //tcp header: dst_port
  cloned_pkt.readData(38, &(c_seq_num), 4); //tcp header: sequence number
  cloned_pkt.readData(42, &(c_ack_num), 4); //tcp header: ack number
  cloned_pkt.readData(46, &(c_head_len), 1); //tcp header: head length 4bit + recv 6bit (4bit)
  cloned_pkt.readData(47, &(c_flag), 1); //tcp header: recv(2bit) + flag (6bit)
  cloned_pkt.readData(48, &(c_window_size), 2); //tcp header: window_size
  cloned_pkt.readData(50, &c_checksum, 2); //tcp header: checksum

  sPacket *c_send_packet = new sPacket;

  if (ntohs(c_total_len) - 40 <= 0 && socket->connected == false) {
    c_send_packet->next_seq_num = ntohl(c_seq_num) + 1;
    sPacket *trash = find_packet(socket, c_send_packet->next_seq_num); // for erase
    delete trash;
    c_send_packet->key = addTimer(m2, socket->TimeoutInterval);
    c_send_packet->send_time = getCurrentTime() * 1000000;
    socket->sendPackets.push_back(c_send_packet);
    sendPacket("IPv4", move(cloned_pkt));
  }else if (ntohs(c_total_len) - 40 > 0){
    if(socket->connected == true){
      // cout << "inside timercallback" << endl;
      c_send_packet->next_seq_num = ntohl(c_seq_num) + ntohs(c_total_len) - 40;
      // printf("here?\n");
      for (int i = socket->start; i < socket->end; i++)
      {
        // cout <<  i << "(timercallback)start: " << socket->start << " end: " << socket->end << " queue sizen: " << socket->pktq.size() << endl;
        sPacket *my_packet = find_packet(socket, ntohl(ack_num));
        if(my_packet != nullptr){
          delete my_packet;
        }
        sendPacket ("IPv4", std::move(socket->pktq[i].clone()));
        // c_send_packet->next_seq_num = ntohl(c_seq_num) + ntohs(c_total_len) - 40;
        // c_send_packet->key = addTimer(m2, socket->TimeoutInterval);
        // c_send_packet->send_time = getCurrentTime() * 1000000;
        // socket->sendPackets.push_back(c_send_packet);
      }
    }
  }
  // printf("end of timercallback\n");
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
    if (((s->my_addr->sin_addr).s_addr == ntohl(ip) || (s->my_addr->sin_addr).s_addr == INADDR_ANY || ip == INADDR_ANY)
      && s->my_addr->sin_port == ntohs(port)){
      return s;
    }
  }
  return nullptr;
}

sPacket * TCPAssignment::find_packet(Socket *socket, uint32_t ack_num)
{
  std::vector <sPacket *>::iterator i;
  for (i = socket->sendPackets.begin(); i != socket->sendPackets.end(); i++)
  {
    sPacket *p = (*i);
    if (p->next_seq_num == ack_num){
      socket->sendPackets.erase(i);
      return p;
    }
  }
  return nullptr;
}

int TCPAssignment::remove_packet(Socket *socket, uint32_t ack_num)
{
  std::vector <sPacket *>::iterator i;
  for (i = socket->sendPackets.begin(); i != socket->sendPackets.end(); i++)
  {
    sPacket *p = (*i);
    if (p->next_seq_num == ack_num){
      return 0;
    }
    socket->sendPackets.erase(i);
    cancelTimer(p->key);
  }
  return -1;
}

void TCPAssignment::syscall_read (UUID syscallUUID, int pid,
                                  int fd, void *buf, size_t count) 
{
  // cout << "(read) inside read " << endl;
  if (count == 0){
    returnSystemCall (syscallUUID, 0);
    return;
  }

  Socket *socket = find_socket(pid, fd);
  if(socket==nullptr || !socket->bound){
    // cout << "(read) socket not bound or nullptr " << endl;
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if(socket->read_buf == nullptr){
    // cout << "(read) pending " << endl;
    socket->syscalluuid = syscallUUID;
    socket->read_wait->syscallUUID = syscallUUID;
    socket->read_wait->buf = buf;
    socket->read_wait->count = count;
    socket->read_wait->waiting = true;
    return;
  }else{
    size_t copy_bytes = 0;
    if (count > 0){
        Payload *p = socket->read_buf;
        copy_bytes = count > (p->size - p->offset)? (p->size - p->offset) : count;
        memcpy(buf, (char *)p->payload + p->offset, copy_bytes);
        p->offset += copy_bytes;
        if (p->size <= p->offset){
          free(p->payload);
          delete p;
          socket->read_buf = nullptr;
      }
      
      returnSystemCall(syscallUUID, copy_bytes);
    }
  }
}

void TCPAssignment::syscall_write (UUID syscallUUID, int pid,
                                   int fd, void *buf, size_t count)
{
  // cout << "(write)inside write" << endl;
  Socket *socket = find_socket(pid, fd);

  // if(socket->connected != true || socket->accepted != true){
  //   return;
  // }
  size_t i = count;

  size_t packet_size = 54 + i;
  Packet pkt (packet_size);
  uint8_t h_len = 0x50;
  uint16_t window_size = 0xffff;
  uint8_t flag = 16;
  uint32_t _sequence_num = htonl(socket->seq_num);
  uint32_t _ack_num = htonl(socket->ack_num);        // no matter
  uint32_t src_ip = htonl((socket->my_addr->sin_addr).s_addr); 
  uint32_t dst_ip = htonl((socket->peer_addr->sin_addr).s_addr);
  uint16_t src_port = htons(socket->my_addr->sin_port);
  uint16_t dst_port = htons(socket->peer_addr->sin_port);

  uint16_t ip_length = htons(i + 40);
  pkt.writeData(16, &ip_length, 2);
  pkt.writeData(26, &src_ip, 4); //ip header: source ip
  pkt.writeData(30, &dst_ip, 4); //ip header: dst ip
  pkt.writeData(34, &src_port,2); //tcp header: source port
  pkt.writeData(36, &dst_port, 2); //tcp header: dst port
  pkt.writeData(38, &_sequence_num, 4); //tcp header: sequence num
  pkt.writeData(42, &_ack_num, 4); //tcp header: ack
  pkt.writeData(46, &h_len, 1); //header length + reserve
  pkt.writeData(47, &flag, 1);
  pkt.writeData(48, &window_size, 2);
  pkt.writeData(54, buf, count);
  // cout << "write 1" << endl;
  uint8_t temp[i + 40 + 5];
  pkt.readData(34, temp, i + 40);
  uint16_t _checksum = NetworkUtil::tcp_sum(src_ip, dst_ip, temp, 20 + i);
  _checksum = htons(~_checksum);
  pkt.writeData(50, &_checksum, 2);
  // cout << "write 2" << endl;
  // printf("checksum: %d \n", ~_checksum);


  socket->pktq.push_back(pkt);

  if(socket->end >= socket->pktq.size()){
    // cout << "hereh??" << endl;
    socket->end = socket->pktq.size() - 1;
  }
  
  // cout << "write 3: " << socket->end << " scket queue: " << socket->pktq.size() << endl;
  // cout << "(write) send: " << ntohl(_sequence_num) << endl;
  sendPacket("IPv4", move(socket->pktq[socket->end]));
  socket->end++;
  // cout << "write 3-1" << endl;

  socket->seq_num += i;
  socket->syscalluuid = syscallUUID;

  tuple<Packet, Socket *> pld = make_tuple(pkt, socket);
  // cout << "write 4" << endl;
  sPacket *send_packet = new sPacket;
  // cout << "write 5" << endl;
  send_packet->next_seq_num = ntohl(_sequence_num) + i;
  send_packet->send_time = getCurrentTime() * 1000000;
  send_packet->key = addTimer(pld, socket->TimeoutInterval);
  socket->sendPackets.push_back(send_packet);
  // cout << "write 6" << endl;

  if((socket->end >= socket->start + W_SIZE) && (socket->connected != true || socket->accepted != true)){ //wait for the last ACK to arrive
      socket->write_wait->syscallUUID = syscallUUID;
      socket->write_wait->buf = buf;
      socket->write_wait->count = count;
      socket->write_wait->waiting = true;
      // cout << "(write) end of pending write" << endl;
      return;
  }else{
      // cout << "(write)send write away " << ntohl(_sequence_num) << endl;
      socket->write_wait->waiting = false;
      // cout << "(write) end of syscallreturn write" << endl;
      returnSystemCall (syscallUUID, count);
    return;
  }
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
  socket->read_wait = new read_meta;
  socket->read_wait->buf = nullptr;
  socket->read_wait->count = 0;
  socket->read_wait->syscallUUID = syscallUUID;
  socket->read_wait->waiting = false;
  socket->write_wait = new write_meta;
  socket->write_wait->buf = nullptr;
  socket->write_wait->count = 0;
  socket->write_wait->syscallUUID = syscallUUID;
  socket->write_wait->waiting = false;
  socket->accepted = false;
  socket->connected = false;
  socket->read_buf = nullptr;
  socket->sendPackets = vector<sPacket *>();
  socket->EstimatedRTT = 100000000;
  socket->DevRTT = 0;
  socket->TimeoutInterval = socket->EstimatedRTT + 4*socket->DevRTT;
  socket->last_ack_num = -1;
  socket->pktq = vector<Packet>();
  socket->start = 0;
  socket->end = 0;
  socket->received = 0;
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
    socket->peer_addr->sin_port = ntohs(addr->sin_port);
    (socket->peer_addr->sin_addr).s_addr = ntohl((addr->sin_addr).s_addr);

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
      socket->my_addr->sin_port = ntohs(client_port);
      (socket->my_addr->sin_addr).s_addr = ntohl(client_ip);
      socket->bound = true;
    }

    // cout << "my_addr: " << "ip: " << (socket->my_addr->sin_addr).s_addr << " port: " << socket->my_addr->sin_port << endl;
    // cout << "peer_addr: " << "ip: " << (socket->peer_addr->sin_addr).s_addr << " port: " << socket->peer_addr->sin_port << endl;

    /*send packet to server SYN*/
    size_t packet_size = 54;
    Packet pkt (packet_size);
    uint8_t h_len = 0x50;
    uint16_t window_size = 1024;
    uint8_t flag = 2;
    uint32_t sequence_num = htonl(rand());
    uint32_t ack_num = htonl(ntohl(sequence_num) + 1);
    socket->seq_num = ntohl(sequence_num);
    socket->ack_num = ntohl(ack_num);
    socket->syscalluuid = syscallUUID;

    uint32_t _src_ip = htonl((socket->my_addr->sin_addr).s_addr);
    uint32_t _dst_ip = htonl((socket->peer_addr->sin_addr).s_addr);
    uint16_t _src_port = htons((socket->my_addr->sin_port));
    uint16_t _dst_port = htons((socket->peer_addr->sin_port));

    uint16_t ip_length = htons(40);
    pkt.writeData(16, &ip_length, 2);
    pkt.writeData(26, &(_src_ip), 4); //ip header: source ip
    pkt.writeData(30, &(_dst_ip), 4); //ip header: dst ip
    pkt.writeData(34, &(_src_port),2); //tcp header: source port
    pkt.writeData(36, &(_dst_port), 2); //tcp header: dst port
    pkt.writeData(38, &sequence_num, 4); //tcp header: sequence num
    pkt.writeData(42, &ack_num, 4); //tcp header: ack
    pkt.writeData(46, &h_len, 1); //header length + reserve
    pkt.writeData(47, &flag, 1);
    pkt.writeData(48, &window_size, 2);
    /*for checksum*/
    uint8_t temp[20];
    pkt.readData(34, temp, sizeof(temp));
    uint16_t checksum = NetworkUtil::tcp_sum(_src_ip, _dst_ip, temp, 20);
    checksum = htons(~checksum);
    pkt.writeData(50, &checksum, 2);
    sendPacket("IPv4", move(pkt));

    tuple<Packet, Socket *> pld = make_tuple(pkt, socket);
    UUID key = addTimer(pld, socket->TimeoutInterval);

    sPacket *send_packet = new sPacket;
    send_packet->next_seq_num = ntohl(sequence_num) + 1;
    send_packet->send_time = getCurrentTime() * 1000000;
    send_packet->key = key;
    socket->sendPackets.push_back(send_packet);
  }
    return;
}

void TCPAssignment::syscall_bind (UUID syscallUUID, int pid,
                  int socket_fd, struct sockaddr *address,
                  socklen_t address_len)
{
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
  socket->my_addr->sin_port = ntohs(_addr->sin_port);
  (socket->my_addr->sin_addr).s_addr = ntohl((_addr->sin_addr).s_addr);
  socket->bound = true;

  returnSystemCall (syscallUUID, check_overlap(pid, socket->fd, _addr->sin_addr, _addr->sin_port));
  return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, 
                                   int socket_fd, struct sockaddr *address, socklen_t *address_len) 
{
  // cout << "inside accept" << endl;
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
    // cout << "(accept)queue has element" << endl;
    Socket *cli_sock = socket->acceptQueue.front();
    socket->acceptQueue.erase (socket->acceptQueue.begin());
    cli_sock->fd = fd;
    cli_sock->pid = pid; //my create same fd in different pid
    cli_sock->syscalluuid = syscallUUID;
    Socketfd.push_back(cli_sock);

    sockaddr_in *addr = (sockaddr_in *)address;
    addr->sin_family = AF_INET;
    addr->sin_port = htons(cli_sock->peer_addr->sin_port);
    addr->sin_addr.s_addr = htonl((cli_sock->peer_addr->sin_addr).s_addr);
    *address_len = sizeof(sockaddr_in);
    cli_sock->bound = true;
    cli_sock->accepted = true;
    cli_sock->connected = true;
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
  addr->sin_family = AF_INET;
  addr->sin_port = htons(server_addr->sin_port);
  (addr->sin_addr).s_addr = htonl((server_addr->sin_addr).s_addr);
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
  addr->sin_port = htons(socket->peer_addr->sin_port);
  (addr->sin_addr).s_addr = htonl((socket->peer_addr->sin_addr).s_addr);
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
      s->sendPackets = vector<sPacket *>();
      delete s->my_addr;
      delete s->peer_addr;
      if(s->pktq.size() <= 0){
          delete s;
      }
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
    if (s->my_addr->sin_port == ntohs(port)
          && ((s->my_addr->sin_addr).s_addr == ntohl(addr.s_addr)
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
    if (s->my_addr->sin_port == ntohs(port)
          && ((s->my_addr->sin_addr).s_addr == ntohl(addr)
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
    if (s->my_addr->sin_port == ntohs(port)){ // overlap port and addr
      if (s->fd != socket_fd || s->pid != pid){
        return false;
      }
    }
  }
  return true;
}


} // namespace E