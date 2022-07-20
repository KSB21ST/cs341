/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include "RoutingAssignment.hpp"

namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {}

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() { //braodcasting in every node to each of it's neighbors
  // cout << "initialize: " << sizeof(rip_t) << " size rip_header: " << sizeof(rip_header_t) << " size of entry: " << sizeof(rip_entry_t) << endl;
  rip_header_t *rip_header = (rip_header_t *)malloc(sizeof(rip_header_t));
  rip_header->command = 1; //for request
  rip_header->version = 1;
  rip_header->zero_0 = 0;
  rip_entry_t *rip_entry = (rip_entry_t *)malloc(sizeof(rip_entry_t));
  rip_entry->address_family = htons(0);
  rip_entry->zero_1 = 0;
  rip_entry->zero_2 = 0;
  rip_entry->zero_3 = 0;
  rip_entry->ip_addr = htonl(0);
  rip_entry->metric = htonl(301);

  in_port_t i = 0;
  optional<ipv4_t> src_ip = getIPAddr(0);
  while(src_ip){
    if (i != 0){
      src_ip = getIPAddr(i);
    }
    if(!src_ip){
      // cout << "break! : " << i << endl;
      break;
    }
    in_addr_t source_ip = NetworkUtil::arrayToUINT64<4>(src_ip.value());
    /*initialize routing table*/
    // map <uint32_t, pair<uint32_t, uint32_t> > m;
    // m[source_ip] = {0, 0};
    // routing_td[source_ip] = m;
    routing_td[ntohl(source_ip)] = 0;
    // neighbors.push_back(ntohl(source_ip));
    links.push_back(ntohl(source_ip));

    uint16_t src_port = getRoutingTable (NetworkUtil::UINT64ToArray<4> (source_ip));
    // cout << "src_port: " << src_port << endl;
    optional<ipv4_t> src_ip_temp = getIPAddr(src_port);
    uint32_t source_ip2 = NetworkUtil::arrayToUINT64<4>(src_ip_temp.value());
    // cout << ntohl(source_ip) << " " << ntohl(source_ip2) << endl;



    /**/
    uint32_t dst_ip = htonl(0xffffffff);
    uint16_t rip_port = htons(520);
    size_t pkt_size = 14; //for ethernet header
    pkt_size += 20; // for ip header
    pkt_size += 8; // for udp header
    pkt_size += 24; //sizeof(rip_header_t) + sizeof(rip_entry_t) for rip data
    uint16_t udp_size = htons(8+24); //htons(8 + sizeof(rip_header_t) + sizeof(rip_entry_t));
    Packet pkt(pkt_size);
    pkt.writeData(26, &source_ip, 4); //ip header: write source ip in IP header 14 + 12
    pkt.writeData(30, &dst_ip, 4); //ip header: write dst ip (broadcast: 255.255.255.255)
    pkt.writeData(34, &rip_port, 2); //udp header: write source - RIP port in UDP header
    pkt.writeData(36, &rip_port, 2); //udp header: write dst - RIP port in UDP header
    pkt.writeData(38, &udp_size, 2); //udp header: length
    //first skip checksum
    pkt.writeData(42, &rip_header->command, 1);
    pkt.writeData(43, &rip_header->version, 1);
    pkt.writeData(44, &rip_header->zero_0, 2);
    pkt.writeData(46, &rip_entry->address_family, 2);
    pkt.writeData(48, &rip_entry->zero_1, 2);
    pkt.writeData(50, &rip_entry->ip_addr, 4);
    pkt.writeData(54, &rip_entry->zero_2, 4);
    pkt.writeData(58, &rip_entry->zero_3, 4);
    pkt.writeData(62, &rip_entry->metric, 4);

    uint16_t checksum;
    uint8_t udp_seg[ntohs(udp_size) + 8];
    pkt.readData (34, udp_seg, ntohs(udp_size));
    checksum = NetworkUtil::tcp_sum (source_ip, dst_ip, udp_seg, ntohs(udp_size));
    checksum = htons (~checksum);
    pkt.writeData (40, &checksum, 2); //udp header: checksum
    sendPacket ("IPv4", move (pkt));
    i++;
  }
  global_timer = addTimer (-1, (Time) 30 * 1000 * 1000 * 1000);
  // cout << "max port num: " << i << endl;
  // printLinkCost();
  free(rip_entry);
  free(rip_header);
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  uint32_t ip_addr = NetworkUtil::arrayToUINT64<4> (ipv4);
  uint16_t src_port = getRoutingTable (NetworkUtil::UINT64ToArray<4> (ip_addr));
  // cout << "src_port: " << src_port << endl;
  optional<ipv4_t> src_ip_temp = getIPAddr(src_port);
  uint32_t source_ip = NetworkUtil::arrayToUINT64<4>(src_ip_temp.value());

  // cout << ntohl(source_ip) << " inside rip query: " << ntohl(ip_addr) << endl;

  if(routing_td.count(ntohl(ip_addr))){
    uint32_t metric = routing_td[ntohl(ip_addr)];
    if(metric < 301){
      return metric;
    }
  }
  // connection_state();
  // Implement below

  return 400;
}

void RoutingAssignment::printLinkCost(){
  in_port_t i = 0;
  optional<ipv4_t> src_ip = getIPAddr(0);
  while(src_ip){
    if (i != 0){
      src_ip = getIPAddr(i);
    }
    if(!src_ip){
      break;
    }
    // cout << "port number: " << i << " link cost: " << linkCost(i) << endl;
    i++;
  }
}

void RoutingAssignment::connection_state ()
{
  for ( const auto &p : my_links )
  {
    cout << p.first << '\t' << p.second << endl;
  } 
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t udp_size;
  uint8_t command;
  uint8_t version;
  uint16_t zero_0;


  packet.readData(26, &src_ip, 4); //ip header: write source ip in IP header 14 + 12
  packet.readData(30, &dst_ip, 4); //ip header: write dst ip (broadcast: 255.255.255.255)
  packet.readData(38, &udp_size, 2); //udp header: length
  //packet skip checksum
  packet.readData(42, &command, 1);
  packet.readData(43, &version, 1);
  packet.readData(44, &zero_0, 2);

  int entry_count = (ntohs(udp_size) - 12)/20; //udp header 8, rip header 4, one rip entry size 20

  uint16_t address_family; // 2 for IP
  uint16_t zero_1;         // must be zero
  uint32_t ip_addr;        // IPv4 address
  uint32_t zero_2;         // must be zero
  uint32_t zero_3;         // must be zero
  uint32_t metric;         // hop-count (max 15) for RIPv1
  packet.readData(46, &address_family, 2);
  packet.readData(48, &zero_1, 2);
  packet.readData(50, &ip_addr, 4);
  packet.readData(54, &zero_2, 4);
  packet.readData(58, &zero_3, 4);
  packet.readData(62, &metric, 4);

  uint16_t src_port = getRoutingTable (NetworkUtil::UINT64ToArray<4> (src_ip));
  // cout << "src_port: " << src_port << endl;
  optional<ipv4_t> src_ip_temp = getIPAddr(src_port);
  uint32_t source_ip = NetworkUtil::arrayToUINT64<4>(src_ip_temp.value());

  if (command == 1){
    // cout << ntohl(source_ip) << " command: 1"  << " src_ip: " << htonl(src_ip) << " dst_ip: " << htonl(dst_ip) << " address family: " << ntohs(address_family) << " ip addr: " << ntohl(ip_addr) << " metric: " << ntohl(metric) << endl;
  // }else{
    // cout << ntohl(source_ip) << " command: 2"  << " src_ip: " << htonl(src_ip) << " dst_ip: " << htonl(dst_ip) << " address family: " << ntohs(address_family) << " ip addr: " << ntohl(ip_addr) << " metric: " << ntohl(metric) << endl;
  }
  


  if(command == 1){ //request, should send the routing table to neighbors
    if (address_family == 0 && entry_count == 1 && ip_addr == 0){ //initial broadcast request
      // cancelTimer(global_timer);
      // cout << "inside request entry count: " << entry_count << endl;
      neighbors.push_back(ntohl(src_ip));
      my_links[ntohl(src_ip)] = ntohl(source_ip);
      rip_t *rip_total = (rip_t *)malloc(sizeof(rip_header_t) + sizeof(rip_entry_t)*routing_td.size());
      rip_header_t *rip_header = (rip_header_t *)malloc(sizeof(rip_header_t));
      // rip_entry_t rip_entry[routing_td.size()];
      // for(int i = 0;i<links.size();i++){
      //   if(ntohl(source_ip) == links[i]){
      //     rip_entry[i].address_family = htons(2);
      //     rip_entry[i].zero_1 = 0;
      //     rip_entry[i].ip_addr = htonl(links[i]);
      //     rip_entry[i].zero_2 = 0;
      //     rip_entry[i].zero_3 = 0;
      //     // rip_entry[i].metric = htonl(linkCost(src_port));
      //     rip_entry[i].metric = htonl(0);
      //   }
      // }
      int index = 0;
      for ( const auto &p : routing_td )
      {
        rip_total->entries[index].address_family = htons(2);
        rip_total->entries[index].zero_1 = 0;
        rip_total->entries[index].ip_addr = htonl(p.first);
        rip_total->entries[index].zero_2 = 0;
        rip_total->entries[index].zero_3 = 0;
        bool is_mine = false;
        for ( const auto &t : my_links )
        {
          if(t.second == p.first){
            is_mine = true;
            break;
          }
        }
        if(is_mine){
          rip_total->entries[index].metric = htonl(0);
        }else{
          rip_total->entries[index].metric = htonl(p.second);
        }
        index++;
      }
      assert(index == routing_td.size());
      rip_header->command = 2;
      rip_header->version = 1;
      rip_header->zero_0 = 0;

      // cout << "src_ip: " << ntohl(src_ip) << " src_port: " << ntohs(src_port) << " source_ip: " << ntohl(source_ip) << endl;

      //make packet
      uint16_t rip_port = htons(520);
      size_t pkt_size = 14; //for ethernet header
      pkt_size += 20; // for ip header
      pkt_size += 8; // for udp header
      pkt_size += sizeof(rip_header_t) + routing_td.size() * sizeof(rip_entry_t);
      uint16_t udp_size = htons(pkt_size - 34);
      Packet pkt(pkt_size);
      pkt.writeData(26, &source_ip, 4); //ip header: write source ip in IP header 14 + 12
      pkt.writeData(30, &src_ip, 4); //ip header: write dst ip (broadcast: 255.255.255.255)
      pkt.writeData(34, &rip_port, 2); //udp header: write source - RIP port in UDP header
      pkt.writeData(36, &rip_port, 2); //udp header: write dst - RIP port in UDP header
      pkt.writeData(38, &udp_size, 2); //udp header: length
      //first skip checksum
      pkt.writeData(42, &rip_header->command, 1);
      pkt.writeData(43, &rip_header->version, 1);
      pkt.writeData(44, &rip_header->zero_0, 2);
      int offset = 46;
      for(int j=0;j<routing_td.size();j++){
        pkt.writeData(offset, &rip_total->entries[j].address_family, 2);
        pkt.writeData(offset + 2, &rip_total->entries[j].zero_1, 2);
        pkt.writeData(offset + 4, &rip_total->entries[j].ip_addr, 4);
        pkt.writeData(offset + 8, &rip_total->entries[j].zero_2, 4);
        pkt.writeData(offset + 12, &rip_total->entries[j].zero_3, 4);
        pkt.writeData(offset + 16, &rip_total->entries[j].metric, 4);
        offset += 20;
      }


      uint16_t checksum;
      uint8_t udp_seg[ntohs(udp_size) + 8];
      pkt.readData(34, udp_seg, ntohs(udp_size));
      checksum = NetworkUtil::tcp_sum (dst_ip, src_ip, udp_seg, ntohs(udp_size));
      checksum = htons (~checksum);
      pkt.writeData (40, &checksum, 2); //udp header: checksum

      sendPacket ("IPv4", move (pkt));
      free(rip_header);
      free(rip_total);
      return;
    }
    else if(entry_count > 1){
      // cout << "inside request entry count: " << entry_count << endl;
    }
  }
  else if (command == 2){
    // cancelTimer(global_timer);
    int offset = 46;
    // cout << ntohl(src_ip) << " entry_count: " << entry_count << endl;
    for(int i = 0;i<entry_count;i++){
      uint16_t address_family; // 2 for IP
      uint16_t zero_1;         // must be zero
      uint32_t ip_addr;        // IPv4 address
      uint32_t zero_2;         // must be zero
      uint32_t zero_3;         // must be zero
      uint32_t metric;         // hop-count (max 15) for RIPv1
      packet.readData(offset, &address_family, 2);
      packet.readData(offset + 2, &zero_1, 2);
      packet.readData(offset + 4, &ip_addr, 4);
      packet.readData(offset + 8, &zero_2, 4);
      packet.readData(offset + 12, &zero_3, 4);
      packet.readData(offset + 16, &metric, 4);
      offset += 20;

      // cout << "ip_addr: " << ntohl(ip_addr) << endl;

      uint32_t new_metric;
      bool in_router = false;
      for ( const auto &p : routing_td )
      {
        if(ntohl(ip_addr) == p.first){
          in_router = true;
          break;
        }
      }

      if(in_router){
        uint32_t original = routing_td[ntohl(ip_addr)];
        new_metric = ntohl(metric) + linkCost(src_port);
        if(new_metric< original){
          routing_td[ntohl(ip_addr)] = new_metric;
        }

      }else{
        routing_td[ntohl(ip_addr)] = ntohl(metric) + linkCost(src_port);
      }
      

      // bool is_neighbor = false;
      // for ( const auto &p : my_links )
      // {
      //   if(ntohl(ip_addr) == p.first){
      //     is_neighbor = true;
      //     break;
      //   }
      // } 
      // if(!is_neighbor){ //not a neighbor
      //   bool is_mine = false;
      //   for ( const auto &t : my_links )
      //   {
      //     if(ntohl(ip_addr) == t.second){
      //       is_mine = true;
      //       break;
      //     }
      //   }

      //   if(is_mine){
      //     routing_td[ntohl(ip_addr)] = 0;
      //   }else{
      //     routing_td[ntohl(ip_addr)] = ntohl(metric) + linkCost(src_port);
      //   }
      //   // cout << ntohl(source_ip) << " " << ntohl(ip_addr) << " " << ntohl(src_ip) << " is not a neighbor" << " metric: " << ntohl(metric) << " new metric: " << routing_td[ntohl(ip_addr)] << endl;
      // }else{ //yes a neighbor
      //   // cout << ntohl(ip_addr) << " is a neighbor"<< endl;
      //   // cout << "original: " << routing_td[ntohl(ip_addr)] << " metric: " << ntohl(metric) << endl;
      //   bool is_mine = false;
      //   for ( const auto &t : my_links )
      //   {
      //     // cout << p.first << '\t' << p.second << endl;
      //     if(ntohl(ip_addr) == t.second){
      //       is_mine = true;
      //       break;
      //     }
      //   }
      //   if(is_mine){
      //     routing_td[ntohl(ip_addr)] = 0;
      //   }else{
      //     // new_metric = ntohl(metric);
      //     uint32_t original = routing_td[ntohl(ip_addr)];
      //     if(new_metric == 0 && original == 0){
      //       original = linkCost(src_port);
      //       routing_td[ntohl(ip_addr)] = linkCost(src_port);
      //     }
      //     if(new_metric == 0){
      //       new_metric = original;
      //     }else if(original == 0){
      //       new_metric = ntohl(metric);
      //     }else{
      //       new_metric = min(ntohl(metric), original);
      //     }
      //     routing_td[ntohl(ip_addr)] = new_metric;
      //     // routing_td[ntohl(ip_addr)] = linkCost(src_port);
      //     // cout << ntohl(source_ip) << " " << ntohl(ip_addr) << " " << ntohl(src_ip) << " yes neighbor" << " original: " << original << " metric: " << ntohl(metric) << " new metric: " << routing_td[ntohl(ip_addr)] << endl;
      //   }
      // }
      // cout << "routing table: " << ntohl(source_ip) << endl;
      // printRoutingTable();
    }
    // printRoutingTable();
  }
}

void RoutingAssignment::timerCallback(std::any payload) {
  rip_header_t *rip_header = (rip_header_t *)malloc(sizeof(rip_header_t));
  rip_t *rip_total = (rip_t *)malloc(sizeof(rip_header_t) + sizeof(rip_entry_t)*routing_td.size());

  // rip_entry_t rip_entry[routing_td.size()];
  int index = 0;
  for ( const auto &p : routing_td )
  {
    rip_total->entries[index].address_family = htons(2);
    rip_total->entries[index].zero_1 = 0;
    rip_total->entries[index].ip_addr = htonl(p.first);
    rip_total->entries[index].zero_2 = 0;
    rip_total->entries[index].zero_3 = 0;
    bool is_mine = false;
    for ( const auto &t : my_links )
    {
      if(t.second == p.first){
        is_mine = true;
        break;
      }
    }
    if(is_mine){
      rip_total->entries[index].metric = htonl(0);
      // rip_total->entries[index].metric = htonl(p.second);
    }else{
      rip_total->entries[index].metric = htonl(p.second);
      // rip_total->entries[index].metric = htonl(0);
    }
    
    index++;
  } 
  // cout << "index: " << index << " routing_td size: " << routing_td.size() << endl;;
  assert(index == routing_td.size());
  rip_header->command = 2;
  rip_header->version = 1;
  rip_header->zero_0 = 0;

  /*broadcast to all the neighbors*/
  in_port_t i = 0;
  optional<ipv4_t> src_ip = getIPAddr(0);
  while(src_ip){
    if (i != 0){
      src_ip = getIPAddr(i);
    }
    if(!src_ip){
      break;
    }
    in_addr_t source_ip = NetworkUtil::arrayToUINT64<4>(src_ip.value());

    //make packet
    uint16_t rip_port = htons(520);
    size_t pkt_size = 14; //for ethernet header
    pkt_size += 20; // for ip header
    pkt_size += 8; // for udp header
    pkt_size += sizeof(rip_header_t) + routing_td.size() * sizeof(rip_entry_t);
    uint16_t udp_size = htons(pkt_size - 34);
    Packet pkt(pkt_size);
    uint32_t dst_ip = htonl(0xffffffff);
    pkt.writeData(26, &source_ip, 4); //ip header: write source ip in IP header 14 + 12
    pkt.writeData(30, &dst_ip, 4); //ip header: write dst ip (broadcast: 255.255.255.255)
    pkt.writeData(34, &rip_port, 2); //udp header: write source - RIP port in UDP header
    pkt.writeData(36, &rip_port, 2); //udp header: write dst - RIP port in UDP header
    pkt.writeData(38, &udp_size, 2); //udp header: length
    //first skip checksum
    pkt.writeData(42, &rip_header->command, 1);
    pkt.writeData(43, &rip_header->version, 1);
    pkt.writeData(44, &rip_header->zero_0, 2);

    int offset = 46;
    for(int j=0;j<routing_td.size();j++){
      pkt.writeData(offset, &rip_total->entries[j].address_family, 2);
      pkt.writeData(offset + 2, &rip_total->entries[j].zero_1, 2);
      pkt.writeData(offset + 4, &rip_total->entries[j].ip_addr, 4);
      pkt.writeData(offset + 8, &rip_total->entries[j].zero_2, 4);
      pkt.writeData(offset + 12, &rip_total->entries[j].zero_3, 4);
      pkt.writeData(offset + 16, &rip_total->entries[j].metric, 4);
      offset += 20;
    }
    uint16_t checksum;
    uint8_t udp_seg[ntohs(udp_size) + 8];
    pkt.readData (34, udp_seg, ntohs(udp_size));
    checksum = NetworkUtil::tcp_sum (source_ip, dst_ip, udp_seg, ntohs(udp_size));
    checksum = htons (~checksum);
    pkt.writeData (40, &checksum, 2); //udp header: checksum
    sendPacket ("IPv4", move (pkt));
    i++;
  }
  // cout << "max port num in timeout: " << i << endl;
  // printLinkCost();
  global_timer = addTimer(NULL, (Time) 30 * 1000 * 1000 * 1000);
  free(rip_header);
  free(rip_total);
}

} // namespace E