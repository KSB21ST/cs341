{\rtf1\ansi\ansicpg949\cocoartf2580
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;\f1\fnil\fcharset0 HelveticaNeue;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx566\tx1133\tx1700\tx2267\tx2834\tx3401\tx3968\tx4535\tx5102\tx5669\tx6236\tx6803\pardirnatural\partightenfactor0

\f0\fs24 \cf0 void packetArrived(std::string fromModule, Packet &&packet);\
* bit corruption checking\
: After readData from arrived packet, first we check whether bit corruption is occured using checksum. \
\
* timer cancel\
: When send the packet, we added timer and made sPacket object and push to sendPacket vector in socket. If the corresponding ACK packet is arrived, we have to cancel the timer. So when the packet which is turning on ACK flag is arrived, find the packet that is the owner of the ACK reply and cancel the timer.\
\
* update RTT\
: When the packet which is turning on ACK flag is arrived, we can get SampleRTT for calculating EstimatedRTT, DevRTT and TimeoutInterval. So find the packet that is the owner of the ACK reply and get SampleRTT to calculate difference between getCurrentTime() and my_packet->send_time. And then, update EstimatedRTT, DevRTT and TimeoutInterval with SampleRTT.\
\
void timerCallback(std::any payload);\
: Have to resend a packet. When add the timer, make tuple, which has two elements Packet and Socket *, for payload. So, in the timerCallback, clone the given packet and resend cloned packet. At this time, we had the same process as when sending the packet originally. (make sPacket object and push to sendPackets vector and add timer, etc) But, when the packet is data packet (packet's payload size is not zero), we didn't add timer. Because if you put a timer it will infinitely call timercallback function.\
\
<additional implemented functions>\
sPacket * find_packet(Socket *socket, uint32_t ack_num);\
: implemeted to find corresponding packet. In this function, iterate on sendPackets vector in socket(parameter) and find pointer of sPacket object which has same next_seq_num with ack_num(parameter). This sPacket * object is erased from sendPackets vector and returned. If there is no appropriate sPacket object in sendPackets vector, just return nullptr.\
\
int remove_packet(Socket *socket, uint32_t ack_num);\
: We implement this function for handling ACK loss. When the ack arrives, it means that all the previous packets have arrived successfully, so the previous packets need to be removed. In this function, remove all packet objects before the packet which has same next_seq_num with ack num(parameter) from the sendPacket vector.\
\pard\pardeftab560\slleading20\pardirnatural\partightenfactor0

\f1\fs26 \cf0 \
\pard\pardeftab560\slleading20\partightenfactor0
\cf0 *syscall_read\
 When the receiver tries to call read before sender calls write and send data packet, the read() system call should be pending until packet including the data. Thus, we made the structure \'91read_meta\'92 to save the buffer pointer and count bytes to mediate the inputs of read() when data packet arrives at packetArrived(). When packet with data arrives before read() is called, then the data should be saved in the receive buffer. For this, we made structure \'91Payload\'92, where we allocate the amount of received data and saves the pointer in \'91payload\'92. \'91Size\'92 is the amount of bytes that was received, and \'91offset\'92 is the position where we should start reading. Later, when read() is called, and Payload is not null, than we can read the saved data and execute read() successfully.\
\
*syscall_read unreliable connection\
When a packet that arrived is other than  expected, we should send duplicate packets to the sender. To enable this, when a new packet with data arrives, we compare the sequence number of the arrived packet and the \'91last_ack_num\'92 inside socket structure, which saves the ack number of the latest ACK package that the receiver sent to the sender. The last_ack_num equals the sum of the sequence number and the bytes of data in the data packet. If the sequence number of the arrived packet and the last_ack_num is the same, it means that correct packet arrived, and we can continue with saving the data. However, if it doesn\'92t match, we send a duplicate ACK packet. In this case, we send a packet to the sender including the \'91last_ack_num\'92 as ACK number.\
\pard\pardeftab560\slleading20\pardirnatural\partightenfactor0
\cf0 \
\pard\pardeftab560\slleading20\partightenfactor0
\cf0 *syscall_write\
Write is a function where we send a packet to the receiver including the data given in the buffer pointer as argument. However, we should consider the window size and control the number of packets sent to the receiver through write(). To enable this, we made a vector of Packets to save the packets made in write. In write(), we make packet from the given buffer and push this to the vector. However, instead of sending the packet to the receiver, we check if the number of sent packets does not go over window size. If it goes over window size, we pend the write() function, until the ACK of previously sent packets arrive. When the ACK arrives in response to previously sent packets, we release the pending and return system call to write(). To enable this, just like read, we made write_meta and saved the buffer pointer and count. \
\pard\pardeftab560\slleading20\pardirnatural\partightenfactor0
\cf0 \
\pard\pardeftab560\slleading20\partightenfactor0
\cf0 *Syscall write unreliable connection\
We implemented a go-back-N flow control, where we chose the window size as 10. To take care of all the packets that were sent, we made the packet queue inside Socket structure. Each socket has a vector of sent or to-be-sent packets. We also made start and end index to check the index of packets sent and packets that received ACK from the receiver afterwards. If we sent a packet to the receiver, we increased \'91end\'92. If we received ACK in response of formerly sent packets, we increased the \'91start\'92 index in meaning that packets before \'91start\'92 is well received. We also implemented timer in each packet, which is explained in the timercallbeck session. If we receive duplicate ACK, we ignore this.}