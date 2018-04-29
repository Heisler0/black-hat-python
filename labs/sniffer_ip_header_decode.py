import socket, os, struct
from ctypes import *

#host to listen on
#host = "enp2s0"
host = "192.168.1.249"
#our IP header
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_uint16),
        ("id", c_uint16),
        ("offset", c_uint16),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_uint16),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        #map protocol constant to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        #human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
        #human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

if os.name == "nt":
    # for windows
    sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
else:
    # for Linux
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    #sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x800))
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL, 1)

try:
    while True:
        #read in a packet
        raw_buffer = sniffer.recvfrom(65565)[0]
        #create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:20])
        #print out the protocol that was detected and the hosts
        print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
#handle ctrl-C
except KeyboardInterrupt:
    #if we're using Windows, turn of promiscuous
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
       
