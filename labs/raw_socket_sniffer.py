import socket, os

#host to listen on
host = "enp2s0"

#create a raw socket and build it to the public interface
if os.name == "nt":
    sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
else:
    sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sniffer.bind((host, 0))

#we want the IP headers included in the capture
#sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#if we're using Windows, we need to send an IOCTL to set up promiscuous mode
#read in a single packet
print sniffer.recvfrom(65565)
#if we're using Windows, turn off promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
