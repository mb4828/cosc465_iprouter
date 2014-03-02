#!/usr/bin/env python

'''
Basic IPv4 router (static routing) in Python, stage 1.
'''

import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp
from pox.lib.addresses import EthAddr,IPAddr,netmask_to_cidr
from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger

class Router(object):
    def __init__(self, net):
        self.net = net
        self.myports = dict()        # ethernet address translations for my ip addresses (key: ipaddr, value: ethaddr)
        self.maccache = dict()       # cached MAC addresses from elsewhere on network (key: ipaddr, value: MAC addr)
        self.ftable = self.buildft() # ip fowarding table (entry: (network addr, subnet mask, next hop, interface))

        for intf in net.interfaces():
            self.myports[intf.ipaddr] = intf.ethaddr

    def router_main(self):    
        while True:
            try:
                dev,ts,pkt = self.net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                # log_debug("Timeout waiting for packets")
                continue
            except SrpyShutdown:
                return

            # respond to ARP requests for my interfaces and log IP/Ethernet mapping
            arp_reply = self.arphandler(pkt)
            if arp_reply != 0:
                self.net.send_packet(dev, arp_reply)
                self.maccache[pkt.payload.protosrc] = pkt.src
                continue

            # handle IP packets destined for me and other hosts
            self.packethandler(pkt)
                

    def packethandler(self, pkt):
        '''
        Handles packets destined for other hosts
        '''
        # is this an IP packet?
        if pkt.type != pkt.IP_TYPE:
            return 0    # no

        # is the packet for me?
        if pkt.payload.dstip in self.myports.keys():
            return 0    # drop the packet

        # perform longest prefix match lookup
        lm_index = -1
        lm_len = -1
        i = 0
        l = len(self.ftable)

        while (i<l):
            mask = IPAddr(self.ftable[i][1])
            masklen = netmask_to_cidr(mask)
            mask_unsigned = mask.toUnsigned()
            ip_unsigned = pkt.payload.dstip.toUnsigned()
            
            ip_masked = IPAddr(ip_unsigned & mask_unsigned)

            if ip_masked == IPAddr(self.ftable[i][0]):
                # masked IP address matches the network address
                if masklen > lm_len:
                    # network address is the longest prefix
                    lm_index = i
                    lm_len = masklen
            
            i+=1

        # did we find a match in the table?
        if lm_index == -1:
            return 0    # no

        # create a new ethernet header for the packet
        print "Packet should be sent to " + self.ftable[lm_index][2] + " out interface " + self.ftable[lm_index][3]


    def arphandler(self, pkt):
        '''
        Identifies incoming ARP requests and generates an ARP reply. Returns 0 if packet
        is not an ARP request
        '''
        # is this an ARP request?
        if pkt.type != pkt.ARP_TYPE:
            return 0    # no

        # is it for me?
        if not pkt.payload.protodst in self.myports.keys():
            return 0    # no
        
        # generate ARP reply
        arp_reply = pktlib.arp()
        arp_reply.opcode = pktlib.arp.REPLY
        arp_reply.protosrc = pkt.payload.protodst
        arp_reply.protodst = pkt.payload.protosrc
        arp_reply.hwsrc = self.myports[pkt.payload.protodst]
        arp_reply.hwdst = pkt.payload.hwsrc

        ether_reply = pktlib.ethernet()
        ether_reply.type = ether_reply.ARP_TYPE
        ether_reply.src = self.myports[pkt.payload.protodst]
        ether_reply.dst = pkt.src
        ether_reply.set_payload(arp_reply)
        
        # hand off ARP reply back to router main
        return ether_reply

    def buildft(self):
        '''
        Returns a forwarding table created from the file 'forwarding_table.txt'
        Entry: (network address, subnet mask, next hop, output interface)
        '''
        ftable = []
        f = open('forwarding_table.txt','r')

        while 1:
            entry = f.readline()

            if entry == "":
                break

            entry = entry.split()
            ftable.append((entry[0], entry[1], entry[2], entry[3]))
        
        f.close()
        return ftable


def srpy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
    
