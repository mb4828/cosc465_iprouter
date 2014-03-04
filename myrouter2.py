#!/usr/bin/env python

'''
Basic IPv4 router (static routing) in Python, stage 1.
'''

import sys
import os
import os.path
import time
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp
from pox.lib.addresses import EthAddr,IPAddr,netmask_to_cidr
from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger
from collections import deque

class PacketData(object):
    def __init__(self, pkt, arpreq, interface):
        self.pkt = pkt                      # packet waiting to be sent
        self.arpreq = arpreq                # copy of the arp request
        self.interface = interface          # interface that we are sending packets out of
        self.ip = arpreq.payload.protodst   # ip address that we're wating for (because I'm a lazy programmer)
        self.lastsent = time.time()         # approximate time of last ARP request
        self.retries = 5                    # number of retries left

    def isExpired(self):
        if time.time()-self.lastsent >= 1:
            return 1
        return 0

    def isDead(self):
        if self.retries <= 0:
            return 1
        return 0

    def logRetry(self):
        self.lastsent = time.time()
        self.tries -= 1

class Router(object):
    def __init__(self, net):
        self.net = net
        self.myports = dict()        # ethernet address translations for my ip addresses (key: ipaddr, value: ethaddr)
        self.maccache = dict()       # cached MAC addresses from elsewhere on network (key: ipaddr, value: MAC addr)
        self.ftable = self.buildft() # ip fowarding table (entry: (network addr, subnet mask, next hop, interface))
        self.jobqueue = deque()      # queue to hold packet data waiting to be sent

        for intf in net.interfaces():
            self.myports[intf.ipaddr] = intf.ethaddr

        print self.myports.keys()
        print self.myports.values()

    def router_main(self):    
        while True:
            try:
                dev,ts,pkt = self.net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                # log_debug("Timeout waiting for packets")
                continue
            except SrpyShutdown:
                return

            print "-"*64
            # 1. update/resend expired jobs in the job queue
            rv = self.queueupdater()
            if rv != 0:
                self.net.send_packet(rv[0], rv[1])                  # re-send ARP req

            # 2. handle ARP replies
            rv = self.queuehandler(pkt)
            if rv != 0:
                self.net.send_packet(rv[0], rv[1])                  # send completed IP packet
                self.maccache[pkt.payload.protosrc] = pkt.payload.hwsrc # log MAC address
                continue

            # 3. handle ARP requests for my interfaces
            rv = self.arpreqhandler(pkt)
            if rv != 0:
                self.net.send_packet(dev, rv)                       # send ARP reply
                self.maccache[pkt.payload.protosrc] = pkt.src       # log MAC address
                continue

            # 4. handle IP packets destined for me and other hosts
            rv = self.packethandler(pkt)
            if rv != 0:
                self.net.send_packet(rv[0], rv[1])                  # send IP packet or ARP req
                continue
    
    def queueupdater(self):
        '''
        Checks the head of the job queue for dead (no more retries) or expired (time to
        re-send ARP request) jobs. Returns 0 if no action needed or (interface, arpreq)
        if it's time to resend
        '''
        # 1. is the job queue empty?
        if len(self.jobqueue) <= 0:
            return 0

        # 2. is the head of the queue dead? (no more retries)
        if self.jobqueue[0].isDead():
            self.jobqueue.popleft()
            print "QUEUE UPDATER:"
            print "Head is dead"
            return 0

        # 3. is the head of the queue expired? (time to re-send ARP request)
        if self.jobqueue[0].isExpired():
            print "QUEUE UPDATER:"
            print "Retry #" + self.jobqueue[0].retries
            self.jobqueue[0].logRetry()
            return (self.jobqueue[0].interface, self.jobqueue[0].arpreq)

        return 0
            
    def queuehandler(self, pkt):
        '''
        Matches ARP replies with jobs in the job queue and constructs an outgoing IP 
        packet for them. Returns 0 if no action necessary and (interface, IP packet)
        if packet is ready
        '''
        # 1. is this an ARP reply?
        if pkt.type != pkt.ARP_TYPE:
            return 0    # no
        if pkt.payload.opcode != arp.REPLY:
            return 0    # we don't handle ARP requests

        # 2. is it for me?
        if not pkt.payload.protodst in self.myports.keys():
            return 0    # no

        # 3. does this MAC address match any of the jobs waiting in the queue
        for i in range(len(self.jobqueue)):
            if pkt.payload.protosrc == self.jobqueue[i].ip:
                # 3a. construct a finished packet to be sent out and return
                print "QUEUE HANDLER:"
                print "Got an ARP reply for " + str(self.jobqueue[i].ip)
                ethhead = pktlib.ethernet()
                ethhead.type = ethhead.IP_TYPE
                ethhead.src = self.jobqueue[i].arpreq.src
                ethhead.dst = pkt.payload.hwsrc
                ethhead.payload = self.jobqueue[i].pkt.payload
                intf = self.jobqueue[i].interface

                del self.jobqueue[i]

                print ethhead.dump()
                return (intf, ethhead)

    def arpreqhandler(self, pkt):
        '''
        Identifies incoming ARP requests and generates an ARP reply. Returns 0 if packet
        is not an ARP request and ARP reply otherwise
        '''
        # 1. is this an ARP request?
        if pkt.type != pkt.ARP_TYPE:
            return 0    # no
        if pkt.payload.opcode != arp.REQUEST:
            return 0    # we don't handle ARP replies

        # 2. is it for me?
        if not pkt.payload.protodst in self.myports.keys():
            return 0    # no

        print "ARP REQUEST HANDLER:"        
        # 3. generate ARP reply
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
        
        # 4. hand off ARP reply back to router main
        return ether_reply

    def packethandler(self, pkt):
        '''
        Handles packets destined for other hosts by generating either an ARP request
        or a new, completed packet. Returns 0 if no action is necessary and
        (interface, packet) otherwise
        '''
        # 1. is this an IP packet?
        if pkt.type != pkt.IP_TYPE:
            return 0    # no

        # 2. is the packet for me?
        if pkt.payload.dstip in self.myports.keys():
            return 0    # drop the packet

        print "PACKET HANDLER:"
        print "Pkt src: " + str(pkt.payload.srcip)
        print "Pkt dst: " + str(pkt.payload.dstip)
        print "Eth src: " + str(pkt.src)
        print "Eth dst: " + str(pkt.dst)

        # 3. figure out where we are sending the packet
        lm_index = -1       # index of the packet destination
        lm_len = -1         # length of the longest prefix
        l = len(self.ftable)

        # 3a. is the destination an exact match to a nexthop? (directly reachable)
        i = 0
        while (i<l):
            nexthop = IPAddr(self.ftable[i][2])
        
            if pkt.payload.dstip == nexthop:
                # exact match found
                lm_index = i
                break
        
            i+=1

        # 3b. perform longest prefix match lookup if no exact match exists
        if lm_index == -1:
            i = 0
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

        # 4. did we find a match in the table?
        if lm_index == -1:
            print "No match found in forwarding table"
            return 0    # no

        # 5. create a new ethernet header for the packet
        print "Packet should be sent to " + self.ftable[lm_index][2] + " out interface " + self.ftable[lm_index][3]

        pkt.payload.ttl -= 1        # decrement ttl

        ethhead = pktlib.ethernet()

        for intf in self.net.interfaces():      # lookup MAC and IP source by port ID
            if intf.name == self.ftable[lm_index][3]:
                ethhead.src = intf.ethaddr
                potprotosrc = intf.ipaddr
                break

        # 5a. do we already know the MAC address of the destination?
        if pkt.payload.dstip in self.maccache.keys():
            ethhead.type = ethhead.IP_TYPE
            ethhead.dst = self.maccache[pkt.payload.dstip]

            etthead.payload = pkt.payload                    # payload is the IP packet
            
        # 5b. if not, generate an ARP request for the MAC address and add to queue
        else:
            ethhead.type = ethhead.ARP_TYPE
            ethhead.dst = ETHER_BROADCAST

            arpreq = pktlib.arp()
            arpreq.opcode = pktlib.arp.REQUEST
            arpreq.protosrc = potprotosrc
            arpreq.protodst = IPAddr(self.ftable[lm_index][2])
            arpreq.hwsrc = ethhead.src
            arpreq.hwdst = ETHER_BROADCAST

            ethhead.payload = arpreq                         # payload is the ARP request
            self.jobqueue.append(PacketData(pkt,ethhead,self.ftable[lm_index][3]))    # add to job queue
            
        print ethhead.dump()
        return (self.ftable[lm_index][3],ethhead)            # return completed packet or ARP request

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
    
