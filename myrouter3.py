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
    def __init__(self, ippkt, arpreq, dout, din):
        self.pkt = ippkt                    # packet waiting to be sent
        self.arpreq = arpreq                # copy of the arp request (ethernet packet)
        self.din = din                      # interface that original packet arrived on
        self.dout = dout                    # interface that we are sending packets out of
        self.ip = arpreq.payload.protodst   # ip address that we're wating for
        self.lastsent = time.time()         # approximate time of last ARP request
        self.retries = 4                    # number of retries left

    def isTime(self):
        if time.time()-self.lastsent >= 1:
            return 1
        return 0

    def isDead(self):
        if self.retries <= 0:
            return 1
        return 0

    def logRetry(self):
        self.lastsent = time.time()
        self.retries -= 1

class Router(object):
    def __init__(self, net):
        self.net = net
        self.myports = dict()        # ethernet address translations for my ip addresses (key: ipaddr, value: ethaddr)
        self.maccache = dict()       # cached MAC addresses from elsewhere on network (key: ipaddr, value: MAC addr)
        self.ftable = self.buildft() # ip fowarding table (entry: (network addr, subnet mask, next hop, interface))
        self.jobqueue = deque()      # queue to hold packet data waiting to be sent

        for intf in net.interfaces():
            self.myports[intf.ipaddr] = intf.ethaddr

        self.printft()
        print self.myports.keys()

    def router_main(self):    
        while True:
            print "-"*64

            try:
                dev,ts,pkt = self.net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                # 1. update/resend expired jobs in the job queue
                rv = self.queueupdater()
                if rv != 0:
                    self.net.send_packet(rv[0], rv[1])              # re-send ARP req
              
                continue

            except SrpyShutdown:
                return

            # 2. handle ARP replies for me
            rv = self.arprephandler(pkt)
            if rv != 0:
                self.net.send_packet(rv[0], rv[1])                  # send completed packet
                self.maccache[pkt.payload.protosrc] = pkt.src       # log MAC address
                continue

            # 3. handle IP packets destined for other hosts
            rv = self.packethandler(pkt, dev)
            if rv != 0:
                self.net.send_packet(rv[0], rv[1])                  # send IP packet or ARP req
                continue

            # 4. handle ARP requests for my interfaces
            rv = self.arpreqhandler(pkt)
            if rv != 0:
                self.net.send_packet(dev, rv)                       # send ARP reply
                self.maccache[pkt.payload.protosrc] = pkt.src       # log MAC address
                continue

            # 5. handle ICMP echo requests for me
            rv = self.ICMPreqhandler(pkt, dev)
            if rv != 0:
                self.net.send_packet(rv[0], rv[1])                  # send echo reply or ARP req
                self.maccache[pkt.payload.srcip] = pkt.src          # log MAC address
                continue

            # 6. handle misc packets addressed to me
            rv = self.miscpackethandler(pkt, dev)
            if rv != 0:
                self.net.send_packet(rv[0], rv[1])                  # send port unreachable error or ARP req
        
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
            print "QUEUE UPDATER:\nRetries left: 0 - ARP request has expired"
            head = self.jobqueue.popleft()

            # create host unreachable error
            ippkt = self.ICMPhstunreachhelper(head.pkt, head.din)
            lm_index = self.lpmhelper(ippkt.srcip)
            if lm_index == -1:
                return 0    # throw up hands in defeat
            ethpkt = self.packethelper(ippkt, lm_index, head.din, 1)

            print "Packet will be sent out " + head.din
            print ethpkt.dump()
            return (head.din, ethpkt)

        # 3. has the head of the queue timed out? (time to re-send ARP request)
        if self.jobqueue[0].isTime():
            print "QUEUE UPDATER:\nRetries left on " + str(self.jobqueue[0].ip) + ": " + str(self.jobqueue[0].retries)
            self.jobqueue[0].logRetry()
            return (self.jobqueue[0].dout, self.jobqueue[0].arpreq)

        return 0
            
    def arprephandler(self, pkt):
        '''
        Matches ARP replies and ICMP replies with jobs in the job queue and constructs 
        an outgoing IP packet for them. Returns 0 if no action necessary and 
        (interface, IP packet) if packet is ready
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
                ethhead.payload = self.jobqueue[i].pkt
                intf = self.jobqueue[i].dout

                del self.jobqueue[i]

                print "Job completed. Ready to send"
                print ethhead.dump()
                return (intf, ethhead)

        return 0

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

    def lpmhelper(self, dstip):
        '''
        Helper function. Performs Longest Prefix Match on the forwarding table
        and returns the index of the longest prefix
        '''
        lm_index = -1       # index of the packet destination
        lm_len = -1         # length of longest prefix
        i = 0
        l = len(self.ftable)
        
        while (i<l):
            masklen = netmask_to_cidr(self.ftable[i][1])
            mask_unsigned = (self.ftable[i][1]).toUnsigned()
            ip_unsigned = dstip.toUnsigned()
            ip_masked = IPAddr(ip_unsigned & mask_unsigned)

            #print "Checking destination " + str(self.ftable[i][0]) + " with masked IP " + str(ip_masked) + " and mask length " + str(masklen)

            if (ip_masked == self.ftable[i][0]) and (masklen > lm_len):
                # network address is the longest prefix
                lm_index = i
                lm_len = masklen
            
            i+=1

        return lm_index

    def packethelper(self, ippkt, lm_index, dev, devflag=0):
        '''
        Helper function. Returns either a finished ethernet packet or an ARP request
        based on the contents of pkt and the forwarding table index. Logs any ARP
        requests in the jobqueue
        '''
        ethhead = pktlib.ethernet()
        arpreq = pktlib.arp()

        if not devflag:
            intf = self.net.interface_by_name(self.ftable[lm_index][3])
        else:
            intf = self.net.interface_by_name(dev)
        ethhead.src = intf.ethaddr
        
        # where are we sending the packet?
        if str(self.ftable[lm_index][2]) == 'x':
            # straight to the final destination
            print "Packet should be sent to " + str(ippkt.dstip) + " (final destination) via interface " + self.ftable[lm_index][3]
            arpreq.protodst = ippkt.dstip
        else:
            # to the next hop
            print "Packet should be sent to " + str(self.ftable[lm_index][2]) + " (next hop) via interface " + self.ftable[lm_index][3]
            arpreq.protodst = self.ftable[lm_index][2]

        # are we missing the MAC address of the destination?
        if not arpreq.protodst in self.maccache.keys():
            print "ARP request needed"
            ethhead.type = ethhead.ARP_TYPE
            ethhead.dst = ETHER_BROADCAST
            ethhead.payload = arpreq
            arpreq.opcode = pktlib.arp.REQUEST
            arpreq.protosrc = intf.ipaddr
            arpreq.hwsrc = intf.ethaddr
            arpreq.hwdst = ETHER_BROADCAST

            # log ARP request in job queue
            if not devflag:
                self.jobqueue.append(PacketData(ippkt,ethhead,self.ftable[lm_index][3],dev))
            else:
                self.jobqueue.append(PacketData(ippkt,ethhead,dev,dev))
        else:
            ethhead.type = ethhead.IP_TYPE
            ethhead.dst = self.maccache[arpreq.protodst]
            ethhead.payload = ippkt

        return ethhead

    def ICMPerrorgen(self, pkt, t, port=0):
        '''
        Helper function. Takes an ethernet packet and generates an IP+ICMP 
        packet with type t:
            0 - time exceeded
            1 - unreachable network
            2 - unreachable port
            3 - unreachable host
        '''
        # create ICMP packet
        icmppkt = pktlib.icmp()
        icmppkt.payload = pktlib.unreach()
        icmppkt.payload.payload = pkt.payload.dump()[:28]

        # set type
        if t==0:
            icmppkt.type = pktlib.TYPE_TIME_EXCEED
        else:
            icmppkt.type = pktlib.TYPE_DEST_UNREACH
            if t==1:
                icmppkt.code = pktlib.CODE_UNREACH_NET
            elif t==2:
                icmppkt.code = pktlib.CODE_UNREACH_PORT
            else:
                icmppkt.code = pktlib.CODE_UNREACH_HOST

        # encapsulate in an IPv4 packet
        ippkt = pktlib.ipv4()
        ippkt.protocol = ippkt.ICMP_PROTOCOL
        ippkt.payload = icmppkt

        if t!=3:
            # pkt is the ethernet packet we received so we just flip the src and dst
            ippkt.srcip = self.net.interface_by_macaddr(pkt.dst).ipaddr
            ippkt.dstip = pkt.payload.srcip
        else:
            # pkt is the IP packet that failed to send
            ippkt.srcip = self.net.interface_by_name(port).ipaddr
            ippkt.dstip = pkt.srcip

        return ippkt

    def ICMPtimexhelper(self, pkt):
        '''
        Helper function. Generates IP+ICMP packet with time exceeded error
        '''
        return self.ICMPerrorgen(pkt, 0)
        
    def ICMPnetunreachhelper(self, pkt):
        '''
        Helper function. Generates IP+ICMP packet with network unreachable error
        '''
        return self.ICMPerrorgen(pkt, 1)

    def ICMPprtunreachhelper(self, pkt):
        '''
        Helper function. Generates IP+ICMP packet with port unreachable error
        '''
        return self.ICMPerrorgen(pkt, 2)

    def ICMPhstunreachhelper(self, pkt, port):
        '''
        Helper function. Generates IP+ICMP packet with host unreachable error
        '''
        return self.ICMPerrorgen(pkt, 3, port)

    def packethandler(self, pkt, dev):
        '''
        Handles packets destined for other hosts by generating an ARP request
        or a new ethernet packet. Supports ICMP time expired and unreachable
        errors. Returns 0 if no action is necessary and (interface, packet) otherwise
        '''
        # 1. is this an IP packet?
        if pkt.type != pkt.IP_TYPE:
            return 0    # no

        # 2. is it for me?
        if pkt.payload.dstip in self.myports.keys():
            return 0    # yes

        print "PACKET HANDLER:\nPkt src: "+str(pkt.payload.srcip)+"\nPkt dst: " + str(pkt.payload.dstip)

        # 3. is the TTL expired?
        pkt.payload.ttl -= 1
        if pkt.payload.ttl <= 0:
            # create an ICMP time exceeded error
            ippkt = self.ICMPtimexhelper(pkt)
        else:
            ippkt = pkt.payload

        # 4. perform longest prefix match to begin computing packet destination
        lm_index = self.lpmhelper(ippkt.dstip)

        # 5. did we find a match in the table?
        if lm_index == -1:
            # create an ICMP network unreachable error
            print "No match found in forwarding table"
            ippkt = self.ICMPnetunreachhelper(pkt)
            lm_index = self.lpmhelper(ippkt.dstip)  # route back to the source

            if lm_index == -1:
                return 0    # if no route to source, give up

        # 6. create either the finished ethernet packet or an ARP request
        ethpkt = self.packethelper(ippkt, lm_index, dev)

        print ethpkt.dump()
        return (self.ftable[lm_index][3],ethpkt)

    def ICMPreqhandler(self, pkt, dev):
        '''
        Handles ICMP echo requests. Returns 0, an ICMP echo reply, or an ARP request
        '''
        # 1. is this an ICMP packet?
        if not ((pkt.type == pkt.IP_TYPE) and (pkt.payload.protocol == pkt.payload.ICMP_PROTOCOL)):
            return 0    # no
        
        # 2. is this an echo request?
        if not (pkt.payload.payload.type == pktlib.TYPE_ECHO_REQUEST):
            return 0    # no

        # 3. is it for me?
        if not (pkt.payload.dstip in self.myports.keys()):
            return 0    # no

        # 4. respond to the echo request
        print "ICMP REQUEST HANDLER:"
        print pkt.dump()

        req = pkt.find('icmp')

        # 4a. create an echo response
        icmprsp = pktlib.icmp()
        icmprsp.type = pktlib.TYPE_ECHO_REPLY
        ping = pktlib.echo()
        ping.id = req.payload.id
        ping.seq = req.payload.seq
        icmprsp.payload = ping

        # 4b. encapsulate in an IPv4 packet
        ippkt = pktlib.ipv4()
        ippkt.protocol = ippkt.ICMP_PROTOCOL
        ippkt.srcip = pkt.payload.dstip
        ippkt.dstip = pkt.payload.srcip
        ippkt.payload = icmprsp

        # 4c. encapsulate in an ethernet packet or create ARP request
        lm_index = self.lpmhelper(ippkt.dstip)
        if lm_index == -1:
            return 0    # throw up hands in defeat
        ethpkt = self.packethelper(ippkt, lm_index, dev)

        print ethpkt.dump()
        return (self.ftable[lm_index][3],ethpkt)

    def miscpackethandler(self, pkt, dev):
        '''
        Handles all miscellaneous packets addressed to me (assumes that ARP requests
        and ICMP echo requests have been dealt with). Returns 0, an ICMP unreachable
        error, or an ARP request
        '''
        # 1. is it for me?
        if not (pkt.payload.dstip in self.myports.keys()):
            return 0    # no

        print "MISC PACKET HANDLER:\nPkt src: "+str(pkt.payload.srcip)

        # 2. assume no one else knew what to do with this packet. generate an ICMP port unreachable error
        ippkt = self.ICMPprtunreachhelper(pkt)
        lm_index = self.lpmhelper(ippkt.srcip)
        if lm_index == -1:
            return 0    # throw up hands in defeat
        ethpkt = self.packethelper(ippkt, lm_index, dev)

        print ethpkt.dump()
        return (self.ftable[lm_index][3],ethpkt)

    def buildft(self):
        '''
        Returns a forwarding table created from the file 'forwarding_table.txt'
        Entry: (network address, subnet mask, next hop, output interface)
        '''
        ftable = []
        f = open('forwarding_table3.txt','r')

        while 1:
            entry = f.readline()
            if entry == "":
                break

            entry = entry.split()
            ftable.append((IPAddr(entry[0]), IPAddr(entry[1]), IPAddr(entry[2]), entry[3]))  # add entry from txt file to ftable

            for intf in self.net.interfaces():
                myportus = IPAddr(intf.ipaddr.toUnsigned() & intf.netmask.toUnsigned())      # trying to find the netmask that matches
                nhus = IPAddr(IPAddr(entry[2]).toUnsigned() & intf.netmask.toUnsigned())     # the next hop from txt file

                if myportus == nhus:
                    ftable.append((nhus, intf.netmask, 'x', entry[3]))                       # add next hop from txt file to table
                                                                                             # using intf netmask and 'x' for nexthop
        f.close()
        return ftable

    def printft(self):
        '''
        Diagnostic function. Prints the contents of the forwarding table in a human-readable format
        '''
        print "-"*64+"\nFORWARDING TABLE:\nnetwork address"+" "*5+"subnet mask"+" "*9+"next hop"+" "*12+"interface"
        for entry in self.ftable:
            ld = len("000.000.000.000")
            l0 = len(str(entry[0]))
            l1 = len(str(entry[1]))
            l2 = len(str(entry[2]))
            print str(entry[0]) + " "*(ld-l0+5) + str(entry[1]) + " "*(ld-l1+5) + str(entry[2]) + " "*(ld-l2+5) + str(entry[3])

def srpy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
    
