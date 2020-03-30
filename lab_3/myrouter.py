#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.intfs = net.interfaces()
        # init ipaddrs of all intfs
        self.ipaddrs=[]
        for intf in self.intfs:
            self.ipaddrs.append(intf.ipaddr)


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, 
        receiving packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                # drop this time if it's not an ARP
                if pkt.has_header(Arp):
                    arp = pkt.get_header_by_name(Arp)
                    # drop if it's not a request or target ip does not exist here
                    if (arp.operation == ArpOperation.Request) and (arp.targetprotoaddr in self.ipaddrs):
                        wanted_macaddr = self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr
                        arp_reply = create_ip_arp_reply(wanted_macaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                        self.net.send_packet(dev, arp_reply)



def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
