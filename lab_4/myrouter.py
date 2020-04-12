#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.intfs = net.interfaces()
        # init ipaddrs of all intfs
        self.ipaddrs = []
        for intf in self.intfs:
            self.ipaddrs.append(intf.ipaddr)
        # init the ARP table----IP-{MAC,last_time}
        self.arp_tab = {}
        # init the forwarding table
        self.fwd_tab = []

    def init_fwd_tab(self):
        '''
        Initialize the forwarding table from 2 sources:
            1. the router's own interfaces
            2. the file named 'forwarding_table.txt'
        A simple list is used to hold each entry in the following order:
            1. network address
            2. subnet mask
            3. next hop IP
            4. intf to forward the packet
        '''
        # add src 1
        for intf in self.intfs:
            entry = []
            entry[0] = intf.ipaddr
            entry[1] = intf.netmask
            entry[2] = '0.0.0.0' # next hop is NONE in this case
            entry[3] = intf.name 

        # add src 2
        for line in open("forwarding_table.txt"):
            entry = line.split()
            self.fwd_tab.append(entry)

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
                # 1. handle ARP packets
                arp = pkt.get_header(Arp)
                if (arp):
                    if (arp.operation == ArpOperation.Request):
                        # add a new entry into the table or just update a recorded one
                        self.arp_tab[arp.senderprotoaddr] = {'mac': arp.senderhwaddr, 'last': time.time()}
                        log_info("Cached ARP table updated: {}".format(str(self.arp_tab)))

                        # drop if target ip does not exist here
                        if arp.targetprotoaddr in self.ipaddrs:
                            wanted_macaddr = self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr
                            arp_reply = create_ip_arp_reply(wanted_macaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                            self.net.send_packet(dev, arp_reply)
                    elif (arp.operation == ArpOperation.Reply):
                        # 
                        a = 1 #delete
                    continue
                # 2. handle IPv4 packets
                ipv4 = pkt.get_header(IPv4)
                if (ipv4):
                    # drop the pkt if the dst belong to the router itself
                    if ipv4.dst not in self.ipaddrs:
                        # denote the longest prefix match so far
                        longest = 0
                        # denote the matched entry so far
                        matched_entry = []
                        for entry in self.fwd_tab:
                            prefixnet = IPv4Network(entry[0] + '/' + entry[1])
                            if (ipv4.dst in prefixnet) and (longest < prefixnet.prefixlen):
                                longest = prefixnet.prefixlen
                                matched_entry = entry
                        # drop the pkt if no matches found
                        if matched_entry != [] :
                            # 1. the dst is within the subnet to which the intf belong
                            if matched_entry[2] == '0.0.0.0':
                                


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.init_fwd_tab()
    r.router_main()
    net.shutdown()
