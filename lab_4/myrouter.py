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
        # init the ARP table----IP-MAC pairs
        self.arp_tab = {}
        # init the forwarding table
        self.fwd_tab = []
        # init the waiting queue for ARP reply
        # composition of every entry in queue:
        #   1. the next hop ip addr (used for requesting the corresponding mac addr)
        #   2. last_request_time (interval < 1)
        #   3. cnt-->times of requesting
        #   4. matched forwarding table entry
        #   5. IPv4 packet
        #   6. ARP request packet
        self.wait_q = []

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
                        self.arp_tab[arp.senderprotoaddr] = arp.senderhwaddr
                        log_info("Cached ARP table updated: {}".format(str(self.arp_tab)))

                        # drop if target ip does not exist here
                        if arp.targetprotoaddr in self.ipaddrs:
                            wanted_macaddr = self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr
                            arp_reply = create_ip_arp_reply(wanted_macaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                            self.net.send_packet(dev, arp_reply)
                    elif (arp.operation == ArpOperation.Reply):
                        # handle ARP replies to my requests stuck in the waiting queue
                        cur_mac = arp.senderhwaddr
                        cur_ip = arp.senderprotoaddr
                        # add the reply information to the ARP table
                        self.arp_tab[cur_ip] = cur_mac
                        # looking for the corresponding receiver to the ARP reply
                        for entry in self.wait_q[:]:
                            if cur_ip == entry[0]:
                                ether = Ethernet()
                                ether.src = self.net.interface_by_name((entry[3])[3]).ethaddr
                                ether.dst = cur_mac
                                ether.ethertype = EtherType.IPv4
                                ipv4_pkt = ether + entry[4]
                                self.net.send_packet((entry[3])[3], ipv4_pkt)
                                self.wait_q.remove(entry)
                                break

                # 2. handle IPv4 packets
                ipv4 = pkt.get_header(IPv4)
                if (ipv4):
                    # drop the pkt if the dst belong to the router itself
                    if ipv4.dst not in self.ipaddrs:
                        # denote the longest prefix match so far
                        longest = 0
                        # denote the updated matched entry
                        matched_entry = []
                        for entry in self.fwd_tab:
                            prefixnet = IPv4Network(entry[0] + '/' + entry[1])
                            if (ipv4.dst in prefixnet) and (longest < prefixnet.prefixlen):
                                longest = prefixnet.prefixlen
                                matched_entry = entry
                        # drop the pkt if no matches found
                        if matched_entry != [] :
                            # assume ttl >= 0
                            ipv4.ttl -= 1
                            intf = self.net.interface_by_name(matched_entry[3])
                            # 1. the dst is within the subnet to which the intf belong
                            #    so the next hop is the dst
                            if matched_entry[2] == '0.0.0.0':
                                next_hop_ip = ipv4.dst
                            # 2. the next hop is an IP address on a router through which the destination is reachable
                            else:
                                next_hop_ip = matched_entry[2]
                            if next_hop_ip in self.arp_tab:
                                dst_macaddr = self.arp_tab[next_hop_ip]
                                ether = Ethernet()
                                ether.src = intf.ethaddr
                                ether.dst = dst_macaddr
                                ether.ethertype = EtherType.IPv4
                                ipv4_pkt = ether + ipv4
                                self.net.send_packet(matched_entry[3], ipv4_pkt)
                            else:
                                arp_rqst = create_ip_arp_request(senderhwaddr = intf.ethaddr,
                                                                senderprotoaddr = intf.ipaddr,
                                                                targetprotoaddr = next_hop_ip)
                                self.net.send_packet(matched_entry[3], arp_rqst)
                                # add this request into waiting queue
                                self.wait_q.append(list(next_hop_ip, time.time, 1, matched_entry, ipv4, arp_rqst))
                # 3. update every entry state in the waiting queue
                for entry in self.wait_q[:]:
                    # ARP reply is not received after 1s
                    if time.time - entry[1] > 1:
                        # ARP request already sent exactly 5 times
                        if (entry[2] >= 5):
                            self.wait_q.remove(entry)
                        # still be able to send ARP request
                        else:
                            entry[1] = time.time
                            entry[2] += 1
                            self.net.send_packet((entry[3])[3], entry[5])


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.init_fwd_tab()
    r.router_main()
    net.shutdown()
