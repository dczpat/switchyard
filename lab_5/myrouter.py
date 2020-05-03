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
        #   3. cnt-->times of requesting (cnt <= 5)
        #   4. matched forwarding table entry
        #   5. IPv4 packet(x)    original packet
        #   6. ARP request packet
        #   7. input port obj
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
            entry.append(str(intf.ipaddr))
            entry.append(str(intf.netmask))
            entry.append('0.0.0.0')  # next hop is NONE in this case
            entry.append(intf.name)
            self.fwd_tab.append(entry)

        # add src 2
        for line in open("forwarding_table.txt"):
            entry = line.split()
            self.fwd_tab.append(entry)

    def send_icmp_error_pkt(self, error_case, pkt, input_intf):
        '''
        put together all 4 error cases together to simplify code
        '''
        # if ipv4_pkt.src not in self.ipaddrs:
        #     return
        # drop the pkt if another 'error' occurs with the error icmp pkt
        ipv4_pkt = pkt.get_header(IPv4)
        match = False
        for entry in self.fwd_tab:
            prefixnet = IPv4Network(entry[0] + '/' + entry[1], strict=False)
            if ipv4_pkt.dst in prefixnet:
                match = True
                break
        if match == False:
            return

        tmp_icmp = ICMP()
        tmp_ip = IPv4()
        tmp_ip.protocol = IPProtocol.ICMP
        tmp_ip.ttl = 64
        tmp_ip.src = input_intf.ipaddr
        tmp_ip.dst = ipv4_pkt.src

        # ICMP error case 1: no match in forwarding table found
        if error_case == 1:
            tmp_icmp.icmptype = ICMPType.DestinationUnreachable
            tmp_icmp.icmpcode = 0
        # ICMP error case 2: TTL become zero
        elif error_case == 2:
            tmp_icmp.icmptype = ICMPType.TimeExceeded
            tmp_icmp.icmpcode = 0
        # ICMP error case 3: no ARP reply received
        elif error_case == 3:
            tmp_icmp.icmptype = ICMPType.DestinationUnreachable
            tmp_icmp.icmpcode = 1
        # ICMP error case 4: dst belong to the router itself while it's not an ICMP echo request
        elif error_case == 4:
            tmp_icmp.icmptype = ICMPType.DestinationUnreachable
            tmp_icmp.icmpcode = 3

        tmp_icmp.icmpdata.data = ipv4_pkt.to_bytes()[:28]
        new_pkt = Packet()
        new_pkt = Ethernet() + tmp_ip + tmp_icmp
        self.ipv4_handle(new_pkt, input_intf)

    def ipv4_handle(self, pkt, input_intf):
        '''
        Handle the IPv4 forwarding job of the router
        in order to simplify the code
        '''
        ipv4_pkt = pkt.get_header(IPv4)
        # TODO 解决和pkt有关的命名问题
        # drop the pkt if the dst belong to the router itself
        if ipv4_pkt.dst in self.ipaddrs:
            if ipv4_pkt.protocol == IPProtocol.ICMP and pkt.get_header(
                    ICMP).icmptype == ICMPType.EchoRequest:
                # TODO 正常发出echoreply，代码在下方已实现
                # TODO 这里应该可以递归调用吧？  另，如果找不到匹配项见问答截图
                ori_icmp = pkt.get_header(ICMP)
                tmp_icmp = ICMP()
                tmp_icmp.icmptype = ICMPType.EchoReply
                # tmp_icmp.icmpdata = ori_icmp.icmpdata
                tmp_icmp.icmpdata.sequence = ori_icmp.icmpdata.sequence
                tmp_icmp.icmpdata.identifier = ori_icmp.icmpdata.identifier
                tmp_icmp.icmpdata.data = ori_icmp.icmpdata.data
                tmp_ipv4 = IPv4()
                tmp_ipv4.src = input_intf.ipaddr
                tmp_ipv4.dst = ipv4_pkt.src
                tmp_ipv4.protocol = IPProtocol.ICMP
                tmp_ipv4.ttl = 64

                new_pkt = Packet()
                new_pkt = Ethernet() + tmp_ipv4 + tmp_icmp
                self.ipv4_handle(new_pkt, input_intf)
            else:
                # TODO  error case4
                self.send_icmp_error_pkt(4, pkt, input_intf)
                return

        else:
            # denote the longest prefix match so far
            longest = 0
            # denote the updated matched entry
            matched_entry = []
            for entry in self.fwd_tab:
                prefixnet = IPv4Network(entry[0] + '/' + entry[1],
                                        strict=False)
                if (ipv4_pkt.dst in prefixnet) and (longest <
                                                    prefixnet.prefixlen):
                    longest = prefixnet.prefixlen
                    matched_entry = entry
            if matched_entry == []:
                #TODO error case1
                self.send_icmp_error_pkt(1, pkt, input_intf)
                return
            # TODO 判断ttl的合法性 pkt要修改 case2
            # error case2
            if ipv4_pkt.ttl - 1 <= 0:
                self.send_icmp_error_pkt(2, pkt, input_intf)
                return
            ipv4_pkt.ttl -= 1
            intf = self.net.interface_by_name(matched_entry[3])
            # 1. the dst is within the subnet to which the intf belong,
            #    which means the next hop is the dst
            if matched_entry[2] == '0.0.0.0':
                next_hop_ip = ipv4_pkt.dst
            # 2. the next hop is an IP address on a router through which the destination is reachable
            else:
                next_hop_ip = IPv4Address(matched_entry[2])
            # if the IP-MAC pair is already recorded in the ARP cache table,
            # then no need for an ARP request
            if next_hop_ip in self.arp_tab:
                dst_macaddr = self.arp_tab[next_hop_ip]
                pkt.get_header(Ethernet).src = intf.ethaddr
                pkt.get_header(Ethernet).dst = dst_macaddr
                self.net.send_packet(matched_entry[3], pkt)
            # ARP request is necessary when none recorded
            else:
                # create a new ARP request using the handy API
                arp_req = create_ip_arp_request(intf.ethaddr, intf.ipaddr,
                                                next_hop_ip)
                self.net.send_packet(matched_entry[3], arp_req)
                # add this request into waiting queue
                new_entry = [
                    next_hop_ip,
                    time.time(), 1, matched_entry, pkt, arp_req, input_intf
                ]
                self.wait_q.append(new_entry)

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, 
        receiving packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                # create the current input interface obj for future convenient use
                intf_obj = self.net.interface_by_name(dev)
                pkt_type = pkt[Ethernet].ethertype

                # 1. handle ARP packets
                if (pkt_type == EtherType.ARP):
                    arp = pkt.get_header(Arp)
                    # code in Lab 3
                    if (arp.operation == ArpOperation.Request):
                        # add a new entry into the ARP cache table or just update a recorded one
                        self.arp_tab[arp.senderprotoaddr] = arp.senderhwaddr
                        log_info("Cached ARP table updated: {}".format(
                            str(self.arp_tab)))

                        # drop it if target ip does not exist here
                        if arp.targetprotoaddr in self.ipaddrs:
                            wanted_macaddr = self.net.interface_by_ipaddr(
                                arp.targetprotoaddr).ethaddr
                            arp_reply = create_ip_arp_reply(
                                wanted_macaddr, arp.senderhwaddr,
                                arp.targetprotoaddr, arp.senderprotoaddr)
                            self.net.send_packet(dev, arp_reply)
                    elif (arp.operation == ArpOperation.Reply):
                        # handle ARP replies to one of my requests stuck in the waiting queue
                        cur_mac = arp.senderhwaddr
                        cur_ip = arp.senderprotoaddr
                        # add the reply information to the ARP cache table
                        self.arp_tab[cur_ip] = cur_mac
                        # looking for the corresponding receiver to the ARP reply
                        for entry in self.wait_q[:]:
                            if cur_ip == entry[0]:
                                # change the Ethernet header of the packet(src and dst)
                                entry[4].get_header(
                                    Ethernet).src = self.net.interface_by_name(
                                        (entry[3])[3]).ethaddr
                                entry[4].get_header(Ethernet).dst = cur_mac
                                self.net.send_packet((entry[3])[3], entry[4])
                                # remove the entry from the waiting queue
                                self.wait_q.remove(entry)
                                break
                # 2. handle IPv4 packets
                elif (pkt_type == EtherType.IPv4):
                    self.ipv4_handle(pkt, intf_obj)

            # when no pkt is received, especially ARP reply
            else:
                # update every entry state in the waiting queue
                for entry in self.wait_q[:]:
                    # ARP reply is not received after 1s
                    if time.time() - entry[1] > 1:
                        # ARP request already sent exactly 5 times
                        if (entry[2] >= 5):
                            # TODO error case3 ARP failure
                            self.send_icmp_error_pkt(3, entry[4], entry[6])
                            self.wait_q.remove(entry)
                        # still be able to send ARP request
                        else:
                            entry[1] = time.time()
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
