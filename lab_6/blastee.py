#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time


class Blastee:
    def __init__(self):
        '''
        init some useful information
        '''
        input_file = open('blastee_params.txt', 'r')
        tmp = input_file.readline().split()
        self.blaster_IP = str(tmp[1])  # useless actually
        self.num = int(tmp[3])

        self.macs = {}
        self.macs['blaster'] = '10:00:00:00:00:01'
        self.macs['blastee'] = '20:00:00:00:00:01'
        self.macs['mb2blaster'] = '40:00:00:00:00:01'
        self.macs['mb2blastee'] = '40:00:00:00:00:02'

        self.ips = {}
        self.ips[blaster] = '192.168.100.1'
        self.ips[blastee] = '192.168.200.1'
        self.ips[mb2blaster] = '192.168.100.2'
        self.ips[mb2blastee] = '192.168.200.2'

    def mk_ack(self, pkt):
        '''
        create ACK for received pkts
        '''
        hdr = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        hdr[Ethernet].src = macs['blastee']
        hdr[Ethernet].dst = macs['mb2blastee']
        hdr[IPv4].src = ips['blastee']
        hdr[IPv4].dst = ips['blaster']

        seq_num = (pkt[RawPacketContents].to_bytes())[:4]

        len = int.from_bytes((pkt[RawPacketContents].to_bytes())[4:6], 'big')
        if len < 8:
            payload = (pkt[RawPacketContents].to_bytes())[6:] + bytes(8 - len)
        else:
            payload = (pkt[RawPacketContents].to_bytes())[6:14]

        return hdr + seq_num + payload


def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    blastee = Blastee()

    while True:
        gotpkt = True
        try:
            timestamp, dev, pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

            new_pkt = blastee.mk_ack(pkt)
            net.send_packet(dev, new_pkt)

    net.shutdown()
