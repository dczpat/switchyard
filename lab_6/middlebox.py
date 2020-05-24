#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
from random import randint
import time
from random import random


class MiddleBox:
    def __init__(self):
        '''
        init some useful information
        '''
        input_file = open('middlebox_params.txt', 'r')
        self.drop_rate = float(input_file.readline().split()[1])

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

    def drop_now(self):
        '''
        decide whether to drop the pkt
        '''
        if random() < drop_rate:
            return True
        else:
            return False


def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    mb = MiddleBox()

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
            log_debug("I got a packet {}".format(pkt))

            if dev == "middlebox-eth0":
                log_debug("Received from blaster")
                '''
                Received data packet
                Should I drop it?
                If not, modify headers & send to blastee
                '''
                if not mb.drop_now():
                    pkt[Ethernet].src = mb.macs['mb2blastee']
                    pkt[Ethernet].dst = mb.macs['blastee']
                    net.send_packet("middlebox-eth1", pkt)
            elif dev == "middlebox-eth1":
                log_debug("Received from blastee")
                '''
                Received ACK
                Modify headers & send to blaster. Not dropping ACK packets!
                '''
                pkt[Ethernet].src = mb.macs['mb2blaster']
                pkt[Ethernet].dst = mb.macs['blaster']
                net.send_packet("middlebox-eth0", pkt)
            else:
                log_debug("Oops :))")

    net.shutdown()
