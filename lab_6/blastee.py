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
        self.pkt_cnt = 0
        self.acked = []

        input_file = open('blastee_params.txt', 'r')
        params = input_file.readline().split()
        self.blaster_IP = str(params[1])  # useless actually
        self.num = int(params[3])

        self.macs = {}
        self.macs['blaster'] = '10:00:00:00:00:01'
        self.macs['blastee'] = '20:00:00:00:00:01'
        self.macs['mb2blaster'] = '40:00:00:00:00:01'
        self.macs['mb2blastee'] = '40:00:00:00:00:02'

        self.ips = {}
        self.ips['blaster'] = '192.168.100.1'
        self.ips['blastee'] = '192.168.200.1'
        self.ips['mb2blaster'] = '192.168.100.2'
        self.ips['mb2blastee'] = '192.168.200.2'

    def mk_ack(self, pkt):
        '''
        create ACK for received pkts
        '''
        hdr = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        hdr[Ethernet].src = self.macs['blastee']
        hdr[Ethernet].dst = self.macs['mb2blastee']
        hdr[IPv4].src = self.ips['blastee']
        hdr[IPv4].dst = self.ips['blaster']
        # extract 'seq_num' from the pkt
        seq_num_raw = (pkt[RawPacketContents].to_bytes())[:4]
        seq_num = int.from_bytes(seq_num_raw, 'big')
        # inorder to end blastee properly
        # only non-acked pkt should be recorded
        if seq_num not in self.acked:
            #print('new pkt!!!!', seq_num)
            self.acked.append(seq_num)
            self.pkt_cnt += 1
        # else:
        #     print('old pkt!!!!', seq_num)
        # extract 'length' from the pkt
        len = int.from_bytes((pkt[RawPacketContents].to_bytes())[4:6], 'big')
        if len < 8:
            # stuff the empty space
            payload = (pkt[RawPacketContents].to_bytes())[6:] + bytes(8 - len)
        else:
            payload = (pkt[RawPacketContents].to_bytes())[6:14]
        # add up the 3 parts above
        return hdr + seq_num_raw + payload

    def safe_exit(self):
        '''
        decide whether it's OK to end blastee
        '''
        if self.pkt_cnt < self.num:
            return False
        # no longer necessary since blaster won't send pkt with seq_num>num
        # for x in range(1, self.num):
        #     if x not in self.acked:
        #         return False
        return True


def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    blastee = Blastee()

    while True:
        gotpkt = True
        if blastee.safe_exit():
            break
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
            #print('new pkt!')
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

            new_pkt = blastee.mk_ack(pkt)
            net.send_packet(dev, new_pkt)

    net.shutdown()
