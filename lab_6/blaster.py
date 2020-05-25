#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time


class Blaster:
    def __init__(self):
        '''
        init some useful information
        '''
        self.lhs = 1
        self.rhs = 0
        self.acked = []
        self.lhs_send_time = 0.0
        self.start = 0.0
        self.retrans = 0
        self.to_times = 0

        input_file = open('blaster_params.txt', 'r')
        params = input_file.readline().split()
        self.blastee_IP = str(params[1])  # useless actually
        self.num = int(params[3])
        self.len = int(params[5])
        self.sw = int(params[7])
        self.to = float(params[9]) / 1000
        self.recv_to = float(params[11]) / 1000

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

    def mk_pkt(self, is_new, seq_num=rhs):
        '''
        create ACK for received pkts
        '''
        hdr = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        hdr[Ethernet].src = macs['blaster']
        hdr[Ethernet].dst = macs['mb2blaster']
        hdr[IPv4].src = ips['blaster']
        hdr[IPv4].dst = ips['blastee']

        if is_new:
            rhs += 1
            if rhs == 1:
                lhs_send_time = time.time()
                first_send_time = time.time()

        seq_num = seq_num.to_bytes(4, 'big')
        length = len.to_bytes(2, 'big')
        payload = bytes(len)

        return hdr + seq_num + length + payload


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    blaster = Blaster()

    while True:
        gotpkt = True
        try:
            # Timeout value will be parameterized!
            timestamp, dev, pkt = net.recv_packet(blaster.recv_to)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            ack_seq = int.from_bytes((pkt[RawPacketContents].to_bytes())[:4],
                                     'big')
            if ack_seq not in blaster.acked:
                blaster.acked.append(ack_seq)

            if ack_seq == blaster.lhs:
                blaster.lhs += 1
                if blaster.lhs == blaster.num:
                    break
                while blaster.lhs in blaster.acked:
                    blaster.lhs += 1
                    if blaster.lhs == blaster.num:
                        break
        else:
            log_debug("Didn't receive anything")
            # send new pkt
            if blaster.rhs - blaster.lhs + 1 < blaster.sw:
                blaster.rhs += 1
                net.send_packet('blaster-eth0', blaster.mk_pkt(True))

            # check timeout for lhs and resend
            if time.time() - blaster.lhs_send_time > blaster.to:
                blaster.to_times += 1
                blaster.lhs_send_time = time.time()
                for x in range(blaster.lhs, blaster.rhs):
                    if x not in blaster.acked:
                        blaster.retrans += 1
                        net.send_packet('blaster-eth0',
                                        blaster.mk_pkt(False, x))

    span = time.time() - blaster.start
    log_info("Total TX time: {}s".format(span))
    log_info("Number of reTX: {}".format(blaster.retrans))
    log_info("Number of coarse TOs: {}".format(blaster.to_times))
    log_info("Throughput (Bps): {}".format(
        (blaster.rhs + blaster.retrans) * blaster.len / span))
    log_info("Goodput (Bps): {}".format(blaster.num * blaster.len / span))

    net.shutdown()
