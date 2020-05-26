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
        # acked pkts' seq_num
        self.acked = []
        # the last timestamp when lhs is sent
        self.lhs_send_time = 0.0
        # the timestamp when first pkt is sent
        self.start = 0.0
        # the total cnt of pkts resent
        self.retrans = 0
        # the total cnt of timeouts
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
        self.ips['blaster'] = '192.168.100.1'
        self.ips['blastee'] = '192.168.200.1'
        self.ips['mb2blaster'] = '192.168.100.2'
        self.ips['mb2blastee'] = '192.168.200.2'

    def mk_pkt(self, seq_num):
        '''
        create ACK for received pkts
        '''
        hdr = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        hdr[Ethernet].src = self.macs['blaster']
        hdr[Ethernet].dst = self.macs['mb2blaster']
        hdr[IPv4].src = self.ips['blaster']
        hdr[IPv4].dst = self.ips['blastee']
        # transform data into rawbyte format
        seq_num = seq_num.to_bytes(4, 'big')
        length = self.len.to_bytes(2, 'big')
        payload = bytes(self.len)
        # add up the 3 parts above
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
            if not pkt.has_header(RawPacketContents):
                continue
            ack_seq = int.from_bytes((pkt[RawPacketContents].to_bytes())[:4],
                                     'big')
            #print("ack!!!!", ack_seq)
            # add new 'seq_num' to acked[]
            if ack_seq not in blaster.acked:
                blaster.acked.append(ack_seq)

            if ack_seq == blaster.lhs:
                '''
                1. change 'lhs' to the most right postion
                    where all pkts to the left have been acked
                2. decide whether to end blaster according to 'num'
                '''
                blaster.lhs += 1
                if blaster.lhs - 1 == blaster.num:
                    #print('end!!!!')
                    break
                while blaster.lhs in blaster.acked:
                    blaster.lhs += 1
                    if blaster.lhs - 1 == blaster.num:
                        #print('end!!!!')
                        break
        else:
            log_debug("Didn't receive anything")
            # send new pkt
            if blaster.rhs - blaster.lhs + 1 < blaster.sw:
                blaster.rhs += 1
                if blaster.rhs == 1:
                    blaster.lhs_send_time = time.time()
                    blaster.start = blaster.lhs_send_time
                if blaster.rhs <= blaster.num:
                    #print('send new pkt!!!!', blaster.rhs)
                    net.send_packet('blaster-eth0',
                                    blaster.mk_pkt(blaster.rhs))

            # check timeout for lhs
            if time.time() - blaster.lhs_send_time > blaster.to:
                # update key info
                blaster.to_times += 1
                #print('{} timeouts!!!!'.format(blaster.to_times))
                blaster.lhs_send_time = time.time()
                # all pkts within sender window and non-acked should be resent
                for x in range(blaster.lhs, min(blaster.rhs, blaster.num) + 1):
                    if x not in blaster.acked:
                        blaster.retrans += 1
                        #print('resend pkt!!!!', x)
                        net.send_packet('blaster-eth0', blaster.mk_pkt(x))

    span = time.time() - blaster.start
    log_info("Total TX time: {}s".format(span))
    log_info("Number of reTX: {}".format(blaster.retrans))
    log_info("Number of coarse TOs: {}".format(blaster.to_times))
    log_info("Throughput (Bps): {}".format(
        (blaster.rhs + blaster.retrans) * blaster.len / span))
    log_info("Goodput (Bps): {}".format(blaster.num * blaster.len / span))

    net.shutdown()