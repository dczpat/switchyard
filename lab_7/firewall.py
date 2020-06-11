from switchyard.lib.userlib import *
import time
import random


class Bucket:
    '''
    designed for the token bucket algorithm
    '''
    def __init__(self, rl):
        # TODO
        self.tokens = 2 * rl
        self.rl = rl


class Rule:
    '''
    some data & funcs related to firewall rules
    '''
    def __init__(self, line):
        self.deny = (line[0] == 'deny')
        self.impair = (line[-1] == 'impair')
        if line[-2] == 'ratelimit':
            self.rl = int(line[-1])
        else:
            self.rl = -1

        if line[1] == 'ip':
            self.type = 'IPv4'
        elif line[1] == 'icmp':
            self.type = 'ICMP'
        elif line[1] == 'tcp':
            self.type = 'TCP'
        elif line[1] == 'udp':
            self.type = 'UDP'

        if line[1] == 'ip' or line[1] == 'icmp':
            self.src = line[3]
            self.dst = line[5]
        elif line[1] == 'tcp' or line[1] == 'udp':
            self.src = line[3]
            self.srcport = line[5]
            self.dst = line[7]
            self.dstport = line[9]


def gather_rules():
    '''
    gather rules from 'firewall_rules.txt'
    and create a list including them
    '''
    rules = []
    buckets = {}
    file = open('firewall_rules.txt', 'r')
    for line in file.readlines():
        line = line.split()
        if not len(line) or line[0][0] == '#':
            continue
        new_rule = Rule(line)
        rules.append(new_rule)
        if new_rule.rl != -1:
            bkt = Bucket(new_rule.rl)
            buckets[new_rule] = bkt
    return rules, buckets


def compare_ip(x, y):
    '''
    compare two IPv4 addrs and see if y belong to x
    '''
    if x == 'any':
        return True
    x1 = int(IPv4Network(x, strict=False).network_address)
    y1 = int(IPv4Network(y, strict=False).network_address)
    return x1 & y1 == x1


def compare_port(x, y):
    '''
    compare two port numbers and see if they match
    '''
    if x == 'any':
        return True
    return int(x) == y


def is_matchable(rule, pkt):
    '''
    see if this rule match the pkt
    '''
    ip_pkt = pkt[IPv4]
    if not (compare_ip(rule.src, ip_pkt.src)
            and compare_ip(rule.dst, ip_pkt.dst)):
        return False
    if rule.type == 'IPv4':
        return True
    if ip_pkt.protocol == IPProtocol.UDP:
        if not (compare_port(rule.srcport, pkt[UDP].src)
                and compare_port(rule.dstport, pkt[UDP].dst)):
            return False
    elif ip_pkt.protocol == IPProtocol.TCP:
        if not (compare_port(rule.srcport, pkt[TCP].src)
                and compare_port(rule.dstport, pkt[TCP].dst)):
            return False
    return True


def change_wndw(sz):
    '''
    randomly change the TCP advertised window size 
    '''
    return int(random.random() * sz)


def filter_pkt(rules, pkt, net, output_port, buckets):
    '''
    filter the pkt according to the rules
    '''
    if not pkt.has_header(IPv4):
        net.send_packet(output_port, pkt)
        return
    ip_pkt = pkt[IPv4]
    for rule in rules:
        if not (rule.type == 'IPv4' or rule.type in pkt.headers()):
            continue
        if not is_matchable(rule, pkt):
            continue
        break
    # no match found
    if not rule:
        net.send_packet(output_port, pkt)
        return
    # filter this pkt
    if rule.deny:
        return
    if rule.rl == -1 and (not rule.impair):
        net.send_packet(output_port, pkt)
        return
    if rule.impair:
        # handle impair
        if pkt.has_header(TCP):
            sz = pkt[TCP].window
            pkt[TCP].window = change_wndw(sz)
            print("The TCP advertised window size changed from {} to {}!!!\n".
                  format(sz, pkt[TCP].window))
        net.send_packet(output_port, pkt)
    else:
        # handle ratelimit
        bkt = buckets[rule]
        size = len(pkt) - len(pkt[Ethernet])
        if size <= bkt.tokens:
            bkt.tokens -= size
            net.send_packet(output_port, pkt)


def main(net):
    # assumes that there are exactly 2 ports
    portnames = [p.name for p in net.ports()]
    portpair = dict(zip(portnames, portnames[::-1]))
    rules, buckets = gather_rules()
    update_time = time.time()

    while True:
        pkt = None
        if time.time() - update_time >= 0.25:
            update_time = time.time()
            for bkt in buckets.values():
                bkt.tokens = min(bkt.rl / 4 + bkt.tokens, 2 * bkt.rl)
        try:
            timestamp, input_port, pkt = net.recv_packet(timeout=0.25)
        except NoPackets:
            pass
        except Shutdown:
            break

        if pkt is not None:
            # This is logically where you'd include some firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            filter_pkt(rules, pkt, net, portpair[input_port], buckets)

    net.shutdown()
