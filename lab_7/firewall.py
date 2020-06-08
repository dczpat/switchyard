from switchyard.lib.userlib import *
import time


class Rule:
    '''
    some data & funcs related to firewall rules
    '''
    def __init__(self, line):
        self.deny = (line[0] == 'deny')
        self.type = line[1]
        if line[1] == 'ip':
            self.type = EtherType.IPv4
        elif line[1] == 'icmp':
            self.type = IPProtocol.ICMP
        elif line[1] == 'tcp':
            self.type = IPProtocol.TCP
        elif line[1] == 'udp':
            self.type = IPProtocol.UDP
        if line[1] == 'ip' or line[1] == 'icmp':
            self.src = line[3]
            self.dst = line[5]
        elif line[1] == 'tcp' or line[1] == 'udp':
            self.src = line[3]
            self.srcport = line[5]
            self.dst = line[7]
            self.dstport = line[9]
        if not self.deny:
            self.impair = False
            if line[-2] == 'ratelimit':
                self.rl = line[-1]
            elif line[-1] == 'impair':
                self.impair = True


def gather_rules():
    '''
    gather rules from 'firewall_rules.txt'
    and create a list including them
    '''
    rules = []
    file = open('firewall_rules.txt', 'r')
    for line in file.readlines():
        line = line.split()
        if not len(line) or line[0][0] == '#':
            continue
        new_rule = Rule(line)
        rules.append(new_rule)
    return rules


def compare_ip(x, y):
    '''
    compare two IPv4 addrs and see if y belong to x
    '''
    if x == 'any':
        return False
    x1 = int(IPv4Network(x, strict=False).network_address)
    y1 = int(IPv4Network(y, strict=False).network_address)
    if x1 & y1 == x1:
        return True
    else:
        return False


def filter_pkt(rules, pkt):
    '''
    filter the pkt according to the rules
    '''
    if not pkt.has_header(IPv4):
        return
    ip = pkt[IPv4]
    for rule in rules:
        if rule.type not in pkt.headers():
            continue


def main(net):
    # assumes that there are exactly 2 ports
    portnames = [p.name for p in net.ports()]
    portpair = dict(zip(portnames, portnames[::-1]))
    rules = gather_rules()

    while True:
        pkt = None
        try:
            timestamp, input_port, pkt = net.recv_packet(timeout=0.5)
        except NoPackets:
            pass
        except Shutdown:
            break

        if pkt is not None:

            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            net.send_packet(portpair[input_port], pkt)

    net.shutdown()
