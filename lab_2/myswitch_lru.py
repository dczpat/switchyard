'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
import heapq

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    max_rules = int(input("Please enter the maximum number of rules permitted: "))
    # add an empty heapq to store forwarding rules
    # each element of tab should be a tuple like: (last_time, host, intf)
    # when a heapq consists of tuples, it is organized based on the tuples' first elements
    tab = []

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        # src already recorded
        if packet[0].src in [rule[1] for rule in tab]:
            # find the corresbonding iterator for the current host
            cur = iter(tab)
            for rule in tab:
                if rule[1] == packet[0].src:
                    cur = rule
                    break
            # first delete, then add a new one   
            tab.remove(cur)
        # src not recorded yet
        else:
            # forwarding table is full
            if len(tab) == max_rules:
                heapq.heappop(tab)
        tab.append((time.time(), packet[0].src, input_port))
        heapq.heapify(tab)

        # dst already recorded
        if packet[0].dst in [rule[1] for rule in tab]:
            # find the corresbonding iterator for the current host
            cur = iter(tab)
            for rule in tab:
                if rule[1] == packet[0].dst:
                    cur = rule
                    break
            log_debug ("Flooding packet {} to {}".format(packet, cur[2]))
            net.send_packet(cur[2], packet)
            new_rule = (time.time(), cur[1], cur[2])
            tab.remove(cur)
            tab.append(new_rule)
            heapq.heapify(tab)
        # dst not recorded yet    
        else:
            # do nothing if dst is the switch itself
            if packet[0].dst not in mymacs:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

    net.shutdown()
