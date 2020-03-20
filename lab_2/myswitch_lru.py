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
    max_rules=int(input("Please enter the maximum number of rules permitted: "))
    # add an empty heapq to store  forwarding rules
    # each element of tab should be a tuple like: (last_time, host, intf)
    tab = []

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        
        if packet[0].src in [rule[1] for rule in tab]:
            # find the corresbonding iterator for the current host
            cur = iter(tab)
            for rule in tab:
                if rule[1] == packet[0].src:
                    #if input_port == rule[2]:
                    cur = rule
                    break
            # first delete, then add a new one    
            del cur
            #tab.insert((time.time(), packet[0].src, input_port))
            #heapq.heapify(tab)
        else:
            if tab.len() == max_rules:
            #    tab.insert((time.time(), packet[0].src, input_port))
            #else:
                heapq.heappop(tab)
        tab.insert((time.time(), packet[0].src, input_port))
        heapq.heapify(tab)

        if packet[0].dst in [rule[1] for rule in tab]:
            # find the corresbonding iterator for the current host
            cur = iter(tab)
            for rule in tab:
                if rule[1] == packet[0].src:
                    #if input_port == rule[2]:
                    cur = rule
                    break
            new_rule = [time.time(), cur[1], cur[2]]    
            del cur
            tab.insert(new_rule)
            heapq.heapify(tab)
        else:
            if packet[0].dst not in mymacs:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

    net.shutdown()
