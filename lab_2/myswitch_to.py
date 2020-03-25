'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    # add an empty dict intended for host-(intf,last_time) pairs
    tab={}

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        # when new packet comes, record its information or update recorded information
        # since 'dictionary' is used and its keys(hosts' mac addresses) are all unique, the following line can do it all
        tab[packet[0].src] = {'intf': input_port, 'last': time.time()}
        # delete timeout entries in the forwarding table
        for host in list(tab):
            if time.time()-tab[host]['last'] > 10:
                del tab[host]

        # dst-port already recorded
        if packet[0].dst in tab:
            cur_intf = tab[packet[0].dst]['intf']
            log_debug ("Flooding packet {} to {}".format(packet, cur_intf))
            net.send_packet(cur_intf, packet)
        # dst-port not recorded yet
        # flood the packet out all ports except the one receiving it
        else:
            # if dst addr is the switch itself, do nothing!
            if packet[0].dst not in mymacs: 
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

    net.shutdown()
