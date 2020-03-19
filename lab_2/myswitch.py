'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    # add an empty dict intended for host-intf pairs
    tab={}

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        # step needed for every case below
        # 1.add the unrecorded pairs
        # 2.ensure the possible changes in the topology being detected
        tab[packet[0].src] = input_port

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        # dst-port already recorded
        elif packet[0].dst in tab:
            cur_intf = tab[packet[0].dst]
            log_debug ("Flooding packet {} to {}".format(packet, cur_intf))
            net.send_packet(cur_intf, packet)
        # dst-port not recorded yet
        # flood the packet out all ports except the one receiving it
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
