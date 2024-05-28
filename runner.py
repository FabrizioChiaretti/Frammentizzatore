

from netfilterqueue import NetfilterQueue
import platform
from FirewallHandler import FirewallHandler
from frammentizzatore import frammentizzatore
from scapy.all import send, defragment6, raw, IPv6, sr

def sendFragments(fragments):
    res = send(fragments)

def traffic_handler(packet):

    print("traffic intercepted")
    print("processing traffic...")
    framm = frammentizzatore()
    fragments = framm.fragment(packet, input_num_of_fragments=3)
    #print("my fragment")
    #for f in fragments:
        #f.show()
    sendFragments(fragments)
    #original_packet = defragment6(fragments)
    #print("input packet")
    #IPv6(packet.get_payload()).show()
    #packet.set_payload(bytes(fragments))
    packet.drop()
    print("frammentizzatore ends")
    return


def setFirewallRules(protocol = "", src_ipv6addr= "::", dest_ipv6addr="::"):
    
    os_type = platform.system().lower()
    print("os_type:", os_type)

    print("setting firewall rules...")
    firewall_handler = FirewallHandler(os_type, protocol, src_ipv6addr, dest_ipv6addr)
    firewall_handler.insert_firewall_rules()
    print("firewall rules set")

    return firewall_handler



def main():

    firewall_handler = setFirewallRules(protocol = "icmpv6")

    nfqueue = NetfilterQueue()
    print("nfqueue created")

    nfqueue.bind(1, traffic_handler)
    print("bind to queue 1 executed")

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("stop frammentizzatore")
    finally:
        firewall_handler.delete_firewall_rules()
        nfqueue.unbind()
    
    print("exiting...")



if __name__ == "__main__":
    main()

