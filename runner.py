

from netfilterqueue import NetfilterQueue
import platform
from FirewallHandler import FirewallHandler
from frammentizzatore import frammentizzatore
from scapy.all import send, defragment6, IPv6, raw


def sendFragments(fragments):
    send(fragments)

def traffic_handler(packet):
    
    print("Traffic intercepted")
    print("Processing traffic...")
    framm = frammentizzatore()
    fragments = framm.fragment(packet)
    #packet.set_payload(bytes(fragments))
    #packet.accept()
    #fragments.show()
    sendFragments(fragments)
    #p = defragment6(fragments)
    #packet.accept()
    packet.drop()
    print("frammentizzatore ends")
    return


def setFirewallRules(protocol = "icmpv6", dest_ipv6addr="", dstPort = ""):
    
    os_type = platform.system().lower()

    firewall_handler = FirewallHandler(os_type, protocol, dest_ipv6addr, dstPort)
    firewall_handler.insert_firewall_rules()

    return firewall_handler



def main():

    firewall_handler = setFirewallRules()
    print("Firewall rules set")

    nfqueue = NetfilterQueue()
    print("Netfilter queue object created")

    nfqueue.bind(1, traffic_handler)
    print("Binding to queue executed")
    
    try:
         nfqueue.run()
    except KeyboardInterrupt:
        print("Stopped")
    finally:
        firewall_handler.delete_firewall_rules()
        nfqueue.unbind()
    
    print("Exiting...")



if __name__ == "__main__":
    main()

