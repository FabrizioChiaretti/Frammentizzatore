

from netfilterqueue import NetfilterQueue
import platform
from FirewallHandler import FirewallHandler


def frammentizzatore(packet):

    print("traffic intercepted")

    print("processing traffic...")
    packet1 = packet
    print(packet.header())
    packet1.accept()

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

    firewall_handler = setFirewallRules()

    nfqueue = NetfilterQueue()
    print("nfqueue created")

    nfqueue.bind(1, frammentizzatore)
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

