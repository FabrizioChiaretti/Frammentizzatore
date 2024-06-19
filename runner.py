

from netfilterqueue import NetfilterQueue
import platform
from FirewallHandler import FirewallHandler
from log import log
from input_handler import inputHandler
from frammentizzatore import frammentizzatore
from scapy.all import send, defragment6, IPv6, raw


logs_handler = None


def sendFragments(fragments):
    send(fragments)

def traffic_handler(packet):
    
    logs_handler.logger.debug("Traffic intercepted")
    framm = frammentizzatore()
    fragments = framm.fragment(packet)
    #packet.set_payload(bytes(fragments))
    #packet.accept()
    #fragments.show()
    sendFragments(fragments)
    #p = defragment6(fragments)
    #packet.accept()
    packet.drop()
    
    return


def setFirewallRules(protocol = "icmpv6", dest_ipv6addr="", dstPort = ""):
    
    os_type = platform.system().lower()

    firewall_handler = FirewallHandler(os_type, protocol, dest_ipv6addr, dstPort)
    firewall_handler.insert_firewall_rules()

    return firewall_handler


def main():

    global logs_handler
    logs_handler = log()

    input_file = open("input.json", "r")
    if input_file == None:
        logs_handler.logger.error("input.json not found")
        exit(1)

    input_handler = inputHandler(input_file)
    
    res = input_handler.parse_input()
    if res == False:
        exit(1)
    
    firewall_handler = setFirewallRules()
    logs_handler.logger.info("Firewall rules set")

    nfqueue = NetfilterQueue()

    nfqueue.bind(1, traffic_handler)
    
    try:
         nfqueue.run()
    except KeyboardInterrupt:
        logs_handler.logger.info("Frammentizzatore Stopped")
    finally:
        firewall_handler.delete_firewall_rules()
        nfqueue.unbind()
    
    print("Exiting...")



if __name__ == "__main__":
    main()

