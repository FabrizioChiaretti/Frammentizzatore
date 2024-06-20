

from netfilterqueue import NetfilterQueue
import platform
from FirewallHandler import FirewallHandler
from log import log
from input_handler import inputHandler
from frammentizzatore import frammentizzatore
from scapy.all import send


logs_handler = None
input_handler = None

def sendFragments(fragments):
    num_of_fragments = len(fragments)
    logs_handler.logger.info("Sending %d fragments", num_of_fragments)
    for frag in fragments:
        frag.show()
    send(fragments)
    logs_handler.logger.info("Fragments sent")

def traffic_handler(packet):
    
    logs_handler.logger.info("Traffic intercepted")
    framm = frammentizzatore(logs_handler)
    fragments = framm.fragment(packet, input_handler.fragmentSize)
    
    if fragments == None:
        packet.accept()
        return
    
    #packet.set_payload(bytes(fragments))
    #fragments.show()
    sendFragments(fragments)
    #p = defragment6(fragments)
    #packet.accept()
    packet.drop()
    return


def setFirewallRules(logs_handler, protocol = "", dest_ipv6addr="", dstPort = ""):
    
    os_type = platform.system().lower()

    logs_handler.logger.info("Inserting firewall rules...")
    firewall_handler = FirewallHandler(os_type, logs_handler, protocol, dest_ipv6addr, dstPort)
    firewall_handler.insert_firewall_rules()

    return firewall_handler


def main():

    global logs_handler
    logs_handler = log()

    input_file = open("input.json", "r")
    if input_file == None:
        logs_handler.logger.error("input.json not found")
        exit(1)

    global input_handler
    input_handler = inputHandler(input_file, logs_handler)
    
    res = input_handler.parse_input()
    if res == False:
        exit(1)
    
    firewall_handler = setFirewallRules(logs_handler, input_handler.protocol, input_handler.ipv6Dest, input_handler.dstPort)
    logs_handler.logger.info("Firewall rules set")

    nfqueue = NetfilterQueue()

    nfqueue.bind(1, traffic_handler)
    
    try:
         nfqueue.run()
    except KeyboardInterrupt:
        logs_handler.logger.info("Frammentizzatore Stopped")
    finally:
        logs_handler.logger.info("Deleting firewall rules")
        firewall_handler.delete_firewall_rules()
        logs_handler.logger.info("Firewall rules deleted")
        nfqueue.unbind()
    
    logs_handler.logger.info("Exiting...")



if __name__ == "__main__":
    main()

