
from itertools import permutations
from netfilterqueue import NetfilterQueue
import platform
from FirewallHandler import FirewallHandler
from log import log
from input_handler import inputHandler
from frammentizzatore import frammentizzatore
from scapy.all import send, sr, sr1
from time import sleep

logs_handler = None
input_handler = None
frammentatore = None

def sendFragments(fragments):
    #fragments = [fragments[0]]
    if fragments != None:
        k = 0
        while k < len(fragments):
            i = 0
            while i < len(fragments[k]):
                #res[k][i] = IPv6(res[k][i])
                logs_handler.logger.info("\n########## FRAGMENT %d ##########", i+1)
                fragments[k][i].show()
                i+=1
            k += 1
    '''for frag in fragments:
        p = list(permutations(frag))
        for f in p:
            f = list(f)
            send(f)
    logs_handler.logger.info("Fragments sent")'''
    for frag in fragments:
        send(frag)
    logs_handler.logger.info("Fragments sent")
    '''send(fragments[0][0])
    sleep(5)
    send(fragments[0][1])'''

def traffic_handler(packet):
    
    logs_handler.logger.info("Traffic intercepted")
    fragments = frammentatore.fragmentation(packet)
    
    if fragments == None:
        logs_handler.logger.warning("Original packets released")
        packet.accept()
        return
    
    packet.drop()
    #packet.accept()
    sendFragments(fragments)
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

    try:
        input_file = open("input.json", "r")
    except OSError:
        logs_handler.logger.error("input.json not found")
        exit(1)

    global input_handler
    input_handler = inputHandler(input_file, logs_handler)
    
    res = input_handler.parse_input()
    if res == False:
        exit(1)
    
    global frammentatore
    frammentatore = frammentizzatore(logs_handler, input_handler)
    
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

