
from netfilterqueue import NetfilterQueue
import platform
from FirewallHandler import FirewallHandler
from argparse import ArgumentParser
from re import match
from log import log
from sender import sender
from input_handler import inputHandler
from frammentizzatore import frammentizzatore
from time import sleep

logs_handler = None
input_handler = None
frammentatore = None
sender_obj = None


def Arguments_parser():
    parser = ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-q", "--queue", required=True)
    return parser.parse_args()
    
    
def traffic_handler(packet):
    
    logs_handler.logger.info("Traffic intercepted")
    fragments = frammentatore.fragmentation(packet)
    
    if fragments == None:
        logs_handler.logger.warning("Original packets released")
        packet.accept()
        return
    
    packet.drop()
    sender_obj.sendFragments(fragments, input_handler.singleTest)

    #packet.accept()
    return


def setFirewallRules(logs_handler, queue_num, table = "", chain = "", protocol = "", dest_ipv6addr="", dstPort = ""):
    
    os_type = platform.system().lower()

    logs_handler.logger.info("Inserting firewall rules...")
    firewall_handler = FirewallHandler(os_type, logs_handler, queue_num, table, chain, protocol, dest_ipv6addr, dstPort)
    firewall_handler.insert_firewall_rules()

    return firewall_handler


def main():

    global logs_handler
    logs_handler = log("Frammentizzatore")

    args = Arguments_parser()
    input_file = args.input
    pattern = "input[0-9]*.json"
    m = match(pattern, input_file)
    if not m:
        logs_handler.logger.error("Invalid input file, expected input.json/input<number>.json")
        exit(1)

    queue_num = args.queue
    pattern = "[0-9]+$"
    m = match(pattern, queue_num)
    if not m:
        logs_handler.logger.error("Invalid queue number, expected an integer number")
        exit(1)

    queue_num = int(queue_num)
    
    try:
        file_desc = open(input_file, "r")
    except OSError:
        logs_handler.logger.error("%s not found", input_file)
        exit(1)

    global input_handler
    input_handler = inputHandler(file_desc, logs_handler)
    
    res = input_handler.parse_input()
    if res == False:
        exit(1)
    
    global frammentatore
    frammentatore = frammentizzatore(logs_handler, input_handler, max_fragment_lenght=input_handler.max_fragmentSize)
    
    global sender_obj
    sender_obj = sender(logs_handler)
    
    firewall_handler = setFirewallRules(logs_handler, queue_num, input_handler.table, input_handler.chain, input_handler.protocol, input_handler.ipv6Dest, input_handler.dstPort)
    logs_handler.logger.info("Firewall rules set")

    nfqueue = NetfilterQueue()
    
    try:
        nfqueue.bind(queue_num, traffic_handler)
    except:
        logs_handler.logger.error("queue number (%d) already chosen", queue_num)
        exit(1)
    
    try:
         nfqueue.run()
    except KeyboardInterrupt:
        logs_handler.logger.info("Stopped")
    finally:
        logs_handler.logger.info("Deleting firewall rules")
        firewall_handler.delete_firewall_rules()
        logs_handler.logger.info("Firewall rules deleted")
        nfqueue.unbind()
    
    logs_handler.logger.info("Exiting...")



if __name__ == "__main__":
    main()

