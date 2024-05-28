
import subprocess



class FirewallHandler:
    def __init__(self, os_type, protocol = "", src_ipv6addr= "::", dest_ipv6addr="::"):
        self.os_type = os_type
        self.protocol = protocol
        self.src_ipv6addr= src_ipv6addr
        self.dest_ipv6addr= dest_ipv6addr



    def insert_firewall_rules(self):
            if self.os_type == "linux":
                self._insert_iptables_rules()
            else:
                print("For now only Linux")
                pass



    def delete_firewall_rules(self):
        if self.os_type == "linux":
            self._delete_iptables_rules()
        else:
            print("For now only Linux")
            pass



    def _insert_iptables_rules(self):

        print("inserting firewall rules...", self.protocol)
    
        if self.protocol == "":
            print("protocol not specified")
            args = ["ip6tables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(1)]

        elif self.protocol == "icmpv6":
            print("the protocol specified is icmpv6")
            args = ["ip6tables", "-I", "OUTPUT", "-p", self.protocol, "--icmpv6-type", "echo-request", "-j", "NFQUEUE", "--queue-num", str(1)]
    
        else:
            args = ["ip6tables", "-I", "OUTPUT", "-s", self.src_ipv6addr, "-d", self.dest_ipv6addr, "-p", self.protocol, "-j", "NFQUEUE", "--queue-num", str(1)]
        
        for arg in args:
            print(arg + ' ', end = '')
        
        print('')
            
        proc = subprocess.Popen(args)
            
        try:
            outs, errs = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

        print("firewall rules inserted")



    def _delete_iptables_rules(self):
    
        print("deleting firewall rules...")

        if self.protocol == "":
            args = ["ip6tables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(1)]

        elif self.protocol == 'icmpv6':
            args = ["sudo", "ip6tables", "-D", "OUTPUT", "-p", self.protocol, "--icmpv6-type", "echo-request", "-j", "NFQUEUE", "--queue-num", str(1)]
    
        else:
            args = ["ip6tables", "-D", "OUTPUT", "-s", self.src_ipv6addr, "-d", self.dest_ipv6addr, "-p", self.protocol, "-j", "NFQUEUE", "--queue-num", str(1)]

        for arg in args:
            print(arg + ' ', end = '')
        
        print('')
        
        proc = subprocess.Popen(args)
        
        try:
            outs, errs = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

        print("firewall rules deleted")









