
import subprocess


class FirewallHandler:
    
    def __init__(self, os_type, protocol = "", dest_ipv6addr="", dstPort = ""):
        self.os_type = os_type
        self.protocol = protocol
        self.dest_ipv6addr = dest_ipv6addr
        self.dstPort = dstPort
        self.args = []


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

        print("Inserting firewall rules...", self.protocol)

        self.args = ["ip6tables", "-I", "OUTPUT"]
    
        if self.dest_ipv6addr != "":
            self.args = self.args + (["-d", self.dest_ipv6addr])
            
        if self.protocol != "": 
            self.args = self.args + (["-p", self.protocol])
            if self.protocol == "icmpv6":
                self.args = self.args + (["--icmpv6-type", "echo-request"])
        
        if self.dstPort != "" and (self.protocol == "tcp" or self.protocol == "udp"): 
            self.args = self.args + (["--dport", self.dstPort])
        
        self.args = self.args + (["-j", "NFQUEUE", "--queue-num", str(1)])
        
        for arg in self.args:
            print(arg + ' ', end = '')
        print('')
            
        proc = subprocess.Popen(self.args)
            
        try:
            outs, errs = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

        print("Firewall rules inserted")


    def _delete_iptables_rules(self):
    
        print("Deleting firewall rules...")

        self.args[1] = "-D"

        for arg in self.args:
            print(arg + ' ', end = '')
        print('')
        
        proc = subprocess.Popen(self.args)
        
        try:
            outs, errs = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

        print("Firewall rules deleted")









