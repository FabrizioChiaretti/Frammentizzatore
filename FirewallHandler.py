
import subprocess


class FirewallHandler:
    
    def __init__(self, os_type, logs_handler, protocol = "", dest_ipv6addr="", dstPort = ""):
        self.os_type = os_type
        self.logs_handler = logs_handler
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

        self.args = ["ip6tables", "-I", "OUTPUT"]
    
        if self.dest_ipv6addr != "":
            self.args = self.args + (["-d", self.dest_ipv6addr])
            
        if self.protocol != "": 
            self.args = self.args + (["-p", self.protocol])
            if self.protocol == "icmpv6":
                self.args = self.args + (["--icmpv6-type", "echo-request"])
        
        if self.dstPort >= 0: 
            self.args = self.args + (["--dport", str(self.dstPort)])
        
        self.args = self.args + (["-j", "NFQUEUE", "--queue-num", str(1)])
        
        rule = ""
        for arg in self.args:
            rule = rule + arg + " "
        self.logs_handler.logger.info(rule)
            
        proc = subprocess.Popen(self.args)
            
        try:
            outs, errs = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            
        return


    def _delete_iptables_rules(self):

        self.args[1] = "-D"

        rule = ""
        for arg in self.args:
            rule = rule + arg + " "
        self.logs_handler.logger.info(rule)
        
        proc = subprocess.Popen(self.args)
        
        try:
            outs, errs = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

        return









