
import subprocess


class FirewallHandler:
    
    def __init__(self, os_type, logs_handler, table = "", chain = "", protocol = "", dest_ipv6addr="", dstPort = ""):
        self.os_type = os_type
        self.logs_handler = logs_handler
        self.table = table
        self.chain = chain
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

        arg = ["ip6tables"]
        if self.table == "":
            arg = arg + ["-I", "OUTPUT"]
        else:
            arg = arg + ["-t", self.table, "-I", self.chain]
            
        self.args = [arg]
    
        if self.dest_ipv6addr != "":
            self.args[0] = self.args[0] + (["-d", self.dest_ipv6addr])
            
        if self.protocol != "": 
            self.args[0] = self.args[0] + (["-p", self.protocol])
            if self.protocol == "icmpv6":
                new_arg1 = self.args[0].copy() + (["--icmpv6-type", "echo-request"])
                #new_arg2 = self.args[0].copy() + (["--icmpv6-type", "echo-reply"])
                self.args = []
                self.args.append(new_arg1)
                #self.args.append(new_arg2)
        
        if self.dstPort >= 0: 
            self.args[0] = self.args[0] + (["--dport", str(self.dstPort)])
        
        self.args[0] = self.args[0] + (["-j", "NFQUEUE", "--queue-num", str(1)])
        if len(self.args) == 2:
            self.args[1] = self.args[1] + (["-j", "NFQUEUE", "--queue-num", str(1)])
        
        for arg in self.args:
            rule = ""
            for s in arg:
                rule = rule + s + " "
            self.logs_handler.logger.info(rule)
        
        for arg in self.args:
            proc = subprocess.Popen(arg)
            try:
                outs, errs = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                
        return


    def _delete_iptables_rules(self):

        for arg in self.args:
            i = arg.index("-I")
            arg[i] = "-D"

        for arg in self.args:
            rule = ""
            for s in arg:
                rule = rule + s + " "
            self.logs_handler.logger.info(rule)
        
        for arg in self.args:
            proc = subprocess.Popen(arg)
            try:
                outs, errs = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()

        return









