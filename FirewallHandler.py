
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

        #ip6tables -I OUTPUT -p esp --espspi 0:4294967295
        #ip6tables -I OUTPUT -m ah --ahspi 0:4294967295

        arg = ["ip6tables"]
        if self.table == "":
            arg = arg + ["-I", "OUTPUT"]
        else:
            arg = arg + ["-t", self.table, "-I", self.chain]
    
        if self.dest_ipv6addr != "":
            arg = arg + (["-d", self.dest_ipv6addr])
             
        for protocol in self.protocol:
            new_arg = arg.copy() 
            new_arg = new_arg + (["-p", protocol])
            if protocol == "icmpv6":
                new_arg1 = new_arg + (["--icmpv6-type", "echo-request"])
                new_arg2 = new_arg + (["--icmpv6-type", "echo-reply"])
                self.args.append(new_arg1)
                self.args.append(new_arg2)
            if protocol == "esp":
                new_arg = new_arg + (["--espspi", "0:4294967295"])
                self.args.append(new_arg)
            if protocol == "ah":
                i = new_arg.index("-p")
                new_arg[i] = "-m"
                new_arg = new_arg + (["--ahspi", "0:4294967295"])
                self.args.append(new_arg)
            if protocol == "tcp" or protocol == "udp":
                if self.dstPort > 0:
                    new_arg = new_arg + (["--dport", str(self.dstPort)])
                self.args.append(new_arg)
        
        k = 0
        while k < len(self.args):
            self.args[k] = self.args[k] + (["-j", "NFQUEUE", "--queue-num", str(1)])
            k += 1
            
        for arg in self.args:
            #print(arg)
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









