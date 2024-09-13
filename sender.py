
from scapy.all import send, raw, IPv6ExtHdrFragment
from itertools import permutations
from time import sleep

class sender:
    
    
    def __init__(self, logs_handler):
        self.logs_handler = logs_handler
        
     
    def __check_overlapping(self, fragments): 
     
        i = 0
        tmp = fragments.copy()
        res = []
        while tmp:
            min_pos = 0
            min_offset = tmp[0][IPv6ExtHdrFragment].offset
            i = 0
            while i < len(tmp):
                cur_offset = tmp[i][IPv6ExtHdrFragment].offset
                if cur_offset < min_offset:
                    min_pos = i
                    min_offset = cur_offset
                i += 1
            
            res.append(tmp[min_pos].copy())
            #tmp[min_pos].show()
            del tmp[min_pos]
     
        current_offset = 0
        for frag in res:
            if IPv6ExtHdrFragment in frag:
                offset = frag[IPv6ExtHdrFragment].offset*8
                if offset < current_offset:
                    return True
                current_offset += len(raw(frag[IPv6ExtHdrFragment].payload))
                
        return False
        
        
    def sendFragments(self, fragments, singleTest):

        #fragments = [fragments[0]]
        if fragments != None:
            k = 0
            while k < len(fragments):
                i = 0
                while i < len(fragments[k]):
                    self.logs_handler.logger.info("\n########## FRAGMENT %d ##########", i+1)
                    fragments[k][i].show()
                    i+=1
                k += 1
                #sleep(10)
        
        if singleTest == 1:
            self.logs_handler.logger.info("Single test")
            for frag in fragments:
                send(frag)
        else:
            overlapping = self.__check_overlapping(fragments[0])
            if overlapping:
                self.logs_handler.logger.info("Fragments overlap")
                for frag in fragments:
                    p = list(permutations(frag))
                    for permutation in p:
                        permutation = list(permutation)
                        send(permutation)
                        '''for fr in permutation:
                            send(fr)
                            sleep(0.002)'''
            else:
                for frag in fragments:
                    send(frag)
        
        self.logs_handler.logger.info("Fragments sent")
        return
            
        
        
        