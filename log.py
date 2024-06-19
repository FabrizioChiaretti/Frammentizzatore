
import logging, sys

class log:
    
    def __init__(self):
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        
        