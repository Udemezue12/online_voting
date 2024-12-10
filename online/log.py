import logging

class Logs:
    def __init__(self):
        
        logging.basicConfig(
            filename='errors.log',
            level=logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def log_error(self, message):
        logging.error(message)


logger = Logs() 

