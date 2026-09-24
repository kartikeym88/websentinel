import logging
import os
from datetime import datetime
from app.core.config import get_settings

def setup_logger(name: str) -> logging.Logger:
    settings = get_settings()
    
    # Ensure log directory exists
    if not os.path.exists(settings.log_dir):
        os.makedirs(settings.log_dir)
        
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # File handler
        log_file = os.path.join(settings.log_dir, f"scan_{datetime.now().strftime('%Y%m%d')}.log")
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        
        # Format
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        fh.setFormatter(formatter)
        
        logger.addHandler(ch)
        logger.addHandler(fh)
        
    return logger
