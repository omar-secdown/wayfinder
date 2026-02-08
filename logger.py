#!/usr/bin/env python3
"""
Wayfinder Logging Configuration
Provides a configured logger for all modules.
"""

import logging
import sys

# Create the wayfinder logger
logger = logging.getLogger('wayfinder')

# Prevent duplicate handlers if module is imported multiple times
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def set_verbose(verbose=True):
    """Enable DEBUG level logging when --verbose is used."""
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
