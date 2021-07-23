# -*- coding: utf-8 -*-

import logging

logger_levels = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
}


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    f = "%(message)s"

    FORMATS = {
        logging.DEBUG: grey + f + reset,
        logging.INFO: grey + f + reset,
        logging.WARNING: yellow + f + reset,
        logging.ERROR: red + f + reset,
        logging.CRITICAL: bold_red + f + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
