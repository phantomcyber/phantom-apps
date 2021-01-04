import logging
import os
import sys
from logging import handlers


class KennyLoggins:
    """ Base Class for Logging """
    __module__ = __name__

    def __init__(self, **kwargs):
        """Construct an instance of the Logging Object"""
        pass

    def get_logger(self, app_name=None, file_name='kenny_loggins', log_level=logging.INFO, version='unknown'):
        log_location = ('{}{}').format(os.path.sep, os.path.join('var', 'log', 'phantom', 'apps', app_name))
        _log = logging.getLogger(('{}/{}').format(app_name, file_name))
        _log.propogate = False
        _log.setLevel(log_level)
        formatter = logging.Formatter(
            ('%(asctime)s log_level=%(levelname)s pid=%(process)d tid=%(threadName)s              file="%(filename)s \
                " function="%(funcName)s" line_number="%(lineno)d" version="{}" %(message)s').format(version))
        try:
            try:
                if not os.path.isdir(log_location):
                    os.makedirs(log_location)
                output_file_name = os.path.join(log_location, ('{}.log').format(file_name))
                f_handle = handlers.RotatingFileHandler(output_file_name, maxBytes=25000000, backupCount=5)
                f_handle.setFormatter(formatter)
                if not len(_log.handlers):
                    _log.addHandler(f_handle)
            except Exception as e:
                handler = logging.StreamHandler(sys.stdout)
                handler.setLevel(log_level)
                handler.setFormatter(formatter)
                if not len(_log.handlers):
                    _log.addHandler(handler)
                _log.error(('Failed to create file-based logging. {}').format(e))

        finally:
            return _log
