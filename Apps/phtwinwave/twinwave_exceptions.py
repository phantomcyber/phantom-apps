# This file contains custom exception classes for fortisiem


# Exception raised when making HTTP REST connection to FortiSIEM
class TwinwaveConnectionException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


# Exception raised when an error occurs trying to map fields from FortiSIEM to Phantom
class TwinwaveFieldMappingException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
