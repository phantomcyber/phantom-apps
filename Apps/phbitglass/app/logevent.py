# File: app/logevent.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

"""
(C) Copyright Bitglass Inc. 2021. All Rights Reserved.
Author: eng@bitglass.com
"""

import sys
import logging
import logging.handlers
import json

from datetime import datetime

# Priority <xy> is already prepended by logging.handlers.emit()
SYSLOG_HEADER = '%s bitglass :%s'
# Feb 21 11:32:34
SYSLOG_HEADER_DATEFORMAT = '%b %d %H:%M:%S'

qradar_address = None
qradar_logger = None


def pushLog(d, address, logTime=datetime.utcnow()):
    """
    Push bg log event entry in json format to QRadar's syslog input
    """
    global qradar_address
    global qradar_logger
    if address != qradar_address:
        # NOTE Having 'QRadar' for the logger name below caused message payload leaks to log files through stdout
        # Also, make sure none of other handlers are called inadvertently
        qradar_logger = logging.getLogger('com.bitglass.lss')
        qradar_logger.propagate = 0

        qradar_logger.setLevel(logging.INFO)
        handler = logging.handlers.SysLogHandler(address=address)
        qradar_logger.addHandler(handler)
        qradar_address = address

    msg = json.dumps(d)
    syslogMsg = SYSLOG_HEADER % (datetime.strftime(logTime, SYSLOG_HEADER_DATEFORMAT), msg)
    qradar_logger.info(syslogMsg)

    return msg


def main():
    args = sys.argv[1:]
    host = 'localhost'
    if len(args):
        host = args[0].strip()
    if host == 'localhost':
        # from app.qpylib import qpylib
        # host = qpylib.get_console_address()
        pass

    testPayload =\
        '{"pagetitle": "", "emailsubject": "", "action": "", "emailbcc": "", "filename": "", "application":'
    '"Bitglass", "dlppattern": "", "location": "Atlanta||Georgia||GA||US", "email": "nspringer@acme-gadget.com",'
    '"details": "Logged out.", "emailcc": "", "time": "25 Feb 2020 13:44:50", "emailfrom": "", "user": "Nate Springer",'
    '"syslogheader": "<110>1 2020-02-25T13:44:50.038000Z api.bitglass.com NILVALUE NILVALUE access",'
    '"device": "Mac OS X 10.15.3", "transactionid": "b862f16858171579ea8e6001848ed1d527f0daca [25 Feb 2020 13:44:50]",'
    '"ipaddress": "v.x.y.z", "url": "/accounts/server_logout/", "request": "", "activity": "Logout", "emailsenttime": "",'
    '"useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",'
    '"emailto": ""}'
    print (testPayload)

    pushLog(testPayload, (host, 514))
    pushLog(testPayload, (host, 514))


if __name__ == '__main__':
    main()
