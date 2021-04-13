# File: app/env.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import os

# Use os.path.abspath() if ever wish running standalone on Windows
datapath = os.path.join(os.sep, 'store', '')

# For Splunk - read-only forward.json (just for the extra options) as the Save button saves to appsetup.conf
# Also, the local/ folder will be empty (the contents are moved over to default/ by the addon builder)
if 'SPLUNK_HOME' in os.environ:
    datapath = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', 'bitglass', 'default', '')

# Standalone Bitglass app
elif os.path.isdir(os.path.join(os.sep, 'opt', 'bitglass', 'store', '')):
    datapath = os.path.join(os.sep, 'opt', 'bitglass', 'store', '')

# Phantom logs to /var/log/phantom/spawn.log
# Can detect the version with 'cat /opt/phantom/etc/settings.json | grep phantom_version'


# The app calls this to override for the paths that include container uuids
def UpdateDataPath(newpath):
    global datapath
    res = (datapath != newpath)
    datapath = newpath
    return res


loggingpath = None


def UpdateLoggingPath(defaultlogfolder=None):
    global loggingpath
    if 'SPLUNK_HOME' in os.environ:
        loggingpath = os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk', 'bitglass.log')
    # Can't use PHANTOM_LOG_DIR (not defined), /opt/phantom/var/log/phantom/apps is missing on the OVA too
    # (the latter uses /opt/phantom...) and would have to create bitglass/ directory in either anyways..
    # TODO Should probably read 'appid' from bitglass.json
    elif os.path.isdir(os.path.join(os.sep, 'opt', 'phantom', 'local_data', 'app_states', '8119e222-818e-42f5-a210-1c7c9d337e81', '')):
        loggingpath = os.path.join(os.sep, 'opt', 'phantom', 'local_data', 'app_states', '8119e222-818e-42f5-a210-1c7c9d337e81', 'bitglass.log')
    # Deployed LSS instance
    elif os.path.isdir(os.path.join(os.sep, 'var', 'log', 'bitglass', '')):
        loggingpath = os.path.join(os.sep, 'var', 'log', 'bitglass', 'app.log')
    else:
        if defaultlogfolder:
            loggingpath = os.path.join(defaultlogfolder, 'log', 'app.log')
        else:
            loggingpath = os.path.join(datapath, 'app.log')


loggingpath = UpdateLoggingPath()
