###########################################################################################################
# File: exceptions.py
#
# ThreatQuotient Proprietary and Confidential
# Copyright (c) 2016-2021 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
###########################################################################################################

class AuthenticationError(Exception):
    """ Raised when the ThreatQ API doese not give us an access token

    Provides a ``res`` property with the raw response.
    """
    def __init__(self, res):
        self.res = res


class APIError(Exception):
    """ Raised when an API endpoint returns an error.

    Includes both the raw response and the errors property directly
    """
    def __init__(self, response, message=None):
        if message:
            super(APIError, self).__init__(message)
        else:
            super(APIError, self).__init__()
        self.response = response
        self.errors = response.json()['errors']


class NotCreatedError(Exception):
    """ Raised when attempting to perform an action on a ThreatQ object
    that would required the object to exist in ThreatQ, but it has not
    yet been created.

    Provides a ``object`` property which includes the object which was
    not created
    """
    def __init__(self, message=None, object=None):
        """Create a :py:class:: threatqsdk.exceptions.NotCreatedError

        :param str mesage: Message to display
        :param object: The object that was not created
        """
        if message:
            Exception.__init__(self, message)
        else:
            Exception.__init__(self)
        self.object = object


class UploadFailedError(Exception):
    """ Raised when uploading an object fails.

    Provides a ``response`` property with the raw response
    """
    def __init__(self, response):
        self.response = response


class ActionFailedError(Exception):
    """ Raised when performing an action on an object fails
    """
    def __init__(self, response):
        self.response = response
