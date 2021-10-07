###########################################################################################################
# File: source.py
#
# ThreatQuotient Proprietary and Confidential
# Copyright (c)2021 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
###########################################################################################################

import datetime
import warnings


class Source(object):
    """ Create a source

    :param str name: Name of the source
    :param tlp: TLP level of the source, optional and defaults to None
    """
    def __init__(self, name, tlp=None, published_at=None):
        self.name = name
        self.tlp = tlp
        self.published_at = self.validate_date(published_at)

    def to_dict(self):
        """ Convert the dictionary representation expected by the API """
        tr = {
            'name': self.name,
        }
        if self.tlp is not None:
            tr['tlp'] = self.tlp
        if self.published_at is not None:
            tr['published_at'] = self.published_at
        return tr

    def validate_date(self, ds):
        """ Validate a date string is: %Y-%m-%d %H:%M:%S. Print warning if not in correct format.

        :param string ds: Date string

        :returns: string ds
        """
        error_message = ' is not in %Y-%m-%d %H:%M:%S format'
        if ds:
            try:
                datetime.datetime.strptime(ds, '%Y-%m-%d %H:%M:%S')
            except Exception:
                warnings.warn(ds + error_message)

        return ds


def make_source_list(sources):
    """ Convert an argument to an iterable of sources

    If the argument is None, we return None.
    If the argument is already a source, we wrap it up in something that can be
    iterated over and return it.
    If the argument is a string, we make a new source object which is wrapped
    and return that.
    Otherwise, we assume the caller knew what they were getting in to and return
    the source unmodified
    """
    if sources is None:
        return sources
    if isinstance(sources, str):
        sources = Source(sources)
    if isinstance(sources, Source):
        return (sources,)
    if isinstance(sources, list):
        new_sources = []
        for s in sources:
            if isinstance(s, Source):
                new_sources.append(s)
            else:
                new_sources.append(Source(s))
        return new_sources
    return sources
