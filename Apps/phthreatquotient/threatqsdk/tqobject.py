###########################################################################################################
# File: tqobject.py
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
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
###########################################################################################################

# pragma pylint: disable=no-method-argument

from abc import ABCMeta, abstractmethod
import datetime
from .exceptions import ActionFailedError
import warnings


class ThreatQuotientObject(object):
    """ Abstract base class for all ThreatQuotient objects """
    __metaclass__ = ABCMeta

    def __init__(self, tq):
        self.tq = tq
        self.current_attributes = []

    @abstractmethod
    def _get_base_endpoint_name(self):
        """ Get the name of the endpoint """

    def _get_api_endpoint(self):
        base_endpoint = self.__class__._get_base_endpoint_name()
        return '/api/' + base_endpoint + '/' + str(self._id())

    @abstractmethod
    def _id(self):
        """ Get the ID of this object within its namespace """
        pass

    @abstractmethod
    def _set_id(self, value):
        """ Set the ID value """
        pass

    @abstractmethod
    def fill_from_api_response(self, api_response):
        """ Fill ourselves in based on an API response """
        pass

    @abstractmethod
    def _to_dict(self, **kwargs):
        """ Serialize this object to a representation suitable for
        upload to threatquotient
        """
        pass

    def add_comment(self, value):

        data = {'value': value}

        res = self.tq.post(
            self._get_api_endpoint() + "/comments?with=sources",
            data=data
        )

        if not res or 'data' not in res:
            raise ActionFailedError(res)

    def get_comments(self):
        p = {'with': 'sources'}
        res = self.tq.get(self._get_api_endpoint() + '/comments', params=p)
        comments = res.get('data', [])
        return comments

    def add_attribute(self, name, value, modify=False, sources=None, published_at=None):
        """
        Adds an attribute to an object
        """

        # Find attributes and remove if matches
        if modify:
            if not self.current_attributes:
                res = self.tq.get('{}/attributes'.format(self._get_api_endpoint()))
                self.current_attributes = res.get('data', [])

            for attr in self.current_attributes:
                if attr['name'] == name and attr['value'].lower() != value.lower():
                    attribute_id = attr['id']
                    self.tq.delete(
                        '{}/attributes/{}'.format(self._get_api_endpoint(), attribute_id))
                    # break

        data = {'name': name, 'value': value}
        if sources and isinstance(sources, str):
            data['sources'] = [{'name': sources}]
        elif sources and isinstance(sources, dict):
            data['sources'] = [sources]
        elif sources and isinstance(sources, list):
            data['sources'] = sources
        if published_at:
            data['published_at'] = published_at

        res = self.tq.post('{}/attributes'.format(self._get_api_endpoint()), data=data)

        # Add the newly added indicator to the cache
        if res.get('total', 0) > 0:
            self.current_attributes.append(res['data'][0])

    def get_attributes(self):
        """ Get attributes associated with this object

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the object has yet to be created
        """

        endpoint = self._get_api_endpoint() + '/attributes'
        results = self.tq.get(endpoint, withp='attribute')
        if 'data' not in results:
            return {}

        return results['data']
        # tr = {}
        # for attribute in results['data']:
        #    tr[attribute['attribute']['name']] = attribute['value']
        # return tr

    def _get_api_suffix(self, obj_type):
        return obj_type._get_base_endpoint_name()

    def relate_object(self, obj):
        """ Relate this object to another in the system

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                either object has not been created
        """
        suffix = self._get_api_suffix(obj.__class__)
        endpoint = self._get_api_endpoint() + '/' + suffix
        obj_id = obj._id()
        results = self.tq.post(endpoint, data={'id': obj_id})

        results = results.get('data')
        if not results or 'pivot' not in results[0]:
            raise ActionFailedError('Relate indicators')

    def get_related_objects(self, obj_type):
        """ Get the objects related to this one of type ``obj_type``

        Note: adversary to adversary relations currently return an empty
        list, until the API adds an endpoint for that

        :param obj_type: Object type to get. Should be a subclass of
            :py:class:`~threatqsdk.tqobject.ThreatQuotientObject`.

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the object has yet to be created

        :returns: A list of objects of type ``obj_type``
        """
        suffix = self._get_api_suffix(obj_type)
        if obj_type == self.__class__ and suffix == 'adversaries':
            return []
        endpoint = self._get_api_endpoint() + '/' + suffix
        results = self.tq.get(endpoint)
        if 'data' not in results:
            return []

        tr = []
        for obj in results['data']:
            inst = obj_type(self.tq)
            inst.fill_from_api_response(obj)
            tr.append(inst)
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
