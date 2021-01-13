# File: ds_model.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from abc import ABCMeta, abstractmethod


class DSModel(object, metaclass=ABCMeta):

    @staticmethod
    def cast(value, to_type):
        try:
            return to_type(value)
        except (ValueError, TypeError):
            return None

    @classmethod
    @abstractmethod
    def from_json(cls, json):
        """
        Create a DSModel object from json dictionary.
        """
