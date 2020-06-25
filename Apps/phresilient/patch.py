#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections

"""Methods and classes for manipulating patch-related elements for the Resilient REST API"""

class Change(object):
    """Represents a change in a Patch object."""
    def __init__(self, field_name, new_value, old_value):
        self.field_name = field_name
        self.new_value = new_value
        self.old_value = old_value

    def to_dict(self):
        """Creates a DTO/dict object from this change."""
        return dict(field = self.field_name,
                    new_value = dict(object = self.new_value),
                    old_value = dict(object = self.old_value))

class Patch(object):
    """Represents a patch to be applied to an object on the server."""
    def __init__(self, previous_object, version = None):
        """ previous_object: The last known state of the object being patched.  You can supply None here, but
                             if you do that then you'll need to provide old_value in your calls to add_value.
            version: The last known version of the object being patched.  If omitted then the 'vers' item in
                     the passed in previous_object will be used.  If one doesn't exist there then the version
                     won't be passed to the server."""
        self.previous_object = previous_object

        if version:
            self.version = version
        elif "vers" in previous_object:
            # if the object contains a "vers" field, then use it.
            self.version = previous_object["vers"]
        else:
            self.version = None

        # Keep the changes ordered.  Really this just simplifies testing a little bit with no perceivable
        # downside.
        self.changes = collections.OrderedDict()

    def _get_base_value(self, field_name):
        """
        Helper to get the value for a field from the previous_object (base object) passed into
        our constructor.
        """
        if not self.previous_object:
            raise ValueError("Constructor previous_object or method old_value argument is required")

        val = self.previous_object

        parts = field_name.split(".")

        for part in parts:
            if part not in val:
                val = None
                break

            val = val[part]

        if isinstance(val, dict):
            raise ValueError("Invalid field_name parameter")

        return val

    def add_value(self, field_name, new_value, **kwargs):
        """Adds a value to the patch.

           field_name: The name of the field.
           new_value: The value to add to the patch.
           old_value: The last known value of the field being patched.  If omitted then we'll pull the old
                      value from the previous_object that you passed into the constructor."""

        if "old_value" in kwargs:
            old_value = kwargs.get("old_value")
        else:
            old_value = self._get_base_value(field_name)

        self.changes[field_name] = Change(field_name, new_value, old_value)

    def exchange_conflicting_value(self, patch_status, field_name, new_value):
        """
        Call this method to update the patch object from within a conflict handler.
        :param patch_status: The PatchStatus object passed into your patch conflict callback.
        :param field_name: The name of the field whose value is to be exchanged.
        :param new_value: The new value to use in the patch (for the next patch operation).  Note that you may
        want to base your new_value on the result of patch_status.get_actual_current_value(field_name) since
        that will be what the other user changed the field to.  If you do not consider that previous value then
        you are effectively overwriting what they did.  Overwriting may be what you want depending on your application,
        but it likely that you want to somehow consider what the other user did.  If you just want to overwrite all
        changes note that you can use SimpleClient.patch(..., overwrite_conflict = True).
        """
        current_value = patch_status.get_actual_current_value(field_name)

        self.changes[field_name] = Change(field_name, new_value, current_value)

    def _get_change_with_field_named(self, field_name):
        """Helper to find an existing change in the list of changes."""
        if field_name in self.changes:
            return self.changes[field_name]

        return None

    def update_for_overwrite(self, patch_status):
        """Changes to patch to reflect the current values in patch_status_dict.  Use this method if you want to
        re-apply a patch operation that failed because of field conflicts...without concern with the previous
        values.
           patch_status_dict: The return from the patch operation.  It is assumed that this has a "field_failures"
                              property."""
        if not patch_status.has_field_failures():
            raise ValueError("Expected field_failures in patch status return")

        for field_name in patch_status.get_conflict_fields():
            change = self._get_change_with_field_named(field_name)

            if not change:
                raise ValueError("No change exists for field failure found in patch status")

            change.old_value = patch_status.get_actual_current_value(field_name)

    def get_old_values(self):
        """
        Gets all the 'old values' from the patch (for all fields).  The SimpleClient uses this to
        determine if anything has changed when calling the patch conflict callback.
        :return: A new list that contains all of the 'old values' in the patch.
        """
        return [change.old_value for field_name, change in self.changes.items()]

    def has_changes(self):
        """
        Determines if this patch has any changes.
        """
        return len(self.changes) > 0

    def get_old_value(self, field_name):
        """
        Gets the old value for the specified field in the patch.
        :param field_name: The field in question.
        """
        return self.changes[field_name].old_value

    def get_new_value(self, field_name):
        """
        Gets the new value for the specified field in the patch.
        :param field_name: The field in question.
        """
        return self.changes[field_name].new_value

    def delete_value(self, field_name):
        """
        Removes the change for the specified field.
        :param field_name: The field to remove.
        """
        if field_name in self.changes:
            del(self.changes[field_name])

    def to_dict(self):
        """Converts this patch object to a dict that can be posted to the server."""
        changes = []

        for field_name, change in self.changes.items():
            changes.append(change.to_dict())

        patch = dict(changes = changes)

        if self.version:
            patch["version"] = self.version

        return patch

class PatchStatus(object):
    """Represents the patch status returned by the patch endpoint."""
    def __init__(self, patch_status_dict):
        """Constructs a PatchStatus object

           patch_status_dict: The dictionary returned by the patch operation."""

        self.patch_status_dict = patch_status_dict

    def _get_patch_failure(self, field_name, should_raise):
        """Internal helper to find the FieldPatchFailureDTO for a given field.
           field_name: The name of the field to find.
           should_raise: Should a ValueError be raised if the field isn't found or should we just return None?"""
        for failure in self.patch_status_dict["field_failures"]:
            if failure["field"] == field_name:
                return failure

        if should_raise:
            raise ValueError("No conflict found for field {}".format(field_name))

        return None

    def is_success(self):
        """Was the patch operation successful?"""
        return self.patch_status_dict["success"]

    def has_field_failures(self):
        """Is there at least one field failure?"""
        return "field_failures" in self.patch_status_dict and len(self.patch_status_dict["field_failures"]) > 0

    def get_conflict_fields(self):
        """Get a list of the conflicting field names."""
        return [x["field"] for x in self.patch_status_dict["field_failures"]]

    def is_conflict_field(self, field_name):
        """Is the specified field_name amongst the conflicting fields?
           field_name: The field in question."""
        return self._get_patch_failure(field_name, should_raise=False) is not None

    def get_your_original_value(self, field_name):
        """Get the value that *you* specified in the original patch for the specified field.  Raises a ValueError
           if the field with the name field_name is not amongst the list of conflicting fields.

           field_name: The name of the field in question."""
        failure = self._get_patch_failure(field_name, should_raise=True)

        return failure["your_original_value"]

    def get_actual_current_value(self, field_name):
        """Get the current server value for the conflicting field.  Raises a ValueError
           if the field with the name field_name is not amongst the list of conflicting fields.

           field_name: The name of the field in question."""
        failure = self._get_patch_failure(field_name, should_raise=True)

        return failure["actual_current_value"]

    def get_message(self):
        """Gets the message associated with the patch status (or None if there wasn't one)."""
        if "message" in self.patch_status_dict:
            return self.patch_status_dict["message"]

        return None

    def to_dict(self):
        """
        Return the underlying dict representation of this PatchStatus object.
        """
        return self.patch_status_dict

