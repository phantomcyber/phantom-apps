# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
# from resilient_consts import *
import requests
import json
from bs4 import BeautifulSoup
import co3
import time, calendar, dateutil.parser, datetime


# get string value: return "" if key not in dictionary, otherwise value
# deprecated use dict.get(key, "")
def getsv(dic, key):
    if key in dic:
        return dic[key]
    else:
        return ""


# add key as target_key to target dictionary if key exists in source dictionary
def addifkey(dic, key, tdic, tkey):
    if key in dic:
        tdic[tkey] = dic[key]


class ResilientConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ResilientConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None


    def get_json_parameter(self, dic, key, action_result):
        if key not in dic:
            return dict()

        value = dic[key]

        action_id = self.get_action_identifier()

        if not isinstance(value, basestring):
            errmsg = "{} failed. {} field is not a string (type={})".format(action_id, key, type(value))
            self.save_progress(errmsg)
            return action_result.set_status(phantom.APP_ERROR, errmsg)

        try:
            payload = json.loads(value)
            return payload
        except Exception as e:
            errmsg = "{} failed. {} field is not valid json, {}".format(action_id, key, repr(e))
            self.save_progress(errmsg)
            return action_result.set_status(phantom.APP_ERROR, errmsg)


    def __handle_exceptions(self, e, action_result):
        action_id = self.get_action_identifier()
        self.save_progress("{} failed: {}.".format(action_id, repr(e)))
        try:
            if e.response == None:
                return action_result.set_status(phantom.APP_ERROR, repr(e))
    
            if e.response.status_code == 400:
                self.save_progress("Bad request.")
                return action_result.set_status(phantom.APP_ERROR, "Bad request.")
    
            elif e.response.status_code == 401:
                self.save_progress("Unauthorized - most commonly, the provided session ID is invalid.")
                return action_result.set_status(phantom.APP_ERROR, "Unauthorized - most commonly, the provided session ID is invalid.")
    
            elif e.response.status_code == 403:
                self.save_progress("Forbidden - most commonly, user authentication failed.")
                return action_result.set_status(phantom.APP_ERROR, "Forbidden - most commonly, user authentication failed.")
    
            elif e.response.status_code == 404:
                self.save_progress("Object not found.")
                return action_result.set_status(phantom.APP_ERROR, "Object not found.")
    
            elif e.response.status_code == 409:
                self.save_progress("Conflicting PUT operation.")
                return action_result.set_status(phantom.APP_ERROR, "Conflicting PUT operation.")
    
            elif e.response.status_code == 500:
                self.save_progress("Internal error.")
                return action_result.set_status(phantom.APP_ERROR, "Internal error.")
    
            elif e.response.status_code == 503:
                self.save_progress("Service unavailable - usually related to LDAP not being accessible.")
                return action_result.set_status(phantom.APP_ERROR, "Service unavailable - usually related to LDAP not being accessible.")
    
            else:
                self.save_progress("Error: status code {}".format(e.response.status_code))
                return action_result.set_status(phantom.APP_ERROR, "Error: status code {}".format(e.response.status_code))

        except:
            pass

        self.save_progress("Error, Action Failed: {}", repr(e))
        return action_result.set_status(phantom.APP_ERROR, "Error, Action Failed: {}", repr(e))


    def _handle_test_connectivity(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_list_tickets(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents?want_closed={}".format(param['want_closed'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        itemtype = "incidents"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    # assumes connection already setup
    # return exception on error
    def _get_ticket(self, param):
        call = "/incidents/{}".format(param['incident_id'])
        self.save_progress("GET {}".format(call))
        retval = self._client.get(call)
        self.save_progress("{} successful.".format(action_id))
        return retval

    def _handle_get_ticket(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}".format(param['incident_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "incidents"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_create_ticket(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents?want_full_data={}&want_tasks={}".format(param['want_full_data'], param['want_tasks'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        fullincidentdatadto = getsv(param, 'fullincidentdatadto')
        if len(fullincidentdatadto) > 1:
            try:
                payload = json.loads(fullincidentdatadto)
            except Exception as e:
                self.save_progress("{} failed. fullincidentdatadto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. fullincidentdatadto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        if 'name' not in payload:
            addifkey(param, 'incident_name', payload, 'name')
        if 'description' not in payload:
            addifkey(param, 'incident_description', payload, 'description')
        if 'discovered_date' not in payload:
            payload['discovered_date'] = calendar.timegm(time.gmtime()) * 1000
        
        if 'name' not in payload:
            self.save_progress("json payload does not have required 'name' key")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'name' key")
        if 'description' not in payload:
            self.save_progress("json payload does not have required 'description' key")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'description' key")
        if 'discovered_date' not in payload:
            self.save_progress("json payload does not have required 'discovered_date' key")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'discovered_date' key")

        try:
            self.save_progress("POST {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.post(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "incidents"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_update_ticket(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        # validate incoming json
        fullincidentdatadto = param['fullincidentdatadto']
        if len(fullincidentdatadto) > 1:
            try:
                payload = json.loads(fullincidentdatadto)
            except Exception as e:
                self.save_progress("{} failed. fullincidentdatadto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. fullincidentdatadto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        config = self.get_config()

        # setup connection
        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}".format(param['incident_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        # remove parameter validation code. It just gets in the way
        #if 'name' not in payload:
        #    self.save_progress("json payload does not have 'name' key, payload should be result of get_ticket")
        #    return action_result.set_status(phantom.APP_ERROR, "json payload does not have 'name' key, payload should be result of get_ticket")
        #if 'description' not in payload:
        #    self.save_progress("json payload does not have 'description' key, payload should be result of get_ticket")
        #    return action_result.set_status(phantom.APP_ERROR, "json payload does not have 'description' key, payload should be result of get_ticket")
        #if 'discovered_date' not in payload:
        #    self.save_progress("json payload does not have 'discovered_date' key, payload should be result of get_ticket")
        #    return action_result.set_status(phantom.APP_ERROR, "json payload does not have 'discovered_date' key, payload should be result of get_ticket")

        # get ticket first
        #if param.get('get_ticket_and_copy_over', False):
        #    try:
        #        ticket = self._get_ticket(param)
        #    except Exception as e:
        #        return self.__handle_exceptions(e, action_result)
        #
        #    newpayload = payload.copy()
        #    newpayload.update(fullincidentdatadto)
        #    payload = newpayload
        
        try:
            def apply(arg):
                arg.update(payload)
                return arg

            self.save_progress("GET_PUT {}".format(call))
            self.save_progress("PAYLOAD {}".format(payload))
            retval = self._client.get_put(call, apply)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "incidents"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_search_tickets(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        payload = dict()
        conditions = list()
        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            call = "/incidents/query?return_level=full"
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        querydto = getsv(param, 'querydto')
        if len(querydto) > 1:
            try:
                payload = json.loads(querydto)
            except Exception as e:
                self.save_progress("{} failed. querydto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. querydto field is not valid json.".format(action_id))
        else:
            payload = dict()

        if 'filters' in payload:
            filters = payload['filters']
        else:
            filters = list()
            payload['filters'] = filters

        conditions = list()
        if param.get('add_condition_all_active_tickets') is True:
            conditions.append({"field_name": "plan_status", "method": "equals", "value": "A"})
        if param.get('add_condition_created_in_last_24_hours') is True:
            conditions.append({"field_name": "create_date", "method": "gte",
                "value": calendar.timegm((datetime.datetime.utcnow() - datetime.timedelta(days=1)).utctimetuple()) * 1000})
        if param.get('add_condition_closed_in_last_24_hours') is True:
            conditions.append({"field_name": "end_date", "method": "gte",
                "value": calendar.timegm((datetime.datetime.utcnow() - datetime.timedelta(days=1)).utctimetuple()) * 1000})
            
        for con in ['1st', '2nd', '3rd', '4th', '5th']:
            try:
                name = getsv(param, "{}_condition_field_name".format(con))
                value = getsv(param, "{}_condition_field_value".format(con))
                method = getsv(param, "{}_condition_comparison_method".format(con))
                isdate = param.get("{}_condition_value_is_datetime".format(con))

                ln = len(name) 
                lv = len(value)
                lm = len(method)

                # no condition, skip
                if (ln + lv + lm) == 0:
                    self.save_progress("{} condition is not complete".format(con))
                    continue

                if isdate:
                    try:
                        value = calendar.timegm(dateutil.parser.parse(value).utctimetuple()) * 1000
                    except Exception as e:
                        self.save_progress("Warning: {} condition value is not a datetime as expected: {}, skipping".format(con, e))
                        continue

                conditions.append({"field_name": name, "method": method, "value": value})
            except Exception as e:
                self.save_progress("Warning: {} condition not valid, skipping: {}.".format(con, e))

        if len('conditions') == 0:
            self.save_progress("json payload does not have 'conditions' key.")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have 'conditions' key")
    
        filters.append({ "conditions": conditions })

        try:
            self.save_progress("POST {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.post(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        itemtype = "incidents"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_list_artifacts(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/artifacts".format(param['incident_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        itemtype = "artifacts"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_get_artifact(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/artifacts/{}".format(param['incident_id'], param['artifact_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "artifacts"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_create_artifact(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/artifacts".format(param['incident_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        incidentartifactdto = getsv(param, 'incidentartifactdto')
        if len(incidentartifactdto) > 1:
            try:
                payload = json.loads(incidentartifactdto)
            except Exception as e:
                self.save_progress("{} failed. incidentartifactdto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. incidentartifactdto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        if 'description' not in payload:
            description = getsv(param, 'description')
            if len(description) > 0:
                payload['description'] = description
                #addifkey(param, 'incident_description', payload, 'description')
                #payload['description'] = dict()
                #payload['description']['format'] = "text"
                #payload['description']['content'] = getsv(param, 'description')
        if 'type' not in payload:
            type = getsv(param, 'type').lower()
            if type == "url":
                type = 3
            elif type == "domain":
                type = 2
            elif type == "file":
                type = 13
            else:
                try:
                    type = int(type)
                except:
                    self.save_progress("{} failed. Type is not recognized or not an integer".format(action_id))
                    return action_result.set_status(phantom.APP_ERROR, "{} failed. Type is not recognized or not an integer".format(action_id))
            if type > 0:
                payload['type'] = type
        if 'value' not in payload:
            addifkey(param, 'value', payload, 'value')

        if 'type' not in payload:
            self.save_progress("json payload does not have required 'type' key")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'name' key")
        if 'value' not in payload:
            self.save_progress("json payload does not have required 'value' key")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'value' key")
        if 'description' not in payload:
            self.save_progress("json payload does not have required 'description' key")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'description' key")

        try:
            self.save_progress("POST {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.post(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        itemtype = "artifacts"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_update_artifact(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/artifacts/{}".format(param['incident_id'], param['artifact_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        incidentartifactdto = getsv(param, 'incidentartifactdto')
        if len(incidentartifactdto) > 1:
            try:
                payload = json.loads(incidentartifactdto)
            except Exception as e:
                self.save_progress("{} failed. incidentartifactdto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. incidentartifactdto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        if 'type' not in payload:
            self.save_progress("json payload does not have 'type' key, payload should be result of get_artifact")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have 'name' key, payload should be result of get_artifact")
        if 'value' not in payload:
            self.save_progress("json payload does not have 'value' key, payload should be result of get_artifact")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have 'value' key, payload should be result of get_artifact")
        if 'description' not in payload:
            self.save_progress("json payload does not have 'description' key, payload should be result of get_artifact")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have 'description' key, payload should be result of get_artifact")
        
        try:
            self.save_progress("PUT {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.put(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "artifacts"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_list_comments(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.headers['text_content_output_format'] = "objects_no_convert"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/comments".format(param['incident_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        itemtype = "comments"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_get_comment(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/comments/{}".format(param['incident_id'], param['comment_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "comments"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_create_comment(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/comments".format(param['incident_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        incidentcommentdto = getsv(param, 'incidentcommentdto')
        if len(incidentcommentdto) > 1:
            try:
                payload = json.loads(incidentcommentdto)
            except Exception as e:
                self.save_progress("{} failed. incidentcommentdto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. incidentcommentdto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        if 'text' not in payload:
            addifkey(param, 'text', payload, 'text')
        if 'parent_id' not in payload:
            addifkey(param, 'parent_id', payload, 'parent_id')

        if 'text' not in payload:
            self.save_progress("json payload does not have required 'text' key")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'text' key")

        try:
            self.save_progress("POST {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.post(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "comments"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_update_comment(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            call = "/incidents/{}/comments/{}".format(param['incident_id'], param['comment_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        payload = self.get_json_parameter(param, 'incidentcommentdto', action_result)
        if payload == phantom.APP_ERROR:
            return payload

        #self.debug_print("{} json is {}".format(action_id, payload))

        if 'text' not in payload:
            self.save_progress("json payload does not have required 'text' key, payload should be result of get comment")
            return action_result.set_status(phantom.APP_ERROR, "json payload does not have required 'text' key, payload should be result of get comment")

        try:
            self.save_progress("PUT {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.put(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "comments"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_list_tables(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/table_data".format(param['incident_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        itemtype = "tables"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_get_table(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/table_data/{}".format(param['incident_id'], param['table_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "tables"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_add_table_row(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/table_data/{}/row_data".format(param['incident_id'], param['table_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        datatablerowdatadto = param.get('datatablerowdatadto', "")
        if len(datatablerowdatadto) > 1:
            try:
                payload = json.loads(datatablerowdatadto)
            except Exception as e:
                self.save_progress("{} failed. datatablerowdatadto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. datatablerowdatadto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        for col in ['1st', '2nd', '3rd', '4th', '5th']:
                key = param.get('{}_cell_property'.format(col), "")
                value = param.get('{}_cell_value'.format(col), "")
                if len(key) > 1 and len(value) > 1:
                    payload['cells'][key] = value
                elif len(key) > 1 or len(value) > 1:
                    self.save_progress("{} cell specification is not complete".format(con))
                    continue

        try:
            self.save_progress("POST {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.post(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "table row"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_update_table_row(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/table_data/{}/row_date/{}".format(param['incident_id'], param['table_id'], param['row_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        datatablerowdatadto = param.get('datatablerowdatadto', "")
        if len(datatablerowdatadto) > 1:
            try:
                payload = json.loads(datatablerowdatadto)
            except Exception as e:
                self.save_progress("{} failed. datatablerowdatadto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. datatablerowdatadto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        for col in ['1st', '2nd', '3rd', '4th', '5th']:
                key = param.get('{}_cell_property'.format(col), "")
                value = param.get('{}_cell_value'.format(col))
                if len(key) > 1 and len(value) > 1:
                    payload['cells'][key] = value
                elif len(key) > 1 or len(value) > 1:
                    self.save_progress("{} cell specification is not complete".format(con))
                    continue

        try:
            self.save_progress("PUT {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.put(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "table row"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_update_table_row_with_key(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()
        # all parameters are required so all parameters are len() > 0

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        datatablerowdatadto = param.get('datatablerowdatadto', "")
        if len(datatablerowdatadto) > 1:
            try:
                payload = json.loads(datatablerowdatadto)
            except Exception as e:
                self.save_progress("{} failed. datatablerowdatadto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. datatablerowdatadto field is not valid json.".format(action_id))
        else:
            self.save_progress("{} failed. datatablerowdatadto field is empty string.".format(action_id))
            return action_result.set_status(phantom.APP_ERROR, "{} failed. datatablerowdatadto field is empty string.".format(action_id))

        # get table first
        try:
            call = "/incidents/{}/table_data/{}".format(param['incident_id'], param['table_id'])
            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("GET successful")
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        def find_row(table, key, value):
            for row in table['rows']:
                if key in row['cells']:
                    if row['cells'][key] == value:
                        return row['id']
            return None

        key = param['key']
        value = param['value']
        rowid = find_row(retval, key, value)

        if rowid == None:
            self.save_progress("{} failed. Cannot match key/value.".format(action_id, key, value))
            return action_result.set_status(phantom.APP_ERROR, "{} failed. Cannot match key/value.".format(action_id, key, value))

        try:
            call = "/incidents/{}/table_data/{}/row_date/{}".format(param['incident_id'], param['table_id'], row_id)
            self.save_progress("PUT {}".format(call))
            self.save_progress("BODY {}".format(payload))
            retval = self._client.put(call, payload)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "table row"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_list_tasks(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/tasks"

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = retval
        itemtype = "tasks"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    # assumes connection already setup
    # return exception on error
    def _get_task(self, param):
        if param.get('handle_format', False) == True:
            self._client.headers['handle_format'] = "names"
        call = "/tasks/{}".format(param['task_id'])
        self.save_progress("GET {}".format(call))
        retval = self._client.get(call)
        self.save_progress("{} successful.".format(action_id))
        return retval

    def _handle_get_task(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/tasks/{}".format(param['task_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "tasks"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_update_task(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        taskdto = param.get('taskdto', "")
        if len(taskdto) > 1:
            try:
                payload = json.loads(taskdto)
            except Exception as e:
                self.save_progress("{} failed. taskdto field is not valid json.".format(action_id))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. taskdto field is not valid json.".format(action_id))
        else:
            payload = dict()
            
        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/tasks/{}".format(param['task_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        # get task first
        #if param.get('get_task_and_copy_over', False):
        #    try:
        #        ticket = self._get_task(param)
        #    except Exception as e:
        #        return self.__handle_exceptions(e, action_result)
        #
        #    newpayload = payload.copy()
        #    newpayload.update(taskdto)
        #    payload = newpayload

        try:
            def apply(arg):
                arg.update(payload)
                return arg

            self.save_progress("GET_PUT {}".format(call))
            self.save_progress("PAYLOAD {}".format(payload))
            retval = self._client.get_put(call, apply)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "tasks"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_close_task(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            self._client.connect(config['user'], config['password'])
            call = "/tasks/{}".format(param['task_id'])
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        try:
            #self.save_progress("GET {}".format(call))
            #retval = self._client.get(call)
            #payload = retval
            #payload['status'] = "C"
            #self.save_progress("PUT {}".format(call))
            #self.save_progress("BODY {}".format(payload))
            def apply(arg):
                arg['status'] = "C"
                return arg

            retval = self._client.get_put(call, apply)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "tasks"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_list_attachments(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/attachments".format(param['incident_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = retval
        itemtype = "attachments"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_get_attachment(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/attachments/{}".format(param['incident_id'], param['attachment_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "attachments"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_download_attachment(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/attachments/{}".format(param['incident_id'], param['attachment_id'])

            self.save_progress("GET {}".format(call))
            retval = self._client.get(call)
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "attachments"
        for r in retval:
            action_result.add_data("OK")
        summary = action_result.update_summary({})
        summary['Length of file'] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_add_attachment(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("In action handler for: {0}".format(action_id))
        action_result = self.add_action_result(ActionResult(dict(param)))
    
        config = self.get_config()

        try:
            self._client = co3.SimpleClient(org_name=config['org_id'], base_url=config['base_url'], verify=config['verify'])
            if param.get('handle_format', False) == True:
                self._client.headers['handle_format'] = "names"
            self._client.connect(config['user'], config['password'])
            call = "/incidents/{}/attachments".format(param['incident_id'])

            container_id = self.get_container_id()
            vault_info = Vault.get_file_info(vault_id=param['vault_id'], container_id=container_id)
            if len(vault_info) == 0:
                self.save_progress("{} failed. {}: vault_id not valid.".format(action_id, param['vault_id']))
                return action_result.set_status(phantom.APP_ERROR, "{} failed. {}: vault_id not valid.".format(action_id, param['vault_id']))
            path = vault_info[0]['path']
            name = filename=vault_info[0]['name']

            retval = self._client.post_attachment(call, path, filename=name)
            self.save_progress("POST_ATTACHMENT {} path={} name={}".format(call, path, name))
            self.save_progress("{} successful.".format(action_id))
        except Exception as e:
            return self.__handle_exceptions(e, action_result)

        retval = [ retval ]
        itemtype = "attachments"
        for r in retval:
            action_result.add_data(r)
        summary = action_result.update_summary({})
        summary['Number of {}'.format(itemtype)] = len(retval)
        return action_result.set_status(phantom.APP_SUCCESS)


    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", action_id)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_tickets':
            ret_val = self._handle_list_tickets(param)

        elif action_id == 'get_ticket':
            ret_val = self._handle_get_ticket(param)

        elif action_id == 'create_ticket':
            ret_val = self._handle_create_ticket(param)

        elif action_id == 'update_ticket':
            ret_val = self._handle_update_ticket(param)

        elif action_id == 'search_tickets':
            ret_val = self._handle_search_tickets(param)

        elif action_id == 'list_artifacts':
            ret_val = self._handle_list_artifacts(param)

        elif action_id == 'get_artifact':
            ret_val = self._handle_get_artifact(param)

        elif action_id == 'create_artifact':
            ret_val = self._handle_create_artifact(param)

        elif action_id == 'update_artifact':
            ret_val = self._handle_update_artifact(param)

        elif action_id == 'list_comments':
            ret_val = self._handle_list_comments(param)

        elif action_id == 'get_comment':
            ret_val = self._handle_get_comment(param)

        elif action_id == 'create_comment':
            ret_val = self._handle_create_comment(param)

        elif action_id == 'update_comment':
            ret_val = self._handle_update_comment(param)

        elif action_id == 'list_tables':
            ret_val = self._handle_list_tables(param)

        elif action_id == 'get_table':
            ret_val = self._handle_get_table(param)

        elif action_id == 'add_table_row':
            ret_val = self._handle_add_table_row(param)

        elif action_id == 'update_table_row':
            ret_val = self._handle_update_table_row(param)

        elif action_id == "update_table_row_with_key":
            ret_val = self._handle_update_table_row_with_key(param)

        elif action_id == 'list_tasks':
            ret_val = self._handle_list_tasks(param)

        elif action_id == 'get_task':
            ret_val = self._handle_get_task(param)

        elif action_id == 'update_task':
            ret_val = self._handle_update_task(param)

        elif action_id == 'close_task':
            ret_val = self._handle_close_task(param)

        elif action_id == 'list_attachments':
            ret_val = self._handle_list_attachments(param)

        elif action_id == 'get_attachment':
            ret_val = self._handle_get_attachment(param)

        elif action_id == 'add_attachment':
            ret_val = self._handle_add_attachment(param)

        return ret_val


    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        """
        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
#    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ResilientConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)

