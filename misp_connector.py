# File: misp_connector.py
#
# Copyright (c) 2017-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import ipaddress
import json

import phantom.app as phantom
import phantom.rules as ph_rules
import phantom.utils as ph_utils
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
from pymisp import MISPEvent, PyMISP

# Imports local to this App
from misp_consts import *


# This patching is required because the PyMISP API sets the verify flag as a
#  member of the Session object (Session.verify)
# Whether its a bug or just because it's an older version, the requests module
#  on phantom doesn't do anything if that member is set, and will only ignore
#  server verification if its passed as part of the function
def patch_requests():
    __orig_session_get = requests.Session.get
    __orig_session_post = requests.Session.post

    def get(self, *args, **kwargs):
        if self.verify is not None:
            kwargs.pop('verify', None)
        else:
            self.verify = True
        return __orig_session_get(self, verify=self.verify, *args, **kwargs)

    def post(self, *args, **kwargs):
        if self.verify is not None:
            kwargs.pop('verify', None)
        else:
            self.verify = True
        return __orig_session_post(self, verify=self.verify, *args, **kwargs)

    requests.Session.get = get
    requests.Session.post = post


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class MispConnector(BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"
    ACTION_ID_CREATE_EVENT = "create_event"
    ACTION_ID_ADD_ATTRIBUTES = "add_attributes"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_GET_EVENT = "get_event"

    def __init__(self):

        # Call the BaseConnectors init first
        super(MispConnector, self).__init__()
        self._verify = None
        self._event = None

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, MISP_INVALID_INT_ERR.format(msg='', param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, MISP_INVALID_INT_ERR.format(msg='', param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, MISP_INVALID_INT_ERR.format(msg='non-negative', param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, MISP_INVALID_INT_ERR.format(msg='non-zero positive', param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_message = MISP_ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception:
            pass

        if not error_code:
            error_text = "Error Message: {}".format(error_message)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_message)

        return error_text

    def _validate_ip(self, input_data):
        ips = []
        if ';' in input_data:
            ips = list(filter(None, input_data.split(';')))

        else:
            ips = phantom.get_list_from_string(input_data)

        for ip in ips:
            try:
                ipaddress.ip_address(ip.strip())
            except Exception:
                return False

        return True

    def _validate_domain(self, input_data):
        domains = []
        if ';' in input_data:
            domains = list(filter(None, input_data.split(';')))
        else:
            domains = phantom.get_list_from_string(input_data)

        for domain in domains:
            if not ph_utils.is_domain(domain.strip()):
                return False
        return True

    def _validate_email(self, input_data):
        emails = []
        if ';' in input_data:
            emails = list(filter(None, input_data.split(';')))
        else:
            emails = phantom.get_list_from_string(input_data)

        for email in emails:
            if not ph_utils.is_email(email.strip()):
                return False
        return True

    def _validate_url(self, input_data):
        urls = []
        if ';' in input_data:
            urls = list(filter(None, input_data.split(';')))
        else:
            urls = phantom.get_list_from_string(input_data)

        for url in urls:
            if not ph_utils.is_url(url.strip()):
                return False
        return True

    def _validate_indicator(self, input_data, inc_type):

        incs = []
        if isinstance(input_data, list):
            incs = input_data
        elif ',' in input_data:
            incs = input_data.split(',')
        elif ';' in input_data:
            incs = input_data.split(';')

        incs = list(filter(None, incs))

        for inc in incs:
            if inc_type == "ip":
                if not self._validate_ip(inc.strip()):
                    return False
            elif inc_type == "email":
                if not ph_utils.is_email(inc.strip()):
                    return False
            elif inc_type == "domain":
                if not ph_utils.is_domain(inc.strip()):
                    return False
            elif inc_type == "url":
                if not ph_utils.is_url(inc.strip()):
                    return False
        return True

    def initialize(self):

        patch_requests()
        config = self.get_config()
        self._verify = config.get("verify_server_cert", False)
        self._misp_url = config.get("base_url").rstrip("/")
        api_key = config.get("api_key")

        self.save_progress("Creating MISP API session...")
        try:
            self._misp = PyMISP(self._misp_url, api_key, ssl=self._verify)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, "Failed to create API session:{0}".format(error_message))

        self.set_validator('ip', self._validate_ip)
        self.set_validator('domain', self._validate_domain)
        self.set_validator('email', self._validate_email)
        self.set_validator('url', self._validate_url)

        return phantom.APP_SUCCESS

    def _test_connectivity(self):
        action_result = self.add_action_result(ActionResult())
        self.save_progress("Checking connectivity to your MISP instance...")
        self.debug_print("Checking connectivity to your MISP instance...")
        config = self.get_config()
        auth = {"Authorization": config.get("api_key")}
        ret_val, resp_json = self._make_rest_call('/servers/getPyMISPVersion.json', action_result, headers=auth)
        if phantom.is_fail(ret_val):
            action_result.append_to_message('Test connectivity failed')
            return action_result.get_status()
        else:
            self.save_progress("Test Connectivity Passed")
            return action_result.set_status(phantom.APP_SUCCESS)

    def _create_event(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        distrib_map = {
            'your org only': 0,
            'this community only': 1,
            'connected communities': 2,
            'all communities': 3,
            '0': 0,
            '1': 1,
            '2': 2,
            '3': 3
        }
        tli_map = {
            'high': 1,
            'medium': 2,
            'low': 3,
            'undefined': 4,
            '1': 1,
            '2': 2,
            '3': 3,
            '4': 4
        }
        analysis_map = {
            'initial': 0,
            'ongoing': 1,
            'completed': 2,
            '0': 0,
            '1': 1,
            '2': 2
        }

        try:
            distribution = distrib_map[str(param['distribution']).lower()]
            threat_level_id = tli_map[str(param['threat_level_id']).lower()]
            analysis = analysis_map[str(param['analysis']).lower()]
        except KeyError as e:
            return action_result.set_status(phantom.APP_ERROR, "Invalid string in parameter: {}".format(str(e)))

        try:
            event = MISPEvent()
            event.distribution = distribution
            event.threat_level_id = threat_level_id
            event.analysis = analysis
            event.info = param["info"]

            self._event = self._misp.add_event(event, pythonify=True)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to create MISP event:{0}".format(error_message))

        try:
            action_result.add_data(json.loads(self._event.to_json()))
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to add data of MISP event:{0}".format(error_message))

        action_result.set_summary({"message": "Event created with id: {0}".format(self._event.id)})

        tags = param.get("tags", "")
        tag_list = [tag.strip() for tag in tags.split(",")] if tags else []
        if tag_list:
            try:
                for tag in tag_list:
                    self._misp.tag(self._event, tag)
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Failed to add tags to MISP event:{0}".format(error_message))

        addAttributes = param.get("add_attributes", True)
        if addAttributes:
            ret_val = self._perform_adds(param, action_result, add_data=True)

            error_message = action_result.get_message()

            if error_message is not None:
                summary = action_result.get_summary()
                summary["errors"] = error_message
                action_result.update_summary(summary)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                event_dict = json.loads(self._event.to_json())
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Failed to load data of MISP event:{0}".format(error_message))

            attributes = event_dict.get('Attribute', [])
            for attribute in attributes:
                action_result.add_data(attribute)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_indicator(self, indicator_list, action_result, indicator_type, to_ids):
        is_valid = True
        indic_type = indicator_type
        for indicator in indicator_list:
            if indicator_type == "source_ips":
                is_valid = self._validate_indicator(indicator_list, "ip")
                indicator_type = "ip-src"
            elif indicator_type == "dest_ips":
                is_valid = self._validate_indicator(indicator_list, "ip")
                indicator_type = "ip-dst"
            elif indicator_type == "domains":
                is_valid = self._validate_indicator(indicator_list, "domain")
                indicator_type = "domain"
            elif indicator_type == "source_emails":
                is_valid = self._validate_indicator(indicator_list, "email")
                indicator_type = "email-src"
            elif indicator_type == "dest_emails":
                is_valid = self._validate_indicator(indicator_list, "email")
                indicator_type = "email-dst"
            elif indicator_type == "urls":
                is_valid = self._validate_indicator(indicator_list, "url")
                indicator_type = "url"

            if not is_valid:
                return action_result.set_status(phantom.APP_ERROR, "'{}'".format(indic_type)), 1

            try:
                self._event.add_attribute(type=indicator_type, value=indicator, to_ids=to_ids)
            except Exception as e:
                self.debug_print("Failed to add attribute due to following error: {}".format(str(e)))
                return action_result.set_status(phantom.APP_ERROR, "'{}'".format(indicator_type)), 2

            try:
                self._event = self._misp.update_event(self._event, pythonify=True)
            except Exception as e:
                self.debug_print("Failed to update MISP event due to following error: {}".format(str(e)))
                return action_result.set_status(phantom.APP_ERROR, "Failed to update MISP event. Check logs for more details."), 3

        return phantom.APP_SUCCESS, 0

    def _perform_adds(self, param, action_result, add_data=False):

        errors = {}
        errors["invalid_key"] = list()
        errors["invalid_value"] = list()
        is_added = False
        is_empty = True

        default_indicator_list = [
            'source_ips', 'dest_ips',
            'domains', 'urls',
            'dest_emails', 'source_emails'
        ]

        for i in default_indicator_list:
            val = param.get(i)
            if val:
                is_empty = False
                indicator_list = phantom.get_list_from_string(val)

                ret_val, cust_error_code = self._add_indicator(indicator_list, action_result, i, param.get('to_ids', False))

                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                else:
                    is_added = True

        json_str = param.get('json')
        if json_str:
            try:
                d = json.loads(json_str)
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Invalid JSON parameter. {0}".format(error_message))
            if not isinstance(d, dict):
                return action_result.set_status(phantom.APP_ERROR, "Invalid JSON parameter")
            for k, v in d.items():
                is_empty = False
                if isinstance(v, list):
                    indicator_list = v
                else:
                    indicator_list = phantom.get_list_from_string(str(v))

                ret_val, cust_error_code = self._add_indicator(indicator_list, action_result, k, param.get('to_ids', False))

                if phantom.is_fail(ret_val):
                    status_message = action_result.get_message()
                    if cust_error_code == 1:
                        errors["invalid_value"].append(status_message)
                    elif cust_error_code == 2:
                        errors["invalid_key"].append(status_message)
                    else:
                        return action_result.get_status()
                else:
                    is_added = True

        error_message = None
        if errors["invalid_value"]:
            invalid_values = ', '.join(errors["invalid_value"])
            error_message = "{} key/keys has invalid value".format(invalid_values)
        if errors["invalid_key"]:
            invalid_keys = ', '.join(errors["invalid_key"])
            if error_message is not None:
                error_message = "{} and ".format(error_message)
            else:
                error_message = ''
            error_message = "{} {} is/are invalid attribute name/names".format(error_message, invalid_keys)

        if error_message is not None:
            error_message = "{} in 'json' action parameter".format(error_message)

        if self.get_action_identifier() == self.ACTION_ID_ADD_ATTRIBUTES:
            status = phantom.APP_SUCCESS
            # if not a single attribute is provided to update event
            if is_empty:
                status = phantom.APP_ERROR
                error_message = "Please provide at least one attribute"
            # if not a single attribute is attached then "update event" task is completely failed
            if not is_added:
                status = phantom.APP_ERROR
            return action_result.set_status(status, error_message)
        # Event is already created so it should be success regardless of the number of attributes attached
        else:
            return action_result.set_status(phantom.APP_SUCCESS, error_message)

    def _add_attributes(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._event is None:
            try:
                ret_val, event_id = self._validate_integer(action_result, param.get("event_id"), MISP_INVALID_EVENT_ID)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                self._event = self._misp.get_event(event=event_id, pythonify=True)
                if not hasattr(self._event, "id"):
                    if isinstance(self._event, dict):
                        raise Exception(self._event.get("errors", ""))
                    else:
                        raise Exception
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Failed to get event for adding attributes:{0}".format(error_message))

        ret_val = self._perform_adds(param, action_result, add_data=True)

        error_message = action_result.get_message()

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            event_dict = json.loads(self._event.to_json())
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to load data of MISP event:{0}".format(error_message))

        attributes = event_dict.get('Attribute', [])
        for attribute in attributes:
            action_result.add_data(attribute)

        tags = param.get("tags", "")
        replace_tags = param.get("replace_tags", False)
        tag_list = [tag.strip() for tag in tags.split(",")] if tags else []
        if tag_list:
            try:
                if replace_tags:
                    existing_tags = self._event.tags
                    for tag in existing_tags:
                        self._misp.untag(self._event, tag.name)

                for tag in tag_list:
                    self._misp.tag(self._event, tag)
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Failed to add tags to MISP event:{0}".format(error_message))

        if hasattr(self._event, "id"):
            summary = {}
            summary["message"] = "Attributes added to event: {0}".format(self._event.id)
            if error_message is not None:
                summary["errors"] = error_message
            action_result.set_summary(summary)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Failed to get event '{0}' for adding attributes".format(param["event_id"]))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _do_search(self, action_result, **kwargs):
        try:
            resp = self._misp.search(**kwargs)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), None)

        return RetVal(phantom.APP_SUCCESS, resp)

    def _run_query(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(param))
        query_dict = {}
        controller = param['controller']
        query_dict['controller'] = controller
        if 'event_id' in param:
            if ',' in param['event_id']:
                query_dict['eventid'] = list()
                for event_id in phantom.get_list_from_string(param['event_id']):
                    ret_val, event_id = self._validate_integer(action_result, event_id, MISP_INVALID_EVENT_ID)

                    if phantom.is_fail(ret_val):
                        return action_result.get_status()

                    query_dict['eventid'].append(event_id)
            else:
                ret_val, event_id = self._validate_integer(action_result, param['event_id'], MISP_INVALID_EVENT_ID)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                query_dict['eventid'] = event_id

        if 'tags' in param:
            query_dict['tags'] = list(filter(None, param['tags'].split(',')))

        if 'other' in param:
            try:
                other = json.loads(param['other'])
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON object{0}".format(error_message))

            if not isinstance(other, dict):
                return action_result.set_status(phantom.APP_ERROR, "Invalid JSON in 'other' action parameter")

            query_dict.update(other)

        max_results = param.get('max_results', 10)
        try:
            if not float(max_results).is_integer():
                return action_result.set_status(phantom.APP_ERROR, MISP_INVALID_INT_ERR.format(msg='', param=MISP_INVALID_MAX_RESULT))

            max_results = int(max_results)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, MISP_INVALID_INT_ERR.format(msg='', param=MISP_INVALID_MAX_RESULT))

        # pagination
        response_list = []
        page = 1
        records_remaining = max_results
        query_dict['limit'] = 1000
        if 0 < max_results < 1000:
            query_dict['limit'] = max_results
        while True:
            query_dict['page'] = page
            ret_val, response = self._do_search(action_result, **query_dict)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            page = page + 1
            if response and controller == 'attributes':
                response = response.get('Attribute')
            response_size = len(response)
            if response_size == 0:
                break
            # slice the response in case response size is larger than remaining records (for positive max_results)
            if max_results > 0 and records_remaining < response_size:
                response = response[:records_remaining]
            response_list.extend(response)

            # update the remaining records (for positive max_results)
            if max_results > 0:
                records_remaining = records_remaining - response_size
                if records_remaining <= 0:
                    break

        # slice the result in case of negative max_results value
        if max_results < 0:
            response_list = response_list[max_results:]

        if controller == 'attributes':
            action_result.add_data({"Attribute": response_list})
        else:
            action_result.add_data(response_list)
        self.debug_print("Successfully ran query")
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully ran query")

    def _download_malware_samples(self, action_result):
        try:
            """ Download malware samples for an event """
            objects = self._event.objects
            for obj in objects:
                for attrib in obj.Attribute:
                    if attrib.malware_binary:
                        if hasattr(Vault, 'get_vault_tmp_dir'):
                            file_path = "{}/{}".format(Vault.get_vault_tmp_dir(), attrib.malware_filename)
                            Vault.create_attachment(file_path, self.get_container_id(), file_name=attrib.malware_filename)
                        else:
                            file_path = '/vault/tmp/{}'.format(attrib.malware_filename)
                            with open(file_path, 'wb') as fp:
                                fp.write(attrib.malware_binary.read())
                                ph_rules.vault_add(container=self.get_container_id(), file_location=file_path, file_name=attrib.malware_filename)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to download malware samples: {0}".format(error_message))

        return phantom.APP_SUCCESS

    def _get_event(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, event_id = self._validate_integer(action_result, param.get("event_id"), MISP_INVALID_EVENT_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            self._event = self._misp.get_event(event=event_id, pythonify=True)

            if not hasattr(self._event, "id"):
                if isinstance(self._event, dict):
                    errors = self._event.get("errors", "")
                    if isinstance(errors, tuple) and errors[0] == 404:
                        return action_result.set_status(phantom.APP_SUCCESS, "Failed to get event for getting attachment:{0}".format(errors))
                    else:
                        Exception(errors)
                else:
                    raise Exception
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Failed to get event for getting attachment:{0}".format(error_message))

        query_dict = {}
        query_dict['eventid'] = event_id
        query_dict['controller'] = 'attributes'

        ret_val, attachments = self._do_search(action_result, **query_dict)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if param.get('download_samples'):
            # Don't forget about this
            ret_val = self._download_malware_samples(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        action_result.add_data(attachments)
        self.debug_print("Successfully retrieved attributes")
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved attributes")

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON {0}".format(error_message)), None

        if 200 <= r.status_code < 205:
            return phantom.APP_SUCCESS, resp_json

        action_result.add_data(resp_json)
        message = r.text.replace('{', '{{').replace('}', '}}')
        return action_result.set_status(phantom.APP_ERROR,
                                        "Error from server, Status Code: {0} data returned: {1}".format(
                                         r.status_code, message)), resp_json

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if r is not None:
                action_result.add_debug_data({'r_text': r.text})
                action_result.add_debug_data({'r_headers': r.headers})
                action_result.add_debug_data({'r_status_code': r.status_code})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})

        # There are just too many differences in the response to handle all of them in the same function
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successful empty response
        # if (200 <= r.status_code < 205) and (not r.text):
        #   return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _make_rest_call(self, endpoint, result, headers={}, params={}, json={}, method="get"):

        url = "{0}{1}".format(self._misp_url, endpoint)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            # Set the action_result status to error, the handler function will most probably return as is
            return result.set_status(phantom.APP_ERROR, "Unsupported method: {0}".format(method)), None
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            # Set the action_result status to error, the handler function will most probably return as is
            return result.set_status(phantom.APP_ERROR, "Handled exception: {0}".format(error_message)), None

        try:
            r = request_func(url, params=params, json=json, headers=headers, verify=self._verify)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return result.set_status(phantom.APP_ERROR, "REST API to server failed: {0}".format(error_message)), None

        return self._process_response(r, result)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == self.ACTION_ID_CREATE_EVENT:
            ret_val = self._create_event(param)
        elif action_id == self.ACTION_ID_ADD_ATTRIBUTES:
            ret_val = self._add_attributes(param)
        elif action_id == self.ACTION_ID_RUN_QUERY:
            ret_val = self._run_query(param)
        elif action_id == self.ACTION_ID_GET_EVENT:
            ret_val = self._get_event(param)
        elif action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import sys

    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = MispConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
